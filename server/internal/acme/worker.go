package acme

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/cache"
)

const (
	defaultScanInterval = 10 * time.Minute
	schedulerLockKey    = "jiuzhang:acme:scheduler_lock"
	schedulerLockTTL    = 8 * time.Minute
	staleOrderMaxAge    = 15 * time.Minute
	staleChallengeAge   = 15 * time.Minute
)

// Worker 负责周期巡检自动 SSL 站点（首次自动申请、到期自动续约、域名增补同步）、
// 同步证书有效期状态（RefreshStatus）以及响应用户开启自动 SSL 或变更域名时的即时唤醒。
type Worker struct {
	svc      *Service
	repo     Repository
	apps     AppRepo
	certs    CertRepo
	cache    *cache.Client
	solver   *HTTP01Solver
	interval time.Duration
	notifyCh chan uuid.UUID
}

// NewWorker 创建自动 SSL 后台调度工人。
func NewWorker(svc *Service, repo Repository, apps AppRepo, certs CertRepo, c *cache.Client, solver *HTTP01Solver, interval time.Duration) *Worker {
	if interval <= 0 {
		interval = defaultScanInterval
	}
	return &Worker{
		svc:      svc,
		repo:     repo,
		apps:     apps,
		certs:    certs,
		cache:    c,
		solver:   solver,
		interval: interval,
		notifyCh: make(chan uuid.UUID, 64),
	}
}

// NotifyApp 非阻塞唤醒后台工人立即检查指定站点的自动 SSL 状态。
func (w *Worker) NotifyApp(appID uuid.UUID) {
	if w == nil || appID == uuid.Nil {
		return
	}
	select {
	case w.notifyCh <- appID:
	default:
		slog.Warn("acme worker notify channel full, will catch up on next periodic scan", "app_id", appID)
	}
}

// Run 启动周期巡检与事件驱动监听，直到 ctx 取消。
func (w *Worker) Run(ctx context.Context) {
	// 启动时收口上次进程异常退出可能残留的进行中订单
	if n, err := w.repo.MarkStaleOrdersFailed(ctx, staleOrderMaxAge); err != nil {
		slog.Warn("acme mark stale orders failed on startup", "error", err)
	} else if n > 0 {
		slog.Info("acme marked stale orders failed on startup", "count", n)
	}

	// 启动后延迟 15 秒执行首轮状态刷新与巡检，避开容器冷启动高峰
	initialTimer := time.NewTimer(15 * time.Second)
	defer initialTimer.Stop()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-initialTimer.C:
			w.RunOnce(ctx)
		case <-ticker.C:
			w.RunOnce(ctx)
		case appID := <-w.notifyCh:
			if _, err := w.svc.EvaluateAndProcessApp(ctx, appID, false); err != nil {
				slog.Warn("acme immediate app evaluation failed", "app_id", appID, "error", err)
			}
		}
	}
}

// RunOnce 执行单轮证书状态刷新、临时文件清扫与全部自动 SSL 候选站点巡检。
func (w *Worker) RunOnce(ctx context.Context) {
	// 1. 定期刷新证书状态（VALID / EXPIRING / EXPIRED；REPLACED/INVALID 保持不动）
	if w.certs != nil {
		if _, err := w.certs.RefreshStatus(ctx); err != nil {
			slog.Warn("refresh certificate statuses failed", "error", err)
		}
	}
	// 2. 清理陈旧本地挑战文件与超时卡住的订单
	if w.solver != nil {
		w.solver.CleanStaleFiles(staleChallengeAge)
	}
	if _, err := w.repo.MarkStaleOrdersFailed(ctx, staleOrderMaxAge); err != nil {
		slog.Warn("acme mark stale orders failed", "error", err)
	}

	// 3. 全局调度锁（多 API 实例部署下保证每轮仅单实例执行巡检）
	release, ok := w.acquireSchedulerLock(ctx)
	if !ok {
		return
	}
	defer release()

	cfg, err := w.repo.GetConfig(ctx)
	if err != nil {
		slog.Warn("acme worker load config failed", "error", err)
		return
	}
	if !cfg.Enabled {
		return
	}

	candidates, err := w.apps.ListAutoSSLCandidates(ctx)
	if err != nil {
		slog.Warn("acme worker list auto-ssl candidates failed", "error", err)
		return
	}
	for _, app := range candidates {
		if ctx.Err() != nil {
			return
		}
		triggered, err := w.svc.EvaluateAndProcessApp(ctx, app.ID, true)
		if err != nil {
			slog.Warn("acme worker app renewal/issuance failed", "app", app.Code, "error", err)
		} else if triggered {
			slog.Info("acme worker app certificate processed", "app", app.Code)
		}
	}
}

func (w *Worker) acquireSchedulerLock(ctx context.Context) (func(), bool) {
	if w.cache == nil || w.cache.Redis() == nil {
		return func() {}, true
	}
	token := uuid.NewString()
	ok, err := w.cache.Redis().SetNX(ctx, schedulerLockKey, token, schedulerLockTTL).Result()
	if err != nil {
		slog.Warn("acme scheduler lock failed", "error", err)
		return func() {}, false
	}
	if !ok {
		return func() {}, false
	}
	return func() {
		relCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = w.cache.Redis().Eval(relCtx, releaseLockLua, []string{schedulerLockKey}, token).Result()
	}, true
}
