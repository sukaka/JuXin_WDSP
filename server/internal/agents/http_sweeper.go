// http_sweeper.go Agent HTTP 事件保留清理（Phase 3，契约 §6 / 设计 §68.9）：
// 每日删除 created_at 早于 7 天的 agent_http_events 记录——硬上限防无限增长。
// 结构对齐 apinodes.Sweeper：SweepOnce 可独立单测 + ticker Run 周期驱动。
package agents

import (
	"context"
	"log/slog"
	"time"
)

const (
	// HTTPEventRetention HTTP 事件保留窗口（契约 §6/设计 §68.9：created_at 早于 7 天
	// 即删——数据为可重建的旁路观测副本，保留窗口仅为排障与资产联动回溯服务，
	// 硬上限防表无限增长；(agent_id, ts DESC) 索引查询窗口不受清理影响语义）。
	HTTPEventRetention = 7 * 24 * time.Hour
	// CaptureOverrideRetention 定向采集规则过期后保留窗口（Phase 4 契约 §2.3：
	// 过期规则服务端无需主动删除，expires_at 早于 30 天后由本 sweeper 同周期顺带清理）。
	CaptureOverrideRetention = 30 * 24 * time.Hour
	// DefaultHTTPEventSweepInterval 默认清理周期（每日一轮——契约 §6）。
	DefaultHTTPEventSweepInterval = 24 * time.Hour
)

// HTTPEventCleaner 过期 HTTP 事件 + 过期定向采集规则删除入口（*Store 实现；接口隔离便于单测 fake）。
type HTTPEventCleaner interface {
	DeleteExpiredHTTPEvents(ctx context.Context, before time.Time) (int64, error)
	// DeleteExpiredCaptureOverrides 删除 expires_at 早于 before 的定向采集规则（Phase 4 契约 §2.3）。
	DeleteExpiredCaptureOverrides(ctx context.Context, before time.Time) (int64, error)
}

// HTTPEventSweeper HTTP 事件保留清理器。
type HTTPEventSweeper struct {
	store    HTTPEventCleaner
	now      func() time.Time
	interval time.Duration // 0 时取 DefaultHTTPEventSweepInterval
}

// NewHTTPEventSweeper 创建清理器。
func NewHTTPEventSweeper(store HTTPEventCleaner) *HTTPEventSweeper {
	return &HTTPEventSweeper{store: store, now: func() time.Time { return time.Now().UTC() }}
}

// SetClock 注入时钟（测试使用）。
func (s *HTTPEventSweeper) SetClock(now func() time.Time) *HTTPEventSweeper { s.now = now; return s }

// SetInterval 设置清理周期（应用装配时使用；非正数取默认每日）。
func (s *HTTPEventSweeper) SetInterval(d time.Duration) *HTTPEventSweeper { s.interval = d; return s }

// SweepOnce 执行一轮清理（可由调度与测试直接调用）：删除 created_at 早于
// now-HTTPEventRetention 的 HTTP 事件，并顺带删除 expires_at 早于
// now-CaptureOverrideRetention 的定向采集规则（Phase 4 契约 §2.3 同周期顺带）；
// 返回两类删除行数合计；失败如实返回错误（不静默吞错）。
func (s *HTTPEventSweeper) SweepOnce(ctx context.Context) (int64, error) {
	n, err := s.store.DeleteExpiredHTTPEvents(ctx, s.now().Add(-HTTPEventRetention))
	if err != nil {
		return 0, err
	}
	m, err := s.store.DeleteExpiredCaptureOverrides(ctx, s.now().Add(-CaptureOverrideRetention))
	if err != nil {
		return n, err
	}
	return n + m, nil
}

// Run 周期驱动：启动即清一轮（进程长期运行每日一轮；频繁重启部署下避免长期不触发），
// 之后按 interval tick；单轮失败仅 Warn（下一轮自然重试），ctx 取消即退出。
func (s *HTTPEventSweeper) Run(ctx context.Context) {
	interval := s.interval
	if interval <= 0 {
		interval = DefaultHTTPEventSweepInterval
	}
	s.sweepLogged(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweepLogged(ctx)
		}
	}
}

func (s *HTTPEventSweeper) sweepLogged(ctx context.Context) {
	n, err := s.SweepOnce(ctx)
	if err != nil {
		slog.Warn("agent http events retention sweep failed", "error", err)
		return
	}
	if n > 0 {
		slog.Info("agent http events retention sweep done", "deleted", n)
	}
}
