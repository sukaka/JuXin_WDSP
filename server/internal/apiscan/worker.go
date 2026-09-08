// worker.go 扫描任务调度执行器（结构对齐 learningjobs janitor：
// RunOnce 可独立单测 + ticker Run 周期调度，挂 app.go 装配）。
//
// 执行纪律（设计稿 §五/§十一）：
//   - 整体开关 api_scan.enabled（settings，默认关）：关闭时调度器空转；
//   - 全局并发任务数上限（api_scan.max_concurrent_jobs，默认 1）+ 同目标互斥（claim 查询保证）；
//   - 每端点批次发包前 Guard 复查授权状态/时间窗与任务状态：撤销即刻停发（STOPPED），
//     过期/越窗按 FAILED 落 last_error，任务被外部停止即中止；
//   - 执行前强校验：目标启用、授权有效、base_url 主机落在授权 allowlist 内；
//   - 不静默吞错：失败原因落 progress.last_error + 操作审计。
package apiscan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
)

// 执行中止的分类错误（Guard 返回，execute 据此区分 STOPPED/FAILED）。
var (
	// errAuthorizationRevoked 授权已撤销（撤销即停 → STOPPED）。
	errAuthorizationRevoked = errors.New("授权已撤销")
	// errAuthorizationInactive 授权过期/越时间窗（→ FAILED，原因落 last_error）。
	errAuthorizationInactive = errors.New("授权已失效")
	// errJobStopped 任务已被外部停止（STOP 入口/紧急停止 → STOPPED）。
	errJobStopped = errors.New("任务已停止")
)

// SettingsProvider 调度开关与限额读取接口（*settings.Service 实现；nil 时默认关闭）。
type SettingsProvider interface {
	GetBool(ctx context.Context, group, key string, def bool) bool
	GetInt(ctx context.Context, group, key string, def int) int
}

// AuditRecorder 操作审计接口（*audits.Service 实现；nil 时跳过审计）。
type AuditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// 调度设置键（settings 组 api_scan）。
const (
	settingsGroup          = "api_scan"
	settingsKeyEnabled     = "enabled"                // 整体开关（默认关）
	settingsKeyMaxJobs     = "max_concurrent_jobs"    // 全局并发任务数（默认 1）
	settingsKeySweepSecond = "sweep_interval_seconds" // 调度间隔（默认 10s）
)

const (
	defaultSweepInterval = 10 * time.Second
	minSweepInterval     = 2 * time.Second
	maxSweepInterval     = 10 * time.Minute
)

// Stats 一轮调度结果。
type Stats struct {
	Claimed   int // 本轮取到并执行的任务数（0/1，RunOnce 单任务语义）
	Completed int // 本轮正常完成任务数
	Failed    int // 本轮失败任务数
	Stopped   int // 本轮被停止任务数（撤销/人工停止）
}

// runningJob 在跑任务的进程内句柄（停止/紧急停止取消用）。
type runningJob struct {
	cancel context.CancelFunc
	authz  uuid.UUID
}

// Worker 扫描任务调度执行器。
type Worker struct {
	store    Repository
	engine   Engine
	signer   *Signer // nil 时探针不携带签名头（记录警告；隔离标记缺失按未隔离形态降级）
	settings SettingsProvider
	audits   AuditRecorder

	mu      sync.Mutex
	running map[uuid.UUID]runningJob
	// starting 已占槽未登记的启动中任务数（与 len(running) 合计口径，
	// 并发上限检查与占槽同锁，消除 check-then-act 竞态）
	starting int
}

// NewWorker 创建调度执行器（engine 必填；signer/settings/audits 可为 nil）。
func NewWorker(store Repository, engine Engine, signer *Signer, settings SettingsProvider, auditSvc AuditRecorder) *Worker {
	return &Worker{
		store: store, engine: engine, signer: signer,
		settings: settings, audits: auditSvc,
		running: map[uuid.UUID]runningJob{},
	}
}

// Enabled 扫描能力整体开关（默认关；settings 未装配视为关——安全默认）。
func (w *Worker) Enabled(ctx context.Context) bool {
	if w.settings == nil {
		return false
	}
	return w.settings.GetBool(ctx, settingsGroup, settingsKeyEnabled, false)
}

// maxConcurrentJobs 全局并发任务数上限（默认 1，夹取 [1,8]）。
func (w *Worker) maxConcurrentJobs(ctx context.Context) int {
	n := 1
	if w.settings != nil {
		n = w.settings.GetInt(ctx, settingsGroup, settingsKeyMaxJobs, 1)
	}
	if n < 1 {
		n = 1
	}
	if n > 8 {
		n = 8
	}
	return n
}

// tryAcquireSlot 并发上限检查与占槽（同锁原子）：在跑 + 启动中合计达上限返回 false。
// 占槽成功须配对 releaseSlot（启动失败/空取）或登记进 running（execute defer 清理）。
// 上限值在锁外读取（settings 可能走 IO），检查与占槽仍在同一把锁内原子完成。
func (w *Worker) tryAcquireSlot(ctx context.Context) bool {
	maxJobs := w.maxConcurrentJobs(ctx)
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.running)+w.starting >= maxJobs {
		return false
	}
	w.starting++
	return true
}

// releaseSlot 释放启动占位（claim 空取/启动失败回滚用）。
func (w *Worker) releaseSlot() {
	w.mu.Lock()
	w.starting--
	w.mu.Unlock()
}

// ---------- 调度 ----------

// Run 周期调度（直到 ctx 取消）。
func (w *Worker) Run(ctx context.Context) {
	interval := defaultSweepInterval
	if w.settings != nil {
		sec := w.settings.GetInt(ctx, settingsGroup, settingsKeySweepSecond, int(defaultSweepInterval/time.Second))
		interval = time.Duration(sec) * time.Second
	}
	if interval < minSweepInterval {
		interval = minSweepInterval
	}
	if interval > maxSweepInterval {
		interval = maxSweepInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	slog.Info("api scan worker started", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("api scan worker stopped")
			return
		case <-t.C:
			stats, err := w.RunOnce(ctx)
			if err != nil {
				slog.Error("api scan sweep failed", "error", err)
				continue
			}
			if stats.Claimed > 0 {
				slog.Info("api scan swept",
					"completed", stats.Completed, "failed", stats.Failed, "stopped", stats.Stopped)
			}
		}
	}
}

// RunOnce 执行一轮调度：取一个 PENDING 任务并同步执行完（可由测试直接调用）。
// 开关关闭或已达全局并发上限时空转（Stats 零值，非错误）。
func (w *Worker) RunOnce(ctx context.Context) (Stats, error) {
	var stats Stats
	if !w.Enabled(ctx) {
		return stats, nil
	}
	if !w.tryAcquireSlot(ctx) {
		return stats, nil
	}
	job, err := w.store.ClaimPendingJob(ctx, time.Now().UTC())
	if err != nil {
		w.releaseSlot()
		return stats, fmt.Errorf("claim pending scan job: %w", err)
	}
	if job == nil {
		w.releaseSlot()
		return stats, nil
	}
	stats.Claimed = 1
	// 登记 running（StopJob/RevokeAuthorization 可取消调度任务；execute defer 清理）
	jobCtx, cancel := context.WithCancel(ctx)
	w.mu.Lock()
	w.starting--
	w.running[job.ID] = runningJob{cancel: cancel, authz: job.AuthorizationID}
	w.mu.Unlock()
	status, execErr := w.execute(jobCtx, job.ID)
	cancel()
	if execErr != nil {
		// execute 内部错误（如库读失败）：任务可能滞留 RUNNING，如实记日志暴露
		// （滞留任务恢复机制为后续分期，见分片报告遗留项）。
		slog.Error("execute scan job failed", "job_id", job.ID, "status", status, "error", execErr)
	}
	switch status {
	case JobStatusCompleted:
		stats.Completed = 1
	case JobStatusFailed:
		stats.Failed = 1
	case JobStatusStopped:
		stats.Stopped = 1
	}
	return stats, nil
}

// StartJob 手动启动任务（PENDING/PAUSED → 后台执行；处理器 POST /jobs/{id}/start 用）。
// 开关关闭 / 达并发上限 / 状态不允许时返回错误。
// 并发计数检查与占槽收在同一把锁内（tryAcquireSlot，消除 check-then-act 竞态：
// 两个并发 StartJob 不得同时看穿上限）；库操作失败即撤销占位。
func (w *Worker) StartJob(ctx context.Context, jobID uuid.UUID) error {
	if !w.Enabled(ctx) {
		return errors.New("主动扫描能力未启用（settings api_scan.enabled）")
	}
	if !w.tryAcquireSlot(ctx) {
		return errors.New("已达全局并发任务上限")
	}
	jobCtx, cancel := context.WithCancel(context.Background())
	// 失败回滚占位（goroutine 尚未启动，execute 的 defer 不负责清理）
	rollback := func(err error) error {
		w.releaseSlot()
		cancel()
		return err
	}
	if _, err := w.store.StartJob(ctx, jobID, time.Now().UTC()); err != nil {
		return rollback(err)
	}
	job, err := w.store.GetJob(ctx, jobID)
	if err != nil {
		return rollback(err)
	}
	w.mu.Lock()
	w.starting--
	w.running[jobID] = runningJob{cancel: cancel, authz: job.AuthorizationID}
	w.mu.Unlock()
	go w.execute(jobCtx, jobID)
	return nil
}

// StopJob 停止任务：库内状态置 STOPPED（PENDING/PAUSED/RUNNING），
// 进程内在跑任务取消执行上下文（停止即刻生效；跨实例场景由 Guard 下批复查兜底）。
func (w *Worker) StopJob(ctx context.Context, jobID uuid.UUID) (*Job, error) {
	job, err := w.store.StopJob(ctx, jobID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	if r, ok := w.running[jobID]; ok {
		r.cancel()
	}
	w.mu.Unlock()
	return job, nil
}

// EmergencyStop 紧急停止（设计稿 §十一.4）：停止任务 + 撤销其授权单 +
// 停止该授权下全部在跑/排队任务。返回撤销的授权单与停止任务数。
func (w *Worker) EmergencyStop(ctx context.Context, jobID uuid.UUID) (*Authorization, int64, error) {
	job, err := w.store.GetJob(ctx, jobID)
	if err != nil {
		return nil, 0, err
	}
	authz, stopped, err := w.RevokeAuthorization(ctx, job.AuthorizationID)
	if err != nil {
		return nil, 0, err
	}
	return authz, stopped, nil
}

// RevokeAuthorization 撤销授权并联动停止（撤销即停，设计稿 §5.1）：
// 授权置 revoked_at → 该授权下全部未终结任务置 STOPPED → 取消进程内执行上下文。
func (w *Worker) RevokeAuthorization(ctx context.Context, authorizationID uuid.UUID) (*Authorization, int64, error) {
	authz, err := w.store.RevokeAuthorization(ctx, authorizationID, time.Now().UTC())
	if err != nil {
		return nil, 0, err
	}
	stopped, err := w.store.StopJobsByAuthorization(ctx, authorizationID, time.Now().UTC())
	if err != nil {
		return nil, 0, err
	}
	w.mu.Lock()
	for _, r := range w.running {
		if r.authz == authorizationID {
			r.cancel()
		}
	}
	w.mu.Unlock()
	return authz, stopped, nil
}

// ---------- 执行 ----------

// execute 执行任务全生命周期：校验 → 探测 → 终结落库 + 审计。返回最终状态。
func (w *Worker) execute(ctx context.Context, jobID uuid.UUID) (string, error) {
	defer func() {
		w.mu.Lock()
		delete(w.running, jobID)
		w.mu.Unlock()
	}()
	now := time.Now().UTC()
	job, err := w.store.GetJob(ctx, jobID)
	if err != nil {
		return JobStatusFailed, fmt.Errorf("load scan job: %w", err)
	}
	progress := job.Progress

	// finish 终结任务（仅 RUNNING 可终结；外部已停止时不覆盖）+ 审计。
	finish := func(status, lastError string) (string, error) {
		if lastError != "" {
			progress.LastError = lastError
		}
		final, err := w.store.FinishJob(ctx, jobID, status, progress, time.Now().UTC())
		if err != nil {
			slog.Error("finish scan job failed", "job_id", jobID, "error", err)
			return status, err
		}
		w.auditJobFinished(ctx, final, lastError)
		return final.Status, nil
	}

	target, err := w.store.GetTarget(ctx, job.TargetID)
	if err != nil {
		return finish(JobStatusFailed, fmt.Sprintf("读取扫描目标失败: %v", err))
	}
	authz, err := w.store.GetAuthorization(ctx, job.AuthorizationID)
	if err != nil {
		return finish(JobStatusFailed, fmt.Sprintf("读取授权单失败: %v", err))
	}
	// 执行前强校验（设计稿 §5.1/§十一）
	if target.Status != TargetStatusEnabled {
		return finish(JobStatusFailed, "目标已停用")
	}
	if authz.RevokedAt != nil {
		return finish(JobStatusStopped, "授权已撤销")
	}
	if reason := authz.InactiveReason(now); reason != "" {
		return finish(JobStatusFailed, reason)
	}
	if !hostAllowed(target.BaseURL, authz.Allowlist) {
		return finish(JobStatusFailed, "目标主机不在授权 allowlist 内")
	}
	// DNS 重绑定防护：授权校验时刻固化主机解析快照，探测拨号逐次重解析比对
	// （hostAllowed 仅是字符串白名单，真实拨号须经快照复检，见 dial_guard.go）。
	snapshot, err := resolveHostSnapshot(ctx, target.BaseURL)
	if err != nil {
		return finish(JobStatusFailed, err.Error())
	}
	sets, err := resolveProbeSets(job.ProbeSet, authz.TestProfile)
	if err != nil {
		return finish(JobStatusFailed, err.Error())
	}
	progress.Total = len(target.AllowedPaths)
	if progress.Total == 0 {
		return finish(JobStatusCompleted, "") // 目标无允许路径：空跑完成（如实 0 端点）
	}
	if w.signer == nil {
		slog.Warn("api scan signer not assembled, probes run without isolation header", "job_id", jobID)
	}

	// Guard：每端点批次发包前复查任务与授权状态（撤销即停/停止即停/过期即失败）。
	guard := func(gctx context.Context) error {
		if err := gctx.Err(); err != nil {
			return err
		}
		curJob, err := w.store.GetJob(gctx, jobID)
		if err != nil {
			return err
		}
		if curJob.Status != JobStatusRunning {
			return errJobStopped
		}
		curAuthz, err := w.store.GetAuthorization(gctx, job.AuthorizationID)
		if err != nil {
			return err
		}
		if curAuthz.RevokedAt != nil {
			return errAuthorizationRevoked
		}
		if reason := curAuthz.InactiveReason(time.Now()); reason != "" {
			return fmt.Errorf("%w: %s", errAuthorizationInactive, reason)
		}
		return nil
	}

	var pmu sync.Mutex // progress 在引擎多 goroutine 回调间共享
	emit := func(res *ProbeResult) error {
		f := &Finding{
			JobID:          jobID,
			Engine:         "builtin",
			Template:       res.Template,
			EndpointKey:    res.EndpointKey,
			Category:       res.Category,
			Severity:       res.Severity,
			Confidence:     res.Confidence,
			Evidence:       res.Evidence,
			RequestSample:  res.RequestSample,
			ResponseSample: res.ResponseSample,
			Status:         FindingStatusNew,
		}
		if err := w.store.CreateFinding(ctx, f); err != nil {
			return err
		}
		pmu.Lock()
		progress.Findings++
		pmu.Unlock()
		return nil
	}
	task := &ProbeTask{
		JobID:          jobID,
		BaseURL:        target.BaseURL,
		Paths:          append([]string(nil), target.AllowedPaths...),
		ProbeSets:      sets,
		MaxQPS:         authz.MaxQPS,
		MaxConcurrency: authz.MaxConcurrency,
		Signer:         w.signer,
		Guard:          guard,
		// 拨号复检客户端：重解析比对授权快照（DNS 重绑定防护），语义同引擎默认客户端
		HTTPClient: newPinnedHTTPClient(snapshot),
		OnEndpointDone: func(done, total int) {
			pmu.Lock()
			progress.Done, progress.Total = done, total
			p := progress
			pmu.Unlock()
			if _, err := w.store.SaveJobProgress(context.Background(), jobID, p); err != nil {
				slog.Warn("save scan job progress failed", "job_id", jobID, "error", err)
			}
		},
	}

	summary, runErr := w.engine.Run(ctx, task, emit)
	pmu.Lock()
	progress.Done = summary.EndpointsDone
	progress.Total = len(target.AllowedPaths)
	progress.Requests = summary.Requests
	progress.Errors = summary.Errors
	if summary.LastError != "" {
		progress.LastError = summary.LastError
	}
	pmu.Unlock()

	switch {
	case runErr == nil && summary.EndpointsFailed > 0 && summary.EndpointsFailed == len(task.Paths):
		// 全部端点探测失败（目标不可达等）：任务判 FAILED，不伪装完成
		reason := progress.LastError
		if reason == "" {
			reason = "全部端点探测失败"
		}
		return finish(JobStatusFailed, reason)
	case runErr == nil:
		return finish(JobStatusCompleted, progress.LastError)
	case errors.Is(runErr, errAuthorizationRevoked), errors.Is(runErr, errJobStopped), errors.Is(runErr, context.Canceled):
		return finish(JobStatusStopped, runErr.Error())
	case errors.Is(runErr, errAuthorizationInactive):
		return finish(JobStatusFailed, runErr.Error())
	default:
		return finish(JobStatusFailed, runErr.Error())
	}
}

// auditJobFinished 任务终结审计（system 操作者；审计失败仅记日志，不反噬执行结果）。
func (w *Worker) auditJobFinished(ctx context.Context, job *Job, lastError string) {
	if w.audits == nil || job == nil {
		return
	}
	action := "scan_job_completed"
	risk := audits.RiskLow
	if job.Status == JobStatusFailed {
		action = "scan_job_failed"
		risk = audits.RiskMedium
	} else if job.Status == JobStatusStopped {
		action = "scan_job_stopped"
		risk = audits.RiskMedium
	}
	after := fmt.Sprintf("status=%s requests=%d findings=%d errors=%d",
		job.Status, job.Progress.Requests, job.Progress.Findings, job.Progress.Errors)
	if lastError != "" {
		after += " last_error=" + lastError
	}
	if err := w.audits.Record(ctx, audits.RecordInput{
		Username:     "system",
		Module:       "api_scan",
		Action:       action,
		ObjectType:   "api_scan_job",
		ObjectID:     job.ID.String(),
		AfterSummary: after,
		Result:       audits.ResultSuccess,
		RiskLevel:    risk,
	}); err != nil {
		slog.Warn("scan job audit record failed", "job_id", job.ID, "error", err)
	}
}

// ---------- 解析辅助 ----------

// resolveProbeSets 解析本次执行探针集：任务指定（逗号分隔）→ 授权画像 → 全部内置；
// 结果必须是词表子集，且授权画像非空时必须 ⊆ 画像（白名单制）。
func resolveProbeSets(jobProbeSet, testProfile string) ([]string, error) {
	parse := func(s string) ([]string, error) {
		var out []string
		for _, p := range strings.Split(s, ",") {
			p = strings.ToUpper(strings.TrimSpace(p))
			if p == "" {
				continue
			}
			if !IsValidProbeSet(p) {
				return nil, fmt.Errorf("词表外探针集: %q", p)
			}
			out = append(out, p)
		}
		return out, nil
	}
	profile, err := parse(testProfile)
	if err != nil {
		return nil, fmt.Errorf("授权画像非法: %v", err)
	}
	sets, err := parse(jobProbeSet)
	if err != nil {
		return nil, err
	}
	if len(sets) == 0 {
		sets = profile
	}
	if len(sets) == 0 {
		sets = AllProbeSets()
	}
	if len(profile) > 0 {
		allowed := map[string]bool{}
		for _, p := range profile {
			allowed[p] = true
		}
		for _, s := range sets {
			if !allowed[s] {
				return nil, fmt.Errorf("探针集 %q 不在授权画像白名单内", s)
			}
		}
	}
	return sets, nil
}

// hostAllowed base_url 主机白名单校验：allowlist 为空 = 仅允许 base_url 主机自身
// （探测只发向 base_url 主机，天然满足）；非空时主机须精确命中（不区分大小写）。
func hostAllowed(baseURL string, allowlist []string) bool {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if len(allowlist) == 0 {
		return true
	}
	for _, item := range allowlist {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if h, _, split := strings.Cut(item, ":"); split && h == host {
			return true // 允许 "host:port" 形态按主机命中
		}
		if item == host {
			return true
		}
	}
	return false
}
