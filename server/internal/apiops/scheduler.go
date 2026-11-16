// scheduler.go AI 运营定时任务调度器：结构对齐 learningjobs janitor
// （SweepOnce 可独立单测 + ticker Run 周期驱动）。「到点判定」为分钟级：
// 计划表存 next_run_at 游标，每轮 SweepOnce 取 next_run_at <= now 的 ENABLED 计划执行。
// 防重入：执行前先推进 next_run_at（claim 先行），再执行；同计划存在 RUNNING 记录时跳过。
// 全局开关 api_ai_ops.schedules_enabled（settings，默认关）门控调度与立即执行。
// 连续失败熔断：执行结局经 RecordRunOutcome 单事务记账（成功清零、失败 +1），
// 连续失败达 api_ai_ops.circuit_threshold（默认 3，夹取 1-10）同事务熔断停用
// （enabled=false + 清空 next_run_at + 记录熔断原因），新熔断触发系统告警
// （AI_OPS_SCHEDULE_CIRCUIT_OPEN，HIGH，组件 AI_OPS）与操作审计；手动启用复位熔断状态。
package apiops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
)

// settings 组与键（与 appconfigs/其他包同口径：组.键）。
const (
	settingsGroup               = "api_ai_ops"
	settingsKeyEnabled          = "schedules_enabled"      // 全局开关（默认关）
	settingsKeyIntervalSec      = "sweep_interval_seconds" // 调度检查间隔（默认 60s）
	settingsKeyCircuitThreshold = "circuit_threshold"      // 连续失败熔断阈值（默认 3，夹取 1-10）
)

// 调度检查间隔夹取范围（默认 60s，[5s, 1h] 防误配）。
const (
	DefaultSweepInterval = 60 * time.Second
	minSweepInterval     = 5 * time.Second
	maxSweepInterval     = time.Hour
)

// 连续失败熔断阈值夹取范围（默认 3，[1,10] 防误配）。
const (
	DefaultCircuitThreshold = 3
	minCircuitThreshold     = 1
	maxCircuitThreshold     = 10
)

// circuitComponent 熔断系统告警组件维度（固定 AI_OPS，同类型同组件告警走引擎合并/冷却）。
const circuitComponent = "AI_OPS"

// sweepBatchSize 单轮 SweepOnce 最多执行的到期计划数（防积压拖垮单轮，剩余下轮再取）。
const sweepBatchSize = 20

// AuditRecorder 操作审计接口（*audits.Service 实现；nil 时跳过审计）。
type AuditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// SettingsProvider 设置读取接口（*settings.Service 实现；nil 时全用默认——开关默认关）。
type SettingsProvider interface {
	GetBool(ctx context.Context, group, key string, def bool) bool
	GetInt(ctx context.Context, group, key string, def int) int
}

// Stats 一轮调度结果。
type Stats struct {
	Due       int // 本轮到期计划数
	Succeeded int // 执行成功数
	Failed    int // 执行失败数（单计划失败不阻断其他计划，原因落 runs/last_error）
	Skipped   int // 跳过数（存在 RUNNING 记录防重入）
}

// Sweeper AI 运营定时任务调度器。
type Sweeper struct {
	store      Repository
	source     Source
	summarizer Summarizer       // nil 时纯模板摘要
	audits     AuditRecorder    // 熔断等系统动作审计；nil 时跳过
	settings   SettingsProvider // nil 时开关默认关、间隔/阈值默认
	alerter    Alerter          // 熔断系统告警；nil 时跳过
	now        func() time.Time // 测试注入固定时钟
}

// NewSweeper 创建调度器。
func NewSweeper(store Repository, source Source) *Sweeper {
	return &Sweeper{store: store, source: source, now: time.Now}
}

// SetSummarizer 设置 LLM 摘要润色（装配时接现有 AI 服务；不设置则纯模板输出）。
func (s *Sweeper) SetSummarizer(v Summarizer) *Sweeper { s.summarizer = v; return s }

// SetAudits 设置操作审计（应用装配时使用）。
func (s *Sweeper) SetAudits(v AuditRecorder) *Sweeper { s.audits = v; return s }

// SetSettings 设置读取（应用装配时使用）。
func (s *Sweeper) SetSettings(v SettingsProvider) *Sweeper { s.settings = v; return s }

// Alerter 熔断系统告警接口（*systemalerts.Engine 天然实现，装配时直接注入；nil 时跳过告警）。
type Alerter interface {
	NotifyFailure(ctx context.Context, alertType, component, title, message string) (*systemalerts.Alert, error)
}

// SetAlerter 注入系统告警引擎（应用装配时使用）。
func (s *Sweeper) SetAlerter(a Alerter) *Sweeper { s.alerter = a; return s }

// SetClock 注入时钟（测试使用）。
func (s *Sweeper) SetClock(now func() time.Time) *Sweeper { s.now = now; return s }

// Enabled 全局开关（默认关；调度与立即执行共用）。
func (s *Sweeper) Enabled(ctx context.Context) bool {
	if s.settings == nil {
		return false
	}
	return s.settings.GetBool(ctx, settingsGroup, settingsKeyEnabled, false)
}

// interval 调度检查间隔（启动时读取一次；运行期改设置重启后生效）。
func (s *Sweeper) interval(ctx context.Context) time.Duration {
	sec := int(DefaultSweepInterval / time.Second)
	if s.settings != nil {
		sec = s.settings.GetInt(ctx, settingsGroup, settingsKeyIntervalSec, sec)
	}
	d := time.Duration(sec) * time.Second
	if d < minSweepInterval {
		d = minSweepInterval
	}
	if d > maxSweepInterval {
		d = maxSweepInterval
	}
	return d
}

// circuitThreshold 连续失败熔断阈值（每次执行结局记账时读取，运行期改设置即生效；
// 默认 3，夹取 [1,10] 防误配）。
func (s *Sweeper) circuitThreshold(ctx context.Context) int {
	n := DefaultCircuitThreshold
	if s.settings != nil {
		n = s.settings.GetInt(ctx, settingsGroup, settingsKeyCircuitThreshold, n)
	}
	if n < minCircuitThreshold {
		n = minCircuitThreshold
	}
	if n > maxCircuitThreshold {
		n = maxCircuitThreshold
	}
	return n
}

// Run 周期调度（直到 ctx 取消）。
func (s *Sweeper) Run(ctx context.Context) {
	interval := s.interval(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	slog.Info("api ai ops sweeper started", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("api ai ops sweeper stopped")
			return
		case <-t.C:
			stats, err := s.SweepOnce(ctx)
			if err != nil {
				slog.Error("api ai ops sweep failed", "error", err)
				continue
			}
			if stats.Due > 0 {
				slog.Info("api ai ops swept",
					"due", stats.Due, "succeeded", stats.Succeeded,
					"failed", stats.Failed, "skipped", stats.Skipped)
			}
		}
	}
}

// SweepOnce 执行一轮到点判定（可由调度与测试直接调用）：
// 全局开关关闭时空转返回；取到期 ENABLED 计划（限 sweepBatchSize），逐条先推进
// next_run_at（claim 防重入）再执行；单计划失败记 last_error + FAILED run，不阻断其他计划。
func (s *Sweeper) SweepOnce(ctx context.Context) (Stats, error) {
	var stats Stats
	if !s.Enabled(ctx) {
		return stats, nil
	}
	now := s.now()
	due, err := s.store.ListDueSchedules(ctx, now, sweepBatchSize)
	if err != nil {
		return stats, fmt.Errorf("list due schedules: %w", err)
	}
	stats.Due = len(due)
	for i := range due {
		sc := &due[i]
		// claim 先行：推进到期游标，执行期间下一 tick 不会重复拾取
		next, err := NextCronAfter(sc.CronExpr, now)
		if err != nil {
			// cron 写入时已校验，此分支仅在库内数据被旁路改写时可达：
			// 清空游标防空转，记 FAILED run + last_error，不静默吞错
			if uerr := s.store.UpdateNextRunAt(ctx, sc.ID, nil); uerr != nil {
				slog.Error("clear unschedulable next_run_at failed", "schedule_id", sc.ID, "error", uerr)
			}
			if rerr := s.recordFailedRun(ctx, sc, err); rerr != nil {
				slog.Error("record unschedulable schedule run failed", "schedule_id", sc.ID, "error", rerr)
			}
			stats.Failed++
			continue
		}
		if err := s.store.UpdateNextRunAt(ctx, sc.ID, &next); err != nil {
			stats.Failed++
			slog.Error("claim schedule next_run_at failed", "schedule_id", sc.ID, "error", err)
			continue
		}
		if _, err := s.executeSchedule(ctx, sc); err != nil {
			if errors.Is(err, ErrRunConflict) {
				stats.Skipped++
				continue
			}
			stats.Failed++
			slog.Error("execute schedule failed", "schedule_id", sc.ID, "task_type", sc.TaskType, "error", err)
			continue
		}
		stats.Succeeded++
	}
	return stats, nil
}

// RunNow 立即执行（手动入口；不经 next_run_at 游标，不改变排期）。
// 全局开关关闭返回 ErrSchedulesDisabled；同计划存在 RUNNING 记录返回 ErrRunConflict。
func (s *Sweeper) RunNow(ctx context.Context, scheduleID uuid.UUID) (*Run, error) {
	if !s.Enabled(ctx) {
		return nil, ErrSchedulesDisabled
	}
	sc, err := s.store.GetSchedule(ctx, scheduleID)
	if err != nil {
		return nil, err
	}
	return s.executeSchedule(ctx, sc)
}

// executeSchedule 执行单个计划：建 RUNNING 记录 → 任务函数产出报告+模板摘要 →
// LLM 润色（可选，失败回退模板）→ 终结记录 + 回填计划执行轨迹。
// 任务失败：run 置 FAILED、summary 落失败原因、计划 last_status/last_error 同步——不静默吞错。
func (s *Sweeper) executeSchedule(ctx context.Context, sc *Schedule) (*Run, error) {
	running, err := s.store.HasRunningRun(ctx, sc.ID)
	if err != nil {
		return nil, err
	}
	if running {
		return nil, ErrRunConflict
	}
	startedAt := s.now()
	run := &Run{ScheduleID: sc.ID, StartedAt: startedAt}
	if err := s.store.CreateRun(ctx, run); err != nil {
		return nil, fmt.Errorf("create run: %w", err)
	}

	report, summary, runErr := s.produce(ctx, sc, startedAt)
	finishedAt := s.now()
	status := RunStatusSuccess
	errMsg := ""
	if runErr != nil {
		status = RunStatusFailed
		errMsg = runErr.Error()
		summary = "执行失败：" + errMsg
		report = json.RawMessage(`{}`)
	}
	if err := s.store.FinishRun(ctx, run.ID, status, summary, report, finishedAt); err != nil {
		return nil, fmt.Errorf("finish run: %w", err)
	}
	// 结局记账（单事务：轨迹回填 + 连续失败计数 + 达阈熔断）；熔断后视图回填 run 输出
	updated, circuitOpened, err := s.store.RecordRunOutcome(ctx, sc.ID, startedAt, status, errMsg, s.circuitThreshold(ctx))
	if err != nil {
		return nil, fmt.Errorf("record run outcome: %w", err)
	}
	if updated != nil {
		*sc = *updated
	}
	if circuitOpened {
		s.onCircuitOpen(ctx, sc)
	}
	run.Status, run.Summary, run.Report, run.FinishedAt = status, summary, report, &finishedAt
	if runErr != nil {
		return run, runErr
	}
	return run, nil
}

// recordFailedRun 执行前失败（如 cron 失效）的记录路径：FAILED run + 结局记账（含熔断计数）。
func (s *Sweeper) recordFailedRun(ctx context.Context, sc *Schedule, cause error) error {
	startedAt := s.now()
	run := &Run{ScheduleID: sc.ID, StartedAt: startedAt}
	if err := s.store.CreateRun(ctx, run); err != nil {
		return fmt.Errorf("create run: %w", err)
	}
	finishedAt := s.now()
	if err := s.store.FinishRun(ctx, run.ID, RunStatusFailed, "执行失败："+cause.Error(), json.RawMessage(`{}`), finishedAt); err != nil {
		return fmt.Errorf("finish run: %w", err)
	}
	updated, circuitOpened, err := s.store.RecordRunOutcome(ctx, sc.ID, startedAt, RunStatusFailed, cause.Error(), s.circuitThreshold(ctx))
	if err != nil {
		return fmt.Errorf("record run outcome: %w", err)
	}
	if updated != nil {
		*sc = *updated
	}
	if circuitOpened {
		s.onCircuitOpen(ctx, sc)
	}
	return nil
}

// onCircuitOpen 熔断触发后续：系统告警（AI_OPS_SCHEDULE_CIRCUIT_OPEN，HIGH，组件 AI_OPS）
// + 操作审计（系统动作，username=system，高风险）。告警/审计失败只记日志，不影响记账结果
// （熔断事实已落库，告警引擎侧另有自身可靠性机制）。
func (s *Sweeper) onCircuitOpen(ctx context.Context, sc *Schedule) {
	title := "AI 运营计划连续失败已熔断"
	message := fmt.Sprintf("计划「%s」（%s）%s；已自动停用并清空排期游标，人工排查后经启用接口恢复",
		sc.Name, sc.TaskType, sc.CircuitReason)
	if s.alerter != nil {
		if _, err := s.alerter.NotifyFailure(ctx, systemalerts.TypeAIOpsScheduleCircuitOpen, circuitComponent, title, message); err != nil {
			slog.Error("raise ai ops circuit alert failed", "schedule_id", sc.ID, "error", err)
		}
	}
	if s.audits != nil {
		if err := s.audits.Record(ctx, audits.RecordInput{
			Username:   "system",
			Module:     "api_ai_ops",
			Action:     "ai_schedule_circuit_open",
			ObjectType: "api_ai_schedule",
			ObjectID:   sc.ID.String(),
			ObjectName: sc.Name,
			AfterSummary: fmt.Sprintf("计划「%s」（%s）连续失败达阈值自动熔断停用：%s",
				sc.Name, sc.TaskType, sc.CircuitReason),
			Result:    audits.ResultSuccess,
			RiskLevel: audits.RiskHigh,
		}); err != nil {
			slog.Error("record ai ops circuit audit failed", "schedule_id", sc.ID, "error", err)
		}
	}
	slog.Warn("ai ops schedule circuit opened",
		"schedule_id", sc.ID, "task_type", sc.TaskType, "reason", sc.CircuitReason)
}

// produce 任务产出公共路径：解析入参 → 查注册表执行任务 → 序列化报告 → LLM 润色。
func (s *Sweeper) produce(ctx context.Context, sc *Schedule, now time.Time) (json.RawMessage, string, error) {
	cfg, err := ParseTaskConfig(sc.Config)
	if err != nil {
		return nil, "", err
	}
	fn, ok := taskRegistry[sc.TaskType]
	if !ok {
		return nil, "", fmt.Errorf("%w：%s", ErrInvalidTaskType, sc.TaskType)
	}
	res, err := fn(ctx, s.source, cfg, now)
	if err != nil {
		return nil, "", err
	}
	summary := polishSummary(ctx, s.summarizer, sc.TaskType, res.Report, res.Draft)
	raw, err := json.Marshal(res.Report)
	if err != nil {
		return nil, "", fmt.Errorf("marshal report: %w", err)
	}
	return raw, summary, nil
}
