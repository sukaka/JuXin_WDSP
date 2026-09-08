// scheduler.go AI 运营定时任务调度器：结构对齐 learningjobs janitor
// （SweepOnce 可独立单测 + ticker Run 周期驱动）。「到点判定」为分钟级：
// 计划表存 next_run_at 游标，每轮 SweepOnce 取 next_run_at <= now 的 ENABLED 计划执行。
// 防重入：执行前先推进 next_run_at（claim 先行），再执行；同计划存在 RUNNING 记录时跳过。
// 全局开关 api_ai_ops.schedules_enabled（settings，默认关）门控调度与立即执行。
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
)

// settings 组与键（与 appconfigs/其他包同口径：组.键）。
const (
	settingsGroup          = "api_ai_ops"
	settingsKeyEnabled     = "schedules_enabled"      // 全局开关（默认关）
	settingsKeyIntervalSec = "sweep_interval_seconds" // 调度检查间隔（默认 60s）
)

// 调度检查间隔夹取范围（默认 60s，[5s, 1h] 防误配）。
const (
	DefaultSweepInterval = 60 * time.Second
	minSweepInterval     = 5 * time.Second
	maxSweepInterval     = time.Hour
)

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
	audits     AuditRecorder    // 保留扩展位（计划触发审计）；nil 时跳过
	settings   SettingsProvider // nil 时开关默认关、间隔默认 60s
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
	if err := s.store.UpdateScheduleRunState(ctx, sc.ID, startedAt, status, errMsg); err != nil {
		return nil, fmt.Errorf("update schedule run state: %w", err)
	}
	run.Status, run.Summary, run.Report, run.FinishedAt = status, summary, report, &finishedAt
	if runErr != nil {
		return run, runErr
	}
	return run, nil
}

// recordFailedRun 执行前失败（如 cron 失效）的记录路径：FAILED run + 计划轨迹回填。
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
	if err := s.store.UpdateScheduleRunState(ctx, sc.ID, startedAt, RunStatusFailed, cause.Error()); err != nil {
		return fmt.Errorf("update schedule run state: %w", err)
	}
	return nil
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
