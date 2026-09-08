// Package learningjobs 学习自动化闭环（P0-1）多条件判定调度：
// 周期扫描 RUNNING 学习任务 → 多条件判定（样本量/来源与身份多样性/学习时长/成功率，
// 见 conditions.go）→ 全满足才完成任务（COMPLETED + 接口 LEARNED + 生命周期事件）→
// 自动构建非空候选并自动提交评审（IN_REVIEW；见 apimodels/candidate_builder.go）→
// 回填 candidate_version_id → 操作审计。超过最长学习时限仍未达标的任务置 FAILED +
// last_error 说明。确认与冻结仍为人工动作，自动化只到提交评审为止。
// 结构对齐 guardjanitor：SweepOnce 可独立测试 + ticker Run 周期调度。
package learningjobs

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/audits"
)

// Jobs 学习任务持久化接口（*apiassets.Store 实现）。
type Jobs interface {
	ListRunningLearningJobs(ctx context.Context) ([]apiassets.LearningJobProgress, error)
	CompleteLearning(ctx context.Context, jobID, endpointID uuid.UUID, actor, reason string) (*apiassets.LearningJob, error)
	FailLearning(ctx context.Context, jobID uuid.UUID, cause string) error
	RecordLearningError(ctx context.Context, jobID uuid.UUID, cause string) error
	AttachLearningCandidate(ctx context.Context, jobID, versionID uuid.UUID) error
}

// Candidates 模型候选创建接口（*apimodels.Store 实现）。
// CreateLearnedCandidate 内部完成「观测画像 → 非空 schema 候选（无观测回退空 Schema）→
// 参数行 observed 物化 → 自动提交 IN_REVIEW」，返回版本（状态已 IN_REVIEW）。
type Candidates interface {
	EndpointKey(ctx context.Context, endpointID uuid.UUID) (string, error)
	CreateLearnedCandidate(ctx context.Context, endpointID uuid.UUID, endpointKey string, validSamples int) (*apimodels.Version, error)
}

// Profiles 参数统计画像刷新接口（*apimodels.Store 实现；nil 时跳过）。
// 三微模型框架 §四.5：学习样本离线聚合 → api_parameter_statistics + observed/recommended；
// 画像刷新后顺带做敏感级别自动标注（敏感字段台账回写 + 语义兜底，只补 UNKNOWN）。
type Profiles interface {
	RefreshParameterStatistics(ctx context.Context) (int, error)
	PropagateSensitivityLevels(ctx context.Context) (int64, error)
}

// Relations 参数关系候选刷新接口（*apimodels.Store 实现；nil 时跳过）。
type Relations interface {
	RefreshParameterRelationCandidates(ctx context.Context) (int, error)
}

// AuditRecorder 操作审计接口（*audits.Service 实现；nil 时跳过审计）。
type AuditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// SettingsProvider 调度间隔与学习条件设置读取接口（*settings.Service 实现；nil 时全用默认）。
type SettingsProvider interface {
	GetInt(ctx context.Context, group, key string, def int) int
	GetString(ctx context.Context, group, key, def string) string
}

// 调度间隔：默认 30s，可经 system_settings 组 api_learning 的 sweep_interval_seconds 覆盖；
// 夹取 [5s, 1h] 防误配。
const (
	DefaultInterval = 30 * time.Second
	minInterval     = 5 * time.Second
	maxInterval     = time.Hour
)

// Stats 一轮清扫结果。
type Stats struct {
	Scanned   int // 扫描到的 RUNNING 且 sample_target>0 任务数
	Completed int // 本轮完成的任务数
	Failed    int // 本轮失败的任务数（单任务失败不阻断其他任务）
	// Expired 本轮超期未达标置 FAILED 的任务数（不计入 Failed：属正常终结而非执行错误）。
	Expired int
	// ProfilesRefreshed 本轮参数统计画像 UPSERT 行数（未注入 Profiles 时恒 0）。
	ProfilesRefreshed int
}

// Worker 学习阈值判定调度器。
type Worker struct {
	jobs       Jobs
	candidates Candidates
	audits     AuditRecorder
	settings   SettingsProvider
	profiles   Profiles  // nil 时跳过参数统计画像刷新
	relations  Relations // nil 时跳过关系候选
}

// NewWorker 创建调度器。
func NewWorker(jobs Jobs, candidates Candidates, auditSvc AuditRecorder, settings SettingsProvider) *Worker {
	return &Worker{jobs: jobs, candidates: candidates, audits: auditSvc, settings: settings}
}

// SetProfileRefresher 设置参数统计画像刷新接口（应用装配时使用；未设置时跳过画像刷新）。
func (w *Worker) SetProfileRefresher(p Profiles) { w.profiles = p }

// SetRelationRefresher 设置参数关系候选刷新（应用装配时使用；未设置时跳过）。
func (w *Worker) SetRelationRefresher(r Relations) { w.relations = r }

// interval 解析调度间隔（启动时读取一次；运行期改设置在重启后生效）。
func (w *Worker) interval(ctx context.Context) time.Duration {
	sec := int(DefaultInterval / time.Second)
	if w.settings != nil {
		sec = w.settings.GetInt(ctx, "api_learning", "sweep_interval_seconds", sec)
	}
	d := time.Duration(sec) * time.Second
	if d < minInterval {
		d = minInterval
	}
	if d > maxInterval {
		d = maxInterval
	}
	return d
}

// Run 周期调度（直到 ctx 取消）。
func (w *Worker) Run(ctx context.Context) {
	interval := w.interval(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	slog.Info("learning jobs worker started", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("learning jobs worker stopped")
			return
		case <-t.C:
			stats, err := w.SweepOnce(ctx)
			if err != nil {
				slog.Error("learning jobs sweep failed", "error", err)
				continue
			}
			if stats.Completed > 0 || stats.Failed > 0 || stats.Expired > 0 || stats.ProfilesRefreshed > 0 {
				slog.Info("learning jobs swept",
					"scanned", stats.Scanned, "completed", stats.Completed, "failed", stats.Failed,
					"expired", stats.Expired, "profiles_refreshed", stats.ProfilesRefreshed)
			}
		}
	}
}

// SweepOnce 执行一轮多条件判定（可由调度与测试直接调用）。
// 逐任务处理：全部条件满足 → 完成 + 自动候选/提交评审 + 审计；未满足且超最长时限 →
// FAILED + last_error 说明；单任务失败记 last_error 并统计，不阻断其他任务。
// 任务循环后整轮刷新一次参数统计画像（已注入 Profiles 时；幂等可重算，失败向上返回，
// 调度器记日志下轮重试，不静默吞错）。
func (w *Worker) SweepOnce(ctx context.Context) (Stats, error) {
	var stats Stats
	jobs, err := w.jobs.ListRunningLearningJobs(ctx)
	if err != nil {
		return stats, fmt.Errorf("list running learning jobs: %w", err)
	}
	stats.Scanned = len(jobs)
	cond := LoadLearningConditions(ctx, w.settings)
	now := time.Now()
	for i := range jobs {
		job := &jobs[i]
		if unmet := EvaluateLearningConditions(job, cond, now); len(unmet) > 0 {
			// 超期未达标：任务置 FAILED + last_error 说明（正常终结，非执行错误）。
			if LearningExpired(job, cond, now) {
				cause := fmt.Sprintf("学习超过最长时限（%s）仍未达标：%s",
					cond.MaxDuration, strings.Join(unmet, "；"))
				if err := w.jobs.FailLearning(ctx, job.ID, cause); err != nil {
					stats.Failed++
					slog.Error("fail learning job failed",
						"job_id", job.ID, "endpoint_id", job.EndpointID, "error", err)
					if rerr := w.jobs.RecordLearningError(ctx, job.ID, err.Error()); rerr != nil {
						slog.Error("record learning job error failed", "job_id", job.ID, "error", rerr)
					}
					continue
				}
				stats.Expired++
				slog.Info("learning job expired",
					"job_id", job.ID, "endpoint_id", job.EndpointID, "cause", cause)
			}
			continue
		}
		if err := w.completeJob(ctx, job); err != nil {
			stats.Failed++
			slog.Error("complete learning job failed",
				"job_id", job.ID, "endpoint_id", job.EndpointID, "error", err)
			if rerr := w.jobs.RecordLearningError(ctx, job.ID, err.Error()); rerr != nil {
				slog.Error("record learning job error failed", "job_id", job.ID, "error", rerr)
			}
			continue
		}
		stats.Completed++
	}
	// 参数统计画像刷新（三微模型 §四.5）：学习任务循环后整轮一次。
	if w.profiles != nil {
		n, err := w.profiles.RefreshParameterStatistics(ctx)
		if err != nil {
			return stats, fmt.Errorf("refresh parameter statistics: %w", err)
		}
		stats.ProfilesRefreshed = n
		// 敏感级别自动标注（敏感字段台账回写 + 语义兜底）：紧随画像刷新，
		// 失败同样向上返回（对齐画像刷新，不静默吞错，下轮重试）。
		if _, err := w.profiles.PropagateSensitivityLevels(ctx); err != nil {
			return stats, fmt.Errorf("propagate sensitivity levels: %w", err)
		}
	}
	// 参数关系候选（只读，不自动生效）
	if w.relations != nil {
		if _, err := w.relations.RefreshParameterRelationCandidates(ctx); err != nil {
			slog.Warn("refresh parameter relation candidates failed", "error", err)
		}
	}
	return stats, nil
}

// completeJob 完成单个达标任务：完成任务 → 自动构建候选并提交评审 → 回填候选版本 → 审计。
// 候选创建失败不回滚任务完成：样本产物已就绪，失败原因经 last_error 暴露，可手工补建候选；
// 避免「候选已建、完成失败」重试产生重复候选版本。
func (w *Worker) completeJob(ctx context.Context, job *apiassets.LearningJobProgress) error {
	endpointKey, err := w.candidates.EndpointKey(ctx, job.EndpointID)
	if err != nil {
		return fmt.Errorf("resolve endpoint key: %w", err)
	}
	reason := fmt.Sprintf("学习达标（有效 %d/目标 %d，来源 %d，身份 %d）自动完成学习",
		job.ValidCount, job.SampleTarget, job.UniqueIPs, job.UniqueIdentities)
	if _, err := w.jobs.CompleteLearning(ctx, job.ID, job.EndpointID, "system", reason); err != nil {
		return fmt.Errorf("complete learning: %w", err)
	}
	v, err := w.candidates.CreateLearnedCandidate(ctx, job.EndpointID, endpointKey, job.ValidCount)
	if err != nil {
		return fmt.Errorf("create learned candidate: %w", err)
	}
	if err := w.jobs.AttachLearningCandidate(ctx, job.ID, v.ID); err != nil {
		return fmt.Errorf("attach candidate version: %w", err)
	}
	if w.audits != nil {
		if err := w.audits.Record(ctx, audits.RecordInput{
			Username:   "system",
			Module:     "api_learning",
			Action:     "learning_auto_complete",
			ObjectType: "api_endpoint",
			ObjectID:   job.EndpointID.String(),
			ObjectName: endpointKey,
			AfterSummary: fmt.Sprintf("任务学习达标（有效 %d/目标 %d，来源 %d，身份 %d）自动完成学习，生成候选模型 v%d（%s）并自动提交评审",
				job.ValidCount, job.SampleTarget, job.UniqueIPs, job.UniqueIdentities, v.VersionNumber, v.ID),
			Result:    audits.ResultSuccess,
			RiskLevel: audits.RiskMedium,
		}); err != nil {
			slog.Warn("learning auto-complete audit record failed", "job_id", job.ID, "error", err)
		}
	}
	return nil
}
