// ai_retention.go 阶段7 §26.4：AI 数据保留期限与清理。
// 分表保留天数经 system_settings（ai 组）配置，每次 sweep 读最新值，调整即时生效；
// 未配置或取值非法（<=0）时回落到内置保守默认值。
// 清理语义：
//   - 会话/Tool 调用/草稿/用量分批限量物理删除，写系统审计，失败记错误不静默；
//   - 被保留期内的 AI 审计记录引用的会话（含其任务）、Tool 调用、草稿不得提前清理；
//   - 已采纳（ACCEPTED）与待审核（PENDING_REVIEW）的草稿一律保留；
//   - 审计表 ai_audit_records 为哈希链，删除任意前缀都会破坏 VerifyChain 校验基线，
//     因此只归档不删除，每次 sweep 附带链完整性校验，不符即报错写系统审计。
package guardjanitor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aiaudit"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/settings"
)

// 内置默认保留天数（保守值；与迁移 000141 种子一致，可被 system_settings 覆盖）。
const (
	DefaultAISessionRetentionDays  = 90
	DefaultAIToolCallRetentionDays = 90
	DefaultAIDraftRetentionDays    = 90
	DefaultAIUsageRetentionDays    = 180
	DefaultAIAuditRetentionDays    = 365
)

const (
	// aiRetentionBatchSize 单批删除行数上限（分批防长事务/锁表）。
	aiRetentionBatchSize = 500
	// aiRetentionMaxBatches 每张表单次 sweep 的最大批数（限量，余量留待下轮）。
	aiRetentionMaxBatches = 20
	// aiRetentionBatchSleep 批间暂停（给业务查询让行）。
	aiRetentionBatchSleep = 200 * time.Millisecond
	// aiChainVerifyLimit 每次 sweep 审计哈希链校验的最大行数。
	aiChainVerifyLimit = 100000
)

// DefaultAIRetentionInterval AI 留存清理默认调度间隔（低频任务）。
const DefaultAIRetentionInterval = time.Hour

// AIRetentionConfig 分表保留期限（天）。
type AIRetentionConfig struct {
	SessionDays  int
	ToolCallDays int
	DraftDays    int
	UsageDays    int
	AuditDays    int
}

// normalized 非法取值（<=0）回落默认值，保证清理永不放大为全表删除。
func (c AIRetentionConfig) normalized() AIRetentionConfig {
	if c.SessionDays <= 0 {
		c.SessionDays = DefaultAISessionRetentionDays
	}
	if c.ToolCallDays <= 0 {
		c.ToolCallDays = DefaultAIToolCallRetentionDays
	}
	if c.DraftDays <= 0 {
		c.DraftDays = DefaultAIDraftRetentionDays
	}
	if c.UsageDays <= 0 {
		c.UsageDays = DefaultAIUsageRetentionDays
	}
	if c.AuditDays <= 0 {
		c.AuditDays = DefaultAIAuditRetentionDays
	}
	return c
}

// aiIntGetter 读取整数设置（*settings.Service 实现）。
type aiIntGetter interface {
	GetInt(ctx context.Context, group, key string, def int) int
}

// aiAuditRecorder 系统审计记录（*audits.Service 实现）。
type aiAuditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// aiChainVerifier AI 审计哈希链校验（*aiaudit.Service 实现）。
type aiChainVerifier interface {
	VerifyChain(ctx context.Context, limit int) (int, error)
}

// AIRetentionStore AI 表分批删除存储（SQL 实现见 ai_retention_store.go；
// 接口抽出便于单元测试覆盖分批/引用保护/边界语义）。
type AIRetentionStore interface {
	// DeleteSessionsBatch 删除 updated_at 早于 cutoff 且未被 AI 审计引用的会话，最多 limit 行。
	// 会话的消息/任务/Tool 调用/压缩记录随外键级联删除；所属任务被审计引用的会话由存储层排除。
	DeleteSessionsBatch(ctx context.Context, cutoff time.Time, limit int) (int64, error)
	// DeleteToolCallsBatch 删除 created_at 早于 cutoff 且所属任务未被 AI 审计引用的 Tool 调用，最多 limit 行。
	DeleteToolCallsBatch(ctx context.Context, cutoff time.Time, limit int) (int64, error)
	// DeleteDraftsBatch 删除 created_at 早于 cutoff 的可清理草稿（DRAFT/REJECTED/EXPIRED
	// 且未被 AI 审计 draft_reference 引用），最多 limit 行。
	DeleteDraftsBatch(ctx context.Context, cutoff time.Time, limit int) (int64, error)
	// DeleteUsageBatch 删除 created_at 早于 cutoff 的用量记录，最多 limit 行。
	DeleteUsageBatch(ctx context.Context, cutoff time.Time, limit int) (int64, error)
}

// AISweepResult 一次 AI 留存清理的结果。
type AISweepResult struct {
	SessionsDeleted  int64
	ToolCallsDeleted int64
	DraftsDeleted    int64
	UsageDeleted     int64
	AuditMismatches  int
}

func (r AISweepResult) total() int64 {
	return r.SessionsDeleted + r.ToolCallsDeleted + r.DraftsDeleted + r.UsageDeleted
}

// AIRetentionCleaner AI 数据保留清理器。
type AIRetentionCleaner struct {
	store    AIRetentionStore
	settings aiIntGetter
	audit    aiAuditRecorder
	chain    aiChainVerifier // 可为 nil（未装配时跳过链校验）

	batchSize  int           // 单批删除行数上限；<=0 时用 aiRetentionBatchSize
	maxBatches int           // 每表单次 sweep 最大批数；<=0 时用 aiRetentionMaxBatches
	batchSleep time.Duration // 批间暂停；<0 时用 aiRetentionBatchSleep（0 表示不暂停，供测试）
}

// NewAIRetentionCleaner 创建 AI 留存清理器（生产装配入口）。
func NewAIRetentionCleaner(db *pgxpool.Pool, settingsSvc *settings.Service, auditSvc *audits.Service, chain *aiaudit.Service) *AIRetentionCleaner {
	return &AIRetentionCleaner{
		store:      newAIRetentionSQLStore(db),
		settings:   settingsSvc,
		audit:      auditSvc,
		chain:      chain,
		batchSize:  aiRetentionBatchSize,
		maxBatches: aiRetentionMaxBatches,
		batchSleep: aiRetentionBatchSleep,
	}
}

// ResolveConfig 读取当前生效的保留配置（每次 sweep 调用，设置修改即时生效）。
func (c *AIRetentionCleaner) ResolveConfig(ctx context.Context) AIRetentionConfig {
	cfg := AIRetentionConfig{
		SessionDays:  DefaultAISessionRetentionDays,
		ToolCallDays: DefaultAIToolCallRetentionDays,
		DraftDays:    DefaultAIDraftRetentionDays,
		UsageDays:    DefaultAIUsageRetentionDays,
		AuditDays:    DefaultAIAuditRetentionDays,
	}
	if c.settings != nil {
		cfg.SessionDays = c.settings.GetInt(ctx, "ai", "retention_session_days", cfg.SessionDays)
		cfg.ToolCallDays = c.settings.GetInt(ctx, "ai", "retention_tool_call_days", cfg.ToolCallDays)
		cfg.DraftDays = c.settings.GetInt(ctx, "ai", "retention_draft_days", cfg.DraftDays)
		cfg.UsageDays = c.settings.GetInt(ctx, "ai", "retention_usage_days", cfg.UsageDays)
		cfg.AuditDays = c.settings.GetInt(ctx, "ai", "retention_audit_days", cfg.AuditDays)
	}
	return cfg.normalized()
}

// SweepOnce 执行一轮 AI 留存清理（可由调度与测试直接调用）。
// 单表失败不阻断其他表，全部错误经 errors.Join 如实返回，不静默。
func (c *AIRetentionCleaner) SweepOnce(ctx context.Context) (AISweepResult, error) {
	var result AISweepResult
	if c.store == nil {
		return result, errors.New("ai retention store not configured")
	}
	cfg := c.ResolveConfig(ctx)
	now := time.Now().UTC()
	var errs []error

	if n, err := c.sweepTable(ctx, "ai_sessions", now.Add(-time.Duration(cfg.SessionDays)*24*time.Hour), c.store.DeleteSessionsBatch); err != nil {
		errs = append(errs, err)
	} else {
		result.SessionsDeleted = n
	}
	if n, err := c.sweepTable(ctx, "ai_tool_calls", now.Add(-time.Duration(cfg.ToolCallDays)*24*time.Hour), c.store.DeleteToolCallsBatch); err != nil {
		errs = append(errs, err)
	} else {
		result.ToolCallsDeleted = n
	}
	if n, err := c.sweepTable(ctx, "ai_recommendations", now.Add(-time.Duration(cfg.DraftDays)*24*time.Hour), c.store.DeleteDraftsBatch); err != nil {
		errs = append(errs, err)
	} else {
		result.DraftsDeleted = n
	}
	if n, err := c.sweepTable(ctx, "ai_usage_records", now.Add(-time.Duration(cfg.UsageDays)*24*time.Hour), c.store.DeleteUsageBatch); err != nil {
		errs = append(errs, err)
	} else {
		result.UsageDeleted = n
	}

	// 审计表哈希链只校验不删除（归档口径 retention_audit_days 不触发物理清理）。
	if c.chain != nil {
		mismatches, verr := c.chain.VerifyChain(ctx, aiChainVerifyLimit)
		switch {
		case verr != nil:
			errs = append(errs, fmt.Errorf("verify ai audit chain: %w", verr))
		case mismatches > 0:
			result.AuditMismatches = mismatches
			slog.Error("ai audit hash chain integrity check failed", "mismatches", mismatches)
		}
	}

	// 系统审计（有实际删除或链校验不符才记录；审计失败仅告警，不掩盖清理结果）。
	if c.audit != nil && (result.total() > 0 || result.AuditMismatches > 0) {
		auditResult := audits.ResultSuccess
		failureReason := ""
		if result.AuditMismatches > 0 {
			auditResult = audits.ResultFailure
			failureReason = fmt.Sprintf("审计哈希链不符 %d 条", result.AuditMismatches)
		}
		if err := c.audit.Record(ctx, audits.RecordInput{
			Username:      "system",
			Module:        "ai_assistant",
			Action:        "ai_data_retention",
			ObjectType:    "ai_data",
			ObjectName:    "AI 数据保留清理",
			AfterSummary:  fmt.Sprintf("会话清理 %d 条，Tool 调用清理 %d 条，草稿清理 %d 条，用量清理 %d 条；审计表仅归档不删除（链校验不符 %d 条）", result.SessionsDeleted, result.ToolCallsDeleted, result.DraftsDeleted, result.UsageDeleted, result.AuditMismatches),
			Result:        auditResult,
			FailureReason: failureReason,
			RiskLevel:     audits.RiskLow,
		}); err != nil {
			slog.Warn("ai retention audit record failed", "error", err)
		}
	}
	return result, errors.Join(errs...)
}

// sweepTable 单表分批限量清理：每批最多 batchSize 行，
// 单次 sweep 最多 maxBatches 批，达到上限时余量留待下轮并记告警。
func (c *AIRetentionCleaner) sweepTable(ctx context.Context, table string, cutoff time.Time,
	del func(context.Context, time.Time, int) (int64, error)) (int64, error) {
	batchSize := c.batchSize
	if batchSize <= 0 {
		batchSize = aiRetentionBatchSize
	}
	maxBatches := c.maxBatches
	if maxBatches <= 0 {
		maxBatches = aiRetentionMaxBatches
	}
	batchSleep := c.batchSleep
	if batchSleep < 0 {
		batchSleep = aiRetentionBatchSleep
	}
	var total int64
	for batch := 0; batch < maxBatches; batch++ {
		n, err := del(ctx, cutoff, batchSize)
		if err != nil {
			return total, fmt.Errorf("clean %s: %w", table, err)
		}
		total += n
		if n < int64(batchSize) {
			return total, nil
		}
		if batchSleep > 0 {
			select {
			case <-ctx.Done():
				return total, ctx.Err()
			case <-time.After(batchSleep):
			}
		} else if err := ctx.Err(); err != nil {
			return total, err
		}
	}
	slog.Warn("ai retention sweep reached batch cap, remaining rows deferred to next sweep",
		"table", table, "deleted", total, "max_batches", maxBatches)
	return total, nil
}

// Run 周期调度（直到 ctx 取消）；每轮结束记录日志，失败记错误不静默。
func (c *AIRetentionCleaner) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultAIRetentionInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	slog.Info("ai retention cleaner started", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("ai retention cleaner stopped")
			return
		case <-t.C:
			result, err := c.SweepOnce(ctx)
			if err != nil {
				slog.Error("ai retention sweep failed", "error", err)
			}
			if result.total() > 0 || result.AuditMismatches > 0 {
				slog.Info("ai retention cleaned",
					"sessions", result.SessionsDeleted, "tool_calls", result.ToolCallsDeleted,
					"drafts", result.DraftsDeleted, "usage", result.UsageDeleted,
					"audit_mismatches", result.AuditMismatches)
			}
		}
	}
}
