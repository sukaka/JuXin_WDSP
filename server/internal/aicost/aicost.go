// Package aicost AI 用量与配额控制（服务端强制，前端计数不可信）。
package aicost

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrQuotaExceeded 配额超限。
var ErrQuotaExceeded = errors.New("ai quota exceeded")

// Quotas 配额配置。
type Quotas struct {
	UserDailyTokens    int      // 用户每日 Token（默认 200000）
	RoleDailyTokens    int      // 角色每日 Token（默认 500000）
	PerRequestTokens   int      // 单次输入 Token（默认 12000）
	MaxToolCalls       int      // 单次任务 Tool 调用（默认 20）
	ConcurrentTasks    int      // 并发任务（默认 10）
	HighCostTaskDaily  int      // 高成本任务每日次数（默认 20；≤0 不限制）
	HighCostTaskTokens int      // 单任务 Token（输入+输出估算）达到该值即视为高成本任务（默认 20000；≤0 关闭该口径）
	HighCostTaskTypes  []string // 高成本任务类型名单（默认重分析/多 Agent 类；空表示关闭该口径）
}

// DefaultHighCostTaskTypes 默认高成本任务类型名单（多 Agent 重分析/模拟/报告类；
// 取值为 aiorchestrator.TaskType 的字符串口径，aicost 不反向依赖编排包）。
func DefaultHighCostTaskTypes() []string {
	return []string{
		"FALSE_POSITIVE_ANALYSIS", "ATTACK_PROFILE", "ATTACK_CHAIN",
		"ROOT_CAUSE_ANALYSIS", "POLICY_RECOMMENDATION", "WHAT_IF_ANALYSIS", "REPORT_SUMMARY",
	}
}

// DefaultQuotas 默认配额。
func DefaultQuotas() Quotas {
	return Quotas{
		UserDailyTokens: 200000, RoleDailyTokens: 500000, PerRequestTokens: 12000,
		MaxToolCalls: 20, ConcurrentTasks: 10, HighCostTaskDaily: 20,
		HighCostTaskTokens: 20000, HighCostTaskTypes: DefaultHighCostTaskTypes(),
	}
}

// Recorder 用量记录与配额检查。
type Recorder struct {
	db     *pgxpool.Pool
	quotas Quotas
}

// NewRecorder 创建用量记录器。
func NewRecorder(db *pgxpool.Pool, q Quotas) *Recorder {
	return &Recorder{db: db, quotas: q}
}

// RecordUsage 记录一次用量（实现 aiorchestrator.CostRecorder）。
func (r *Recorder) RecordUsage(ctx context.Context, userID uuid.UUID, sessionID, taskID *uuid.UUID, modelID *uuid.UUID, inTok, outTok, toolCalls int, cost float64) error {
	_, err := r.db.Exec(ctx, `
INSERT INTO ai_usage_records (user_id, session_id, task_id, model_id, input_tokens, output_tokens, tool_calls, estimated_cost)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		userID, sessionID, taskID, modelID, inTok, outTok, toolCalls, cost)
	return err
}

// runningTaskWindow 并发任务统计窗口：进程崩溃遗留的 RUNNING 行只在该窗口内计入，
// 窗口后自动解除，避免僵尸任务永久锁死配额（正常任务由编排层 defer Finish 终结，远小于该窗口）。
const runningTaskWindow = 30 * time.Minute

// CheckQuota 配额检查（用户/角色每日 Token、单次输入、并发任务）。
// 安全纪律：本检查是本地 LLM 成本的唯一服务端闸门，任何用量查询失败一律返回错误
// （fail-closed，调用方按 5xx 处理），不得在 DB 抖动时按 0 用量静默放行。
func (r *Recorder) CheckQuota(ctx context.Context, userID uuid.UUID, roleCode string, estimatedInput int) error {
	if estimatedInput > r.quotas.PerRequestTokens {
		return fmt.Errorf("%w: single request tokens %d > limit %d", ErrQuotaExceeded, estimatedInput, r.quotas.PerRequestTokens)
	}
	if r.db == nil {
		return errors.New("aicost: 配额存储未装配，无法核实配额")
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	var userTok int64
	if err := r.db.QueryRow(ctx, `
SELECT COALESCE(SUM(input_tokens + output_tokens), 0) FROM ai_usage_records
WHERE user_id = $1 AND created_at >= $2`, userID, today).Scan(&userTok); err != nil {
		return fmt.Errorf("aicost: 查询用户当日用量失败: %w", err)
	}
	if userTok+int64(estimatedInput) > int64(r.quotas.UserDailyTokens) {
		return fmt.Errorf("%w: user daily token quota", ErrQuotaExceeded)
	}
	var roleTok int64
	if err := r.db.QueryRow(ctx, `
SELECT COALESCE(SUM(u.input_tokens + u.output_tokens), 0) FROM ai_usage_records u
JOIN users usr ON usr.id = u.user_id
JOIN user_roles ur ON ur.user_id = usr.id
JOIN roles ro ON ro.id = ur.role_id
WHERE ro.code = $1 AND u.created_at >= $2`, roleCode, today).Scan(&roleTok); err != nil {
		return fmt.Errorf("aicost: 查询角色当日用量失败: %w", err)
	}
	if roleTok+int64(estimatedInput) > int64(r.quotas.RoleDailyTokens) {
		return fmt.Errorf("%w: role daily token quota", ErrQuotaExceeded)
	}
	// 并发任务上限：统计窗口内在跑（RUNNING）任务数。检查先于任务登记（任务行在编排层
	// 创建），并发突发可瞬时超出，属软上限；稳态滥用被拦截。
	if r.quotas.ConcurrentTasks > 0 {
		var running int64
		if err := r.db.QueryRow(ctx, `
SELECT count(*) FROM ai_tasks WHERE status = 'RUNNING' AND started_at >= $1`,
			time.Now().UTC().Add(-runningTaskWindow)).Scan(&running); err != nil {
			return fmt.Errorf("aicost: 查询在跑任务数失败: %w", err)
		}
		if running >= int64(r.quotas.ConcurrentTasks) {
			return fmt.Errorf("%w: concurrent task quota", ErrQuotaExceeded)
		}
	}
	return nil
}

// IsHighCostTask 判定一次任务是否高成本：任务类型命中名单，或 Token（输入+输出估算）达到阈值。
// 两处口径均为 Quotas 配置，判定依据见 DefaultHighCostTaskTypes 与 HighCostTaskTokens。
func (r *Recorder) IsHighCostTask(taskType string, estimatedTokens int) bool {
	for _, t := range r.quotas.HighCostTaskTypes {
		if t == taskType {
			return true
		}
	}
	return r.quotas.HighCostTaskTokens > 0 && estimatedTokens >= r.quotas.HighCostTaskTokens
}

// CheckHighCostQuota 高成本任务日配额检查（按用户统计当日已执行的高成本任务数，达到上限拒绝）。
// 计数来源为 ai_audit_records 中 action=chat/analyze 且命中高成本口径的记录：
// ai_tasks 随一次性分析会话级联删除，审计记录持久保留且口径与 IsHighCostTask 一致。
// 只统计已完成执行的任务，在跑任务不计入（软上限，与并发任务口径一致）。
// 安全纪律同 CheckQuota：任何查询失败一律返回错误（fail-closed），不得按 0 次静默放行。
func (r *Recorder) CheckHighCostQuota(ctx context.Context, userID uuid.UUID) error {
	if r.quotas.HighCostTaskDaily <= 0 {
		return nil
	}
	if r.db == nil {
		return errors.New("aicost: 配额存储未装配，无法核实高成本任务配额")
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	// 类型口径关闭时空数组使 ANY 恒假；Token 口径关闭时用极大阈值使比较恒假
	types := r.quotas.HighCostTaskTypes
	if types == nil {
		types = []string{}
	}
	tokenThreshold := r.quotas.HighCostTaskTokens
	if tokenThreshold <= 0 {
		tokenThreshold = int(^uint(0) >> 1)
	}
	var count int64
	if err := r.db.QueryRow(ctx, `
SELECT count(*) FROM ai_audit_records
WHERE user_id = $1 AND occurred_at >= $2 AND action IN ('chat','analyze')
  AND (task_type = ANY($3) OR (input_tokens + output_tokens) >= $4)`,
		userID, today, types, tokenThreshold).Scan(&count); err != nil {
		return fmt.Errorf("aicost: 查询当日高成本任务数失败: %w", err)
	}
	if count >= int64(r.quotas.HighCostTaskDaily) {
		return fmt.Errorf("%w: high cost task daily quota %d/%d", ErrQuotaExceeded, count, r.quotas.HighCostTaskDaily)
	}
	return nil
}

// Usage 用量统计。
type Usage struct {
	TodayInputTokens  int64   `json:"today_input_tokens"`
	TodayOutputTokens int64   `json:"today_output_tokens"`
	TodayModelCalls   int64   `json:"today_model_calls"`
	TodayToolCalls    int64   `json:"today_tool_calls"`
	TodayCost         float64 `json:"today_cost"`
}

// Overview 今日用量总览。
func (r *Recorder) Overview(ctx context.Context) (*Usage, error) {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	var u Usage
	err := r.db.QueryRow(ctx, `
SELECT COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0), count(*),
  COALESCE(SUM(tool_calls),0), COALESCE(SUM(estimated_cost),0)
FROM ai_usage_records WHERE created_at >= $1`, today).
		Scan(&u.TodayInputTokens, &u.TodayOutputTokens, &u.TodayModelCalls, &u.TodayToolCalls, &u.TodayCost)
	return &u, err
}

// ByUser 按用户统计（近 7 天）。
func (r *Recorder) ByUser(ctx context.Context) ([]map[string]interface{}, error) {
	start := time.Now().Add(-7 * 24 * time.Hour).UTC()
	rows, err := r.db.Query(ctx, `
SELECT u.username, COALESCE(SUM(r.input_tokens),0), COALESCE(SUM(r.output_tokens),0),
  count(*), COALESCE(SUM(r.estimated_cost),0)
FROM ai_usage_records r JOIN users u ON u.id = r.user_id
WHERE r.created_at >= $1
GROUP BY u.username ORDER BY 5 DESC LIMIT 20`, start)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var name string
		var inTok, outTok, calls int64
		var cost float64
		if err := rows.Scan(&name, &inTok, &outTok, &calls, &cost); err != nil {
			return nil, err
		}
		out = append(out, map[string]interface{}{
			"username": name, "input_tokens": inTok, "output_tokens": outTok,
			"model_calls": calls, "cost": cost,
		})
	}
	return out, rows.Err()
}

// ByAgent 按 Agent 统计（近 7 天，来自 ai_agent_runs）。
func (r *Recorder) ByAgent(ctx context.Context) ([]map[string]interface{}, error) {
	start := time.Now().Add(-7 * 24 * time.Hour).UTC()
	rows, err := r.db.Query(ctx, `
SELECT COALESCE(a.code, ar.agent_id::text), count(*),
  COALESCE(SUM(ar.input_tokens),0), COALESCE(SUM(ar.output_tokens),0),
  count(*) FILTER (WHERE ar.status='FAILED')
FROM ai_agent_runs ar
LEFT JOIN ai_agents a ON a.id = ar.agent_id
WHERE ar.created_at >= $1
GROUP BY 1 ORDER BY 2 DESC LIMIT 30`, start)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var code string
		var calls, inTok, outTok, fails int64
		if err := rows.Scan(&code, &calls, &inTok, &outTok, &fails); err != nil {
			return nil, err
		}
		out = append(out, map[string]interface{}{
			"agent": code, "runs": calls, "input_tokens": inTok, "output_tokens": outTok, "failures": fails,
		})
	}
	return out, rows.Err()
}

// ByTask 按任务类型统计（近 7 天）。
func (r *Recorder) ByTask(ctx context.Context) ([]map[string]interface{}, error) {
	start := time.Now().Add(-7 * 24 * time.Hour).UTC()
	rows, err := r.db.Query(ctx, `
SELECT t.task_type, count(*),
  COALESCE(SUM(u.input_tokens),0), COALESCE(SUM(u.output_tokens),0), COALESCE(SUM(u.estimated_cost),0)
FROM ai_tasks t
LEFT JOIN ai_usage_records u ON u.task_id = t.id
WHERE t.created_at >= $1
GROUP BY t.task_type ORDER BY 2 DESC LIMIT 30`, start)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var tt string
		var calls, inTok, outTok int64
		var cost float64
		if err := rows.Scan(&tt, &calls, &inTok, &outTok, &cost); err != nil {
			return nil, err
		}
		out = append(out, map[string]interface{}{
			"task_type": tt, "tasks": calls, "input_tokens": inTok, "output_tokens": outTok, "cost": cost,
		})
	}
	return out, rows.Err()
}
