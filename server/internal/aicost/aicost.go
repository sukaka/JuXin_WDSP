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
	UserDailyTokens   int // 用户每日 Token（默认 200000）
	RoleDailyTokens   int // 角色每日 Token（默认 500000）
	PerRequestTokens  int // 单次输入 Token（默认 12000）
	MaxToolCalls      int // 单次任务 Tool 调用（默认 20）
	ConcurrentTasks   int // 并发任务（默认 10）
	HighCostTaskDaily int // 高成本任务每日次数（默认 20）
}

// DefaultQuotas 默认配额。
func DefaultQuotas() Quotas {
	return Quotas{
		UserDailyTokens: 200000, RoleDailyTokens: 500000, PerRequestTokens: 12000,
		MaxToolCalls: 20, ConcurrentTasks: 10, HighCostTaskDaily: 20,
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

// CheckQuota 配额检查（用户/角色每日 Token、单次输入、并发）。
func (r *Recorder) CheckQuota(ctx context.Context, userID uuid.UUID, roleCode string, estimatedInput int) error {
	if estimatedInput > r.quotas.PerRequestTokens {
		return fmt.Errorf("%w: single request tokens %d > limit %d", ErrQuotaExceeded, estimatedInput, r.quotas.PerRequestTokens)
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	var userTok int64
	_ = r.db.QueryRow(ctx, `
SELECT COALESCE(SUM(input_tokens + output_tokens), 0) FROM ai_usage_records
WHERE user_id = $1 AND created_at >= $2`, userID, today).Scan(&userTok)
	if userTok+int64(estimatedInput) > int64(r.quotas.UserDailyTokens) {
		return fmt.Errorf("%w: user daily token quota", ErrQuotaExceeded)
	}
	var roleTok int64
	_ = r.db.QueryRow(ctx, `
SELECT COALESCE(SUM(u.input_tokens + u.output_tokens), 0) FROM ai_usage_records u
JOIN users usr ON usr.id = u.user_id
JOIN user_roles ur ON ur.user_id = usr.id
JOIN roles ro ON ro.id = ur.role_id
WHERE ro.code = $1 AND u.created_at >= $2`, roleCode, today).Scan(&roleTok)
	if roleTok+int64(estimatedInput) > int64(r.quotas.RoleDailyTokens) {
		return fmt.Errorf("%w: role daily token quota", ErrQuotaExceeded)
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
