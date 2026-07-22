// Package aiaudit AI 审计：独立审计链路（哈希链完整性），记录模型/Agent/Tool/草稿/确认操作。
// 不保存模型私有思维链与敏感信息（密钥/密码/私钥/完整载荷）。
package aiaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aitools"
)

// Record 审计记录。
type Record struct {
	OccurredAt     time.Time `json:"occurred_at"`
	UserID         *uuid.UUID `json:"user_id,omitempty"`
	Username       string     `json:"username"`
	RoleCodes      string     `json:"role_codes"`
	SessionID      *uuid.UUID `json:"session_id,omitempty"`
	TaskID         *uuid.UUID `json:"task_id,omitempty"`
	Action         string     `json:"action"`
	TaskType       string     `json:"task_type"`
	AgentCode      string     `json:"agent_code"`
	ToolCode       string     `json:"tool_code"`
	ModelCode      string     `json:"model_code"`
	PromptVersion  string     `json:"prompt_version"`
	InputTokens    int        `json:"input_tokens"`
	OutputTokens   int        `json:"output_tokens"`
	DurationMs     int        `json:"duration_ms"`
	EstimatedCost  float64    `json:"estimated_cost"`
	RequestSummary string     `json:"request_summary"`
	ResultSummary  string     `json:"result_summary"`
	DraftReference string     `json:"draft_reference"`
	ConfirmResult  string     `json:"confirm_result"`
}

// Service AI 审计服务。
type Service struct {
	db *pgxpool.Pool
}

// NewService 创建审计服务。
func NewService(db *pgxpool.Pool) *Service {
	return &Service{db: db}
}

// 敏感词脱敏（密钥/密码/私钥不进入审计正文；匹配前已转小写，关键词必须小写）。
var sensitiveKeys = []string{"api_key", "apikey", "password", "secret", "private_key", "begin", "token"}

func mask(s string, n int) string {
	lower := strings.ToLower(s)
	for _, k := range sensitiveKeys {
		if strings.Contains(lower, k) {
			// 粗粒度遮蔽：替换常见密文形态
			s = maskLongTokens(s)
			break
		}
	}
	if len(s) > n {
		// 按 rune 截断，避免截断多字节字符产生非法 UTF-8
		r := []rune(s)
		if len(r) > n {
			s = string(r[:n]) + "..."
		}
	}
	return s
}

func maskLongTokens(s string) string {
	fields := strings.Fields(s)
	for i, f := range fields {
		if len(f) >= 24 {
			fields[i] = f[:6] + "***"
		}
	}
	return strings.Join(fields, " ")
}

// computeHash 链上哈希。
func computeHash(occurredAt time.Time, username, action, objectID, previousHash string) string {
	h := sha256.New()
	h.Write([]byte(strings.Join([]string{occurredAt.UTC().Format(time.RFC3339Nano), username, action, objectID, previousHash}, "|")))
	return hex.EncodeToString(h.Sum(nil))
}

// Record 写入审计（哈希链，advisory lock 串行化）。
func (s *Service) Record(ctx context.Context, r Record) error {
	occurredAt := time.Now().UTC().Truncate(time.Microsecond)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(93847562)`); err != nil {
		return err
	}
	var prev string
	err = tx.QueryRow(ctx, `SELECT record_hash FROM ai_audit_records ORDER BY occurred_at DESC, id DESC LIMIT 1`).Scan(&prev)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			prev = ""
		} else {
			return err
		}
	}
	objectID := r.TaskID
	objStr := ""
	if objectID != nil {
		objStr = objectID.String()
	}
	hash := computeHash(occurredAt, r.Username, r.Action, objStr, prev)
	_, err = tx.Exec(ctx, `
INSERT INTO ai_audit_records (occurred_at, user_id, username, role_codes, session_id, task_id,
  action, task_type, agent_code, tool_code, model_code, prompt_version,
  input_tokens, output_tokens, duration_ms, estimated_cost,
  request_summary, result_summary, draft_reference, confirm_result, previous_hash, record_hash)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
		occurredAt, r.UserID, r.Username, r.RoleCodes, r.SessionID, r.TaskID,
		r.Action, r.TaskType, r.AgentCode, r.ToolCode, r.ModelCode, r.PromptVersion,
		r.InputTokens, r.OutputTokens, r.DurationMs, r.EstimatedCost,
		mask(r.RequestSummary, 500), mask(r.ResultSummary, 1000), r.DraftReference, r.ConfirmResult,
		prev, hash)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RecordToolCall 实现 aitools.Auditor 接口。
func (s *Service) RecordToolCall(ctx context.Context, rec aitools.AuditRecord) (string, error) {
	ref := "toolcall:" + rec.ToolCode + ":" + uuid.NewString()[:8]
	return ref, s.Record(ctx, Record{
		TaskID: &rec.TaskID, Action: "tool_call", ToolCode: rec.ToolCode,
		RequestSummary: rec.InputSummary, ResultSummary: "status=" + rec.Status + " err=" + rec.ErrorCode,
		DurationMs: rec.DurationMs,
	})
}

// VerifyChain 校验审计链完整性。
func (s *Service) VerifyChain(ctx context.Context, limit int) (int, error) {
	if limit <= 0 {
		limit = 10000
	}
	rows, err := s.db.Query(ctx, `
SELECT occurred_at, username, action, COALESCE(task_id::text,''), previous_hash, record_hash
FROM ai_audit_records ORDER BY occurred_at ASC, id ASC LIMIT $1`, limit)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	prev := ""
	mismatches := 0
	for rows.Next() {
		var at time.Time
		var u, a, obj, ph, rh string
		if err := rows.Scan(&at, &u, &a, &obj, &ph, &rh); err != nil {
			return 0, err
		}
		if ph != prev {
			mismatches++
		}
		if computeHash(at, u, a, obj, ph) != rh {
			mismatches++
		}
		prev = rh
	}
	return mismatches, rows.Err()
}

// ListFilter 审计查询过滤。
type ListFilter struct {
	UserID    *uuid.UUID
	SessionID *uuid.UUID
	Action    string
	TaskType  string
	Start     time.Time
	End       time.Time
	Page      int
	PageSize  int
}

// List 分页查询审计。
func (s *Service) List(ctx context.Context, f ListFilter) ([]Record, int64, error) {
	where := "1=1"
	args := []interface{}{}
	idx := 1
	if f.UserID != nil {
		where += fmt.Sprintf(" AND user_id = $%d", idx)
		args = append(args, *f.UserID)
		idx++
	}
	if f.SessionID != nil {
		where += fmt.Sprintf(" AND session_id = $%d", idx)
		args = append(args, *f.SessionID)
		idx++
	}
	if f.Action != "" {
		where += fmt.Sprintf(" AND action = $%d", idx)
		args = append(args, f.Action)
		idx++
	}
	if f.TaskType != "" {
		where += fmt.Sprintf(" AND task_type = $%d", idx)
		args = append(args, f.TaskType)
		idx++
	}
	if !f.Start.IsZero() {
		where += fmt.Sprintf(" AND occurred_at >= $%d", idx)
		args = append(args, f.Start)
		idx++
	}
	if !f.End.IsZero() {
		where += fmt.Sprintf(" AND occurred_at < $%d", idx)
		args = append(args, f.End)
		idx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM ai_audit_records WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	rows, err := s.db.Query(ctx, `
SELECT occurred_at, user_id, username, role_codes, session_id, task_id, action, task_type, agent_code, tool_code, model_code,
  input_tokens, output_tokens, duration_ms, estimated_cost, request_summary, result_summary, draft_reference
FROM ai_audit_records WHERE `+where+` ORDER BY occurred_at DESC LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		append(args, f.PageSize, (f.Page-1)*f.PageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		var uid, sid, tid *uuid.UUID
		if err := rows.Scan(&r.OccurredAt, &uid, &r.Username, &r.RoleCodes, &sid, &tid, &r.Action, &r.TaskType, &r.AgentCode, &r.ToolCode, &r.ModelCode,
			&r.InputTokens, &r.OutputTokens, &r.DurationMs, &r.EstimatedCost, &r.RequestSummary, &r.ResultSummary, &r.DraftReference); err != nil {
			return nil, 0, err
		}
		r.UserID = uid
		r.SessionID = sid
		r.TaskID = tid
		out = append(out, r)
	}
	return out, total, rows.Err()
}
