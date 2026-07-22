// Package apiruntime API 运行时主事件持久化。
package apiruntime

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
)

// Store 事件仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// SavePrimary 保存统一主事件。
func (s *Store) SavePrimary(ctx context.Context, ev *events.PrimaryEvent) error {
	if ev == nil {
		return nil
	}
	if ev.ID == "" {
		ev.ID = uuid.New().String()
	}
	raw, _ := json.Marshal(ev.Details)
	id, err := uuid.Parse(ev.ID)
	if err != nil {
		id = uuid.New()
		ev.ID = id.String()
	}
	_, err = s.db.Exec(ctx, `
INSERT INTO api_runtime_events (id, request_id, endpoint_key, risk_score, risk_level, final_action, details_json, occurred_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		id, ev.RequestID, ev.EndpointKey, ev.RiskScore, ev.RiskLevel, ev.FinalAction, raw, ev.OccurredAt)
	return err
}

// List 最近事件。
func (s *Store) List(ctx context.Context, page, pageSize int) ([]map[string]any, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_runtime_events`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `
SELECT id, request_id, endpoint_key, risk_score, risk_level, final_action, details_json, occurred_at
FROM api_runtime_events ORDER BY occurred_at DESC LIMIT $1 OFFSET $2`, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id uuid.UUID
		var reqID, ek, rl, fa string
		var score int
		var details []byte
		var at time.Time
		if err := rows.Scan(&id, &reqID, &ek, &score, &rl, &fa, &details, &at); err != nil {
			return nil, 0, err
		}
		var det []dsctx.DetectorMatch
		_ = json.Unmarshal(details, &det)
		out = append(out, map[string]any{
			"id": id, "request_id": reqID, "endpoint_key": ek,
			"risk_score": score, "risk_level": rl, "final_action": fa,
			"details": det, "occurred_at": at,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, total, rows.Err()
}
