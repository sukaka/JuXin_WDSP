// overrides_store.go Phase 4 定向采集规则 PostgreSQL 仓储（契约 §2）：
// 管理端列表/创建/删除（创建与删除在同一事务内 agents.config_version+1，驱动 Agent
// 重拉配置——契约 §2.3）；机器端 config 拉取未过期全量（§2.4）；保留清理删除
// expires_at 早于 30 天的规则（http sweeper 同周期顺带——契约 §2.3）。
package agents

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// overrideCols 规则行共用列序。
const overrideCols = `id, agent_id, match, capture_level, note, created_by, created_at, expires_at`

// scanOverride 按 overrideCols 列序扫描单行。
func scanOverride(row rowScanner) (*CaptureOverride, error) {
	var o CaptureOverride
	if err := row.Scan(&o.ID, &o.AgentID, &o.Match, &o.CaptureLevel, &o.Note,
		&o.CreatedBy, &o.CreatedAt, &o.ExpiresAt); err != nil {
		return nil, err
	}
	return &o, nil
}

// ListCaptureOverrides 管理端规则列表（含已过期——管理端标注 inactive；created_at 倒序）。
func (s *Store) ListCaptureOverrides(ctx context.Context, agentID uuid.UUID) ([]CaptureOverride, error) {
	rows, err := s.db.Query(ctx, `
SELECT `+overrideCols+`
FROM agent_capture_overrides WHERE agent_id=$1 ORDER BY created_at DESC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CaptureOverride{}
	for rows.Next() {
		o, err := scanOverride(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *o)
	}
	return out, rows.Err()
}

// CreateCaptureOverride 创建规则并同事务 config_version+1（契约 §2.3；
// Agent 不存在 → ErrAgentNotFound）。
func (s *Store) CreateCaptureOverride(ctx context.Context, in CaptureOverrideInput) (*CaptureOverride, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id=$1)`, in.AgentID).
		Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrAgentNotFound
	}
	row := tx.QueryRow(ctx, `
INSERT INTO agent_capture_overrides (agent_id, match, capture_level, note, created_by, created_at, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7)
RETURNING `+overrideCols,
		in.AgentID, in.Match, in.CaptureLevel, in.Note, in.CreatedBy, in.Now.UTC(), in.ExpiresAt.UTC())
	o, err := scanOverride(row)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
UPDATE agents SET config_version=config_version+1, updated_at=now() WHERE agent_id=$1`, in.AgentID); err != nil {
		return nil, err
	}
	return o, tx.Commit(ctx)
}

// DeleteCaptureOverride 删除规则并同事务 config_version+1（契约 §2.3）。
// 返回被删除行供审计 before；规则不存在或不属于该 Agent → ErrCaptureOverrideNotFound
// （404 口径一致，防越权探测）。
func (s *Store) DeleteCaptureOverride(ctx context.Context, agentID, overrideID uuid.UUID, now time.Time) (*CaptureOverride, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row := tx.QueryRow(ctx, `
DELETE FROM agent_capture_overrides WHERE id=$1 AND agent_id=$2
RETURNING `+overrideCols, overrideID, agentID)
	o, err := scanOverride(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrCaptureOverrideNotFound
	}
	if err != nil {
		return nil, err
	}
	res, err := tx.Exec(ctx, `
UPDATE agents SET config_version=config_version+1, updated_at=$2 WHERE agent_id=$1`, agentID, now.UTC())
	if err != nil {
		return nil, err
	}
	if res.RowsAffected() == 0 {
		return nil, ErrAgentNotFound
	}
	return o, tx.Commit(ctx)
}

// ActiveCaptureOverrides 机器端 config 下发：未过期规则全量（expires_at > now；
// 过期规则 Agent 即时忽略且服务端不主动删除——契约 §2.3/§2.4）。
func (s *Store) ActiveCaptureOverrides(ctx context.Context, agentID uuid.UUID, now time.Time) ([]CaptureOverride, error) {
	rows, err := s.db.Query(ctx, `
SELECT `+overrideCols+`
FROM agent_capture_overrides WHERE agent_id=$1 AND expires_at > $2
ORDER BY created_at`, agentID, now.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CaptureOverride{}
	for rows.Next() {
		o, err := scanOverride(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *o)
	}
	return out, rows.Err()
}

// DeleteExpiredCaptureOverrides 保留清理：删除 expires_at 早于 before 的规则
// （契约 §2.3：过期规则保留 30 天后由 http sweeper 同周期顺带清理）。
func (s *Store) DeleteExpiredCaptureOverrides(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.Exec(ctx, `DELETE FROM agent_capture_overrides WHERE expires_at < $1`, before.UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}
