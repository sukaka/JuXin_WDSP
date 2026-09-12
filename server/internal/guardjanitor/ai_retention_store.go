// ai_retention_store.go AI 留存清理的 PostgreSQL 实现。
// 引用保护全部下推到 SQL（NOT EXISTS 子查询），与删除同事务语义，避免先查后删的竞态。
package guardjanitor

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// aiRetentionSQLStore 是 AIRetentionStore 的 PostgreSQL 实现。
type aiRetentionSQLStore struct {
	db *pgxpool.Pool
}

var _ AIRetentionStore = (*aiRetentionSQLStore)(nil)

func newAIRetentionSQLStore(db *pgxpool.Pool) *aiRetentionSQLStore {
	return &aiRetentionSQLStore{db: db}
}

// 会话清理：长期未更新（updated_at 早于 cutoff）且未被 AI 审计引用。
// 引用保护两条路径：审计直接引用 session_id；或会话下任一 task 被审计 task_id 引用
// （删会话会级联删任务，故任务级引用也必须保护会话）。
func (s *aiRetentionSQLStore) DeleteSessionsBatch(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	res, err := s.db.Exec(ctx, `
DELETE FROM ai_sessions WHERE id IN (
  SELECT s.id FROM ai_sessions s
  WHERE s.updated_at < $1
    AND NOT EXISTS (SELECT 1 FROM ai_audit_records a WHERE a.session_id = s.id)
    AND NOT EXISTS (
      SELECT 1 FROM ai_tasks t JOIN ai_audit_records a ON a.task_id = t.id
      WHERE t.session_id = s.id)
  ORDER BY s.updated_at ASC LIMIT $2
)`, cutoff, limit)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}

// Tool 调用清理：created_at 早于 cutoff 且所属任务未被 AI 审计 task_id 引用。
func (s *aiRetentionSQLStore) DeleteToolCallsBatch(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	res, err := s.db.Exec(ctx, `
DELETE FROM ai_tool_calls WHERE id IN (
  SELECT c.id FROM ai_tool_calls c
  WHERE c.created_at < $1
    AND NOT EXISTS (SELECT 1 FROM ai_audit_records a WHERE a.task_id = c.task_id)
  ORDER BY c.created_at ASC LIMIT $2
)`, cutoff, limit)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}

// 草稿清理：仅清理 DRAFT/REJECTED/EXPIRED 状态的超期草稿；
// 已采纳（ACCEPTED）与待审核（PENDING_REVIEW）保留，被审计 draft_reference 引用的保留。
func (s *aiRetentionSQLStore) DeleteDraftsBatch(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	res, err := s.db.Exec(ctx, `
DELETE FROM ai_recommendations WHERE id IN (
  SELECT r.id FROM ai_recommendations r
  WHERE r.created_at < $1
    AND r.status IN ('DRAFT', 'REJECTED', 'EXPIRED')
    AND NOT EXISTS (SELECT 1 FROM ai_audit_records a WHERE a.draft_reference = r.id::text)
  ORDER BY r.created_at ASC LIMIT $2
)`, cutoff, limit)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}

// 用量清理：无其他记录引用用量表，按 created_at 超期直接分批删除。
func (s *aiRetentionSQLStore) DeleteUsageBatch(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	res, err := s.db.Exec(ctx, `
DELETE FROM ai_usage_records WHERE id IN (
  SELECT id FROM ai_usage_records WHERE created_at < $1
  ORDER BY created_at ASC LIMIT $2
)`, cutoff, limit)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}
