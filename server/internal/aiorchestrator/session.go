// session.go AI 会话与消息持久化、上下文统计与自动压缩。
package aiorchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrSessionNotFound 会话不存在。
var ErrSessionNotFound = errors.New("ai session not found")

// SessionStore 会话存储。
type SessionStore struct {
	db         *pgxpool.Pool
	thresholds CompressionThresholds
}

// NewSessionStore 创建会话存储。
func NewSessionStore(db *pgxpool.Pool) *SessionStore {
	return &SessionStore{db: db, thresholds: DefaultThresholds()}
}

// Create 创建会话。
func (s *SessionStore) Create(ctx context.Context, userID uuid.UUID, title string) (*Session, error) {
	if title == "" {
		title = "新会话"
	}
	sess := &Session{ID: uuid.New(), UserID: userID, Title: title, Status: "ACTIVE"}
	_, err := s.db.Exec(ctx, `
INSERT INTO ai_sessions (id, user_id, title, status) VALUES ($1,$2,$3,$4)`,
		sess.ID, userID, title, sess.Status)
	return sess, err
}

// Get 读取会话（校验归属由调用方处理）。
func (s *SessionStore) Get(ctx context.Context, id uuid.UUID) (*Session, error) {
	var sess Session
	err := s.db.QueryRow(ctx, `
SELECT id, user_id, title, status, COALESCE(context_summary,''), context_token_count
FROM ai_sessions WHERE id = $1`, id).Scan(
		&sess.ID, &sess.UserID, &sess.Title, &sess.Status, &sess.ContextSummary, &sess.ContextTokenCount)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}
	return &sess, nil
}

// List 按用户列出会话。
func (s *SessionStore) List(ctx context.Context, userID uuid.UUID, includeArchived bool, page, pageSize int) ([]Session, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	where := "user_id = $1"
	if !includeArchived {
		where += " AND status = 'ACTIVE'"
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM ai_sessions WHERE `+where, userID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `
SELECT id, user_id, title, status, COALESCE(context_summary,''), context_token_count
FROM ai_sessions WHERE `+where+` ORDER BY updated_at DESC LIMIT $2 OFFSET $3`,
		userID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var sess Session
		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.Title, &sess.Status, &sess.ContextSummary, &sess.ContextTokenCount); err != nil {
			return nil, 0, err
		}
		out = append(out, sess)
	}
	return out, total, rows.Err()
}

// Rename 重命名。
func (s *SessionStore) Rename(ctx context.Context, id uuid.UUID, title string) error {
	title = truncateRunes(title, 200)
	_, err := s.db.Exec(ctx, `UPDATE ai_sessions SET title=$2, updated_at=now() WHERE id=$1`, id, title)
	return err
}

// Archive 归档会话。
func (s *SessionStore) Archive(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.Exec(ctx, `UPDATE ai_sessions SET status='ARCHIVED', archived_at=now(), updated_at=now() WHERE id=$1`, id)
	return err
}

// Delete 删除会话（含消息/任务级联）。
func (s *SessionStore) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.Exec(ctx, `DELETE FROM ai_sessions WHERE id=$1`, id)
	return err
}

// Touch 更新活动时间与 Token 计数。
func (s *SessionStore) Touch(ctx context.Context, id uuid.UUID, tokenCount int) error {
	_, err := s.db.Exec(ctx, `UPDATE ai_sessions SET updated_at=now(), context_token_count=$2 WHERE id=$1`, id, tokenCount)
	return err
}

// AppendMessage 追加消息，返回消息 ID。
func (s *SessionStore) AppendMessage(ctx context.Context, sessionID uuid.UUID, role, content string, modelID, promptVersionID *uuid.UUID, inTok, outTok int, finishReason string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.db.Exec(ctx, `
INSERT INTO ai_messages (id, session_id, role, content, model_id, prompt_version_id, input_tokens, output_tokens, finish_reason)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		id, sessionID, role, content, modelID, promptVersionID, inTok, outTok, finishReason)
	if err != nil {
		return uuid.Nil, err
	}
	// 更新会话 token 计数
	if _, err := s.db.Exec(ctx, `
UPDATE ai_sessions SET updated_at=now(), context_token_count = context_token_count + $2 WHERE id=$1`,
		sessionID, inTok+outTok); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// RecentMessages 最近 N 条消息（正序）。
func (s *SessionStore) RecentMessages(ctx context.Context, sessionID uuid.UUID, limit int) ([]Message, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	rows, err := s.db.Query(ctx, `
SELECT id, role, content, created_at FROM ai_messages
WHERE session_id = $1 ORDER BY created_at DESC LIMIT $2`, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.Role, &m.Content, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	// 反转为正序
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, rows.Err()
}

// MessageCount 会话消息数。
func (s *SessionStore) MessageCount(ctx context.Context, sessionID uuid.UUID) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM ai_messages WHERE session_id=$1`, sessionID).Scan(&n)
	return n, err
}

// MaybeCompress 超阈值时执行压缩（记录审计），返回是否压缩。
func (s *SessionStore) MaybeCompress(ctx context.Context, sessionID uuid.UUID, contextWindow int) (bool, error) {
	sess, err := s.Get(ctx, sessionID)
	if err != nil {
		return false, err
	}
	budget := CheckBudget(sess.ContextTokenCount, contextWindow, s.thresholds)
	if !budget.NeedCompress {
		return false, nil
	}
	msgs, err := s.RecentMessages(ctx, sessionID, 100)
	if err != nil {
		return false, err
	}
	var cms []ContextMessage
	for _, m := range msgs {
		cms = append(cms, ContextMessage{Role: m.Role, Content: m.Content})
	}
	res := Compress(cms, 8, 1500)
	if res.DroppedMessages == 0 {
		return false, nil
	}
	// 写入摘要与压缩记录
	summary := res.Summary
	if sess.ContextSummary != "" {
		summary = sess.ContextSummary + "\n" + res.Summary
	}
	refs, _ := json.Marshal(res.PreservedRefs)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
UPDATE ai_sessions SET context_summary=$2, context_token_count=$3, updated_at=now() WHERE id=$1`,
		sessionID, truncateRunes(summary, 8000), res.AfterTokens); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO ai_context_compressions (session_id, before_tokens, after_tokens, summary, preserved_references, compression_reason)
VALUES ($1,$2,$3,$4,$5,$6)`,
		sessionID, res.BeforeTokens, res.AfterTokens, truncateRunes(res.Summary, 2000), refs,
		fmt.Sprintf("usage %.2f >= threshold %.2f", budget.Usage, s.thresholds.Compress)); err != nil {
		return false, err
	}
	// 删除已摘要的旧消息（保留最近 8 条）
	keep := res.RetainedMessages
	if keep > 0 {
		if _, err := tx.Exec(ctx, `
DELETE FROM ai_messages WHERE session_id=$1 AND id NOT IN (
  SELECT id FROM ai_messages WHERE session_id=$1 ORDER BY created_at DESC LIMIT $2)`, sessionID, keep); err != nil {
			return false, err
		}
	}
	return true, tx.Commit(ctx)
}

// AddFeedback 添加反馈。
func (s *SessionStore) AddFeedback(ctx context.Context, sessionID, messageID, userID uuid.UUID, rating int, feedbackType, comment string) error {
	if rating != 1 && rating != -1 {
		return fmt.Errorf("invalid rating")
	}
	_, err := s.db.Exec(ctx, `
INSERT INTO ai_feedback (session_id, message_id, user_id, rating, feedback_type, comment)
VALUES ($1,$2,$3,$4,$5,$6)`,
		sessionID, messageID, userID, rating, truncateRunes(feedbackType, 30), truncateRunes(comment, 500))
	return err
}

// GetMessage 读取单条消息（归属校验用）。
func (s *SessionStore) GetMessage(ctx context.Context, messageID uuid.UUID) (*Message, *uuid.UUID, error) {
	var m Message
	var sessID uuid.UUID
	err := s.db.QueryRow(ctx, `SELECT id, session_id, role, content, created_at FROM ai_messages WHERE id=$1`, messageID).
		Scan(&m.ID, &sessID, &m.Role, &m.Content, &m.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrSessionNotFound
		}
		return nil, nil, err
	}
	return &m, &sessID, nil
}
