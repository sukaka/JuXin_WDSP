// Package aimemory AI 记忆管理：会话/项目/长期记忆，置信度分级，敏感信息拦截。
package aimemory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 记忆作用域。
const (
	ScopeSession  = "SESSION"
	ScopeProject  = "PROJECT"
	ScopeLongTerm = "LONG_TERM"
)

// 置信度。
const (
	ConfidenceUserConfirmed   = "USER_CONFIRMED"
	ConfidenceSystemConfirmed = "SYSTEM_CONFIRMED"
	ConfidenceAIInferred      = "AI_INFERRED"
)

// Memory 记忆条目。
type Memory struct {
	ID              uuid.UUID  `json:"id"`
	UserID          uuid.UUID  `json:"user_id"`
	MemoryScope     string     `json:"memory_scope"`
	ScopeReference  string     `json:"scope_reference"`
	Content         string     `json:"content"`
	ConfidenceType  string     `json:"confidence_type"`
	SourceType      string     `json:"source_type"`
	SourceReference string     `json:"source_reference"`
	Status          string     `json:"status"`
	LastUsedAt      *time.Time `json:"last_used_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// ErrNotFound 记忆不存在。
var ErrNotFound = errors.New("memory not found")

// ErrSensitiveContent 敏感内容禁止写入长期记忆。
var ErrSensitiveContent = errors.New("sensitive content not allowed in long-term memory")

// 敏感内容模式（密码/Token/私钥/完整载荷特征；匹配前内容已转小写，模式必须全小写）。
var sensitivePatterns = []string{
	"password", "passwd", "api_key", "apikey", "secret_key", "private_key",
	"begin rsa", "begin private", "begin ec", "eyjhbgcioi",
}

// ContainsSensitive 检查内容是否含敏感信息。
func ContainsSensitive(content string) bool {
	lower := strings.ToLower(content)
	for _, p := range sensitivePatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	// 长随机串（疑似凭据）
	for _, f := range strings.Fields(content) {
		if len(f) >= 40 && !strings.Contains(f, " ") && strings.IndexFunc(f, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '+' || r == '/' || r == '=')
		}) == -1 {
			return true
		}
	}
	return false
}

// Store 记忆仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建记忆仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// Create 创建记忆（AI_INFERRED 默认不得写入长期记忆，须用户确认）。
func (s *Store) Create(ctx context.Context, m *Memory) error {
	if m.Content == "" || len(m.Content) > 4000 {
		return fmt.Errorf("content required (<=4000 chars)")
	}
	if m.MemoryScope == ScopeLongTerm {
		if m.ConfidenceType == ConfidenceAIInferred {
			return fmt.Errorf("%w: AI 推测须用户确认后才能进入长期记忆", ErrSensitiveContent)
		}
		if ContainsSensitive(m.Content) {
			return ErrSensitiveContent
		}
	}
	m.ID = uuid.New()
	_, err := s.db.Exec(ctx, `
INSERT INTO ai_memories (id, user_id, memory_scope, scope_reference, content, confidence_type, source_type, source_reference)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		m.ID, m.UserID, m.MemoryScope, m.ScopeReference, m.Content, m.ConfidenceType, m.SourceType, m.SourceReference)
	return err
}

// List 按用户/作用域查询。
func (s *Store) List(ctx context.Context, userID uuid.UUID, scope string, includeDisabled bool) ([]Memory, error) {
	where := "user_id = $1"
	args := []interface{}{userID}
	if scope != "" {
		where += " AND memory_scope = $2"
		args = append(args, scope)
	}
	if !includeDisabled {
		where += " AND status = 'ACTIVE'"
	}
	rows, err := s.db.Query(ctx, `
SELECT id, user_id, memory_scope, scope_reference, content, confidence_type, source_type, source_reference, status, last_used_at, created_at, updated_at
FROM ai_memories WHERE `+where+` ORDER BY updated_at DESC LIMIT 100`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Memory
	for rows.Next() {
		var m Memory
		if err := rows.Scan(&m.ID, &m.UserID, &m.MemoryScope, &m.ScopeReference, &m.Content,
			&m.ConfidenceType, &m.SourceType, &m.SourceReference, &m.Status, &m.LastUsedAt, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Update 修改记忆内容（仅本人，handler 校验归属）。
func (s *Store) Update(ctx context.Context, id uuid.UUID, content string) error {
	if ContainsSensitive(content) {
		return ErrSensitiveContent
	}
	tag, err := s.db.Exec(ctx, `UPDATE ai_memories SET content=$2, updated_at=now() WHERE id=$1`, id, content)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetStatus 启停记忆。
func (s *Store) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	if status != "ACTIVE" && status != "DISABLED" {
		return fmt.Errorf("invalid status")
	}
	tag, err := s.db.Exec(ctx, `UPDATE ai_memories SET status=$2, updated_at=now() WHERE id=$1`, id, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete 删除记忆。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM ai_memories WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetOwner 查询记忆归属用户。
func (s *Store) GetOwner(ctx context.Context, id uuid.UUID) (uuid.UUID, error) {
	var uid uuid.UUID
	err := s.db.QueryRow(ctx, `SELECT user_id FROM ai_memories WHERE id=$1`, id).Scan(&uid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrNotFound
		}
		return uuid.Nil, err
	}
	return uid, nil
}

// LoadForContext 加载会话上下文用记忆（长期 + 项目，仅 ACTIVE）。
func (s *Store) LoadForContext(ctx context.Context, userID uuid.UUID, projectScope string, limit int) ([]Memory, error) {
	if limit <= 0 || limit > 10 {
		limit = 5
	}
	rows, err := s.db.Query(ctx, `
SELECT id, user_id, memory_scope, scope_reference, content, confidence_type, source_type, source_reference, status, last_used_at, created_at, updated_at
FROM ai_memories
WHERE user_id = $1 AND status = 'ACTIVE' AND (memory_scope = 'LONG_TERM' OR (memory_scope = 'PROJECT' AND scope_reference = $2))
ORDER BY confidence_type, updated_at DESC LIMIT $3`, userID, projectScope, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Memory
	for rows.Next() {
		var m Memory
		if err := rows.Scan(&m.ID, &m.UserID, &m.MemoryScope, &m.ScopeReference, &m.Content,
			&m.ConfidenceType, &m.SourceType, &m.SourceReference, &m.Status, &m.LastUsedAt, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// TouchUsed 更新最近使用时间。
func (s *Store) TouchUsed(ctx context.Context, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.db.Exec(ctx, `UPDATE ai_memories SET last_used_at = now() WHERE id = ANY($1)`, ids)
	return err
}
