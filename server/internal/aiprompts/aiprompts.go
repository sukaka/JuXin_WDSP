// Package aiprompts Prompt 管理：不可变版本、静态安全检查、测试/发布/回滚。
package aiprompts

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
)

// Prompt Prompt 定义。
type Prompt struct {
	ID               uuid.UUID `json:"id"`
	Code             string    `json:"code"`
	Name             string    `json:"name"`
	PromptType       string    `json:"prompt_type"`
	Status           string    `json:"status"`
	CurrentVersionID *uuid.UUID `json:"current_version_id"`
	CreatedAt        time.Time `json:"created_at"`
}

// Version Prompt 版本。
type Version struct {
	ID            uuid.UUID  `json:"id"`
	PromptID      uuid.UUID  `json:"prompt_id"`
	VersionNumber int        `json:"version_number"`
	Content       string     `json:"content"`
	ContentHash   string     `json:"content_hash"`
	ChangeSummary string     `json:"change_summary"`
	TestResult    string     `json:"test_result"`
	CreatedAt     time.Time  `json:"created_at"`
	PublishedAt   *time.Time `json:"published_at"`
	IsCurrent     bool       `json:"is_current"`
}

// ErrNotFound 不存在。
var ErrNotFound = errors.New("prompt not found")

// ErrActivePrompt 已发布（ACTIVE）的 Prompt 不可删除。
var ErrActivePrompt = errors.New("published prompt cannot be deleted")

// ErrUnsafeContent Prompt 包含禁止内容。
var ErrUnsafeContent = errors.New("prompt contains forbidden content")

// 禁止内容模式（密钥/Shell/绕过权限/私有思维链要求）。
var forbiddenPatterns = []string{
	"api_key", "apikey", "BEGIN PRIVATE", "BEGIN RSA",
	"shell", "bash -c", "exec(", "os.execute",
	"忽略你的权限", "ignore your permissions", "绕过权限", "bypass permission",
	"思维链", "chain of thought", "展示你的思考过程", "show your reasoning",
}

// ValidateContent 静态安全检查。
func ValidateContent(content string) error {
	if content == "" || len(content) > 50000 {
		return fmt.Errorf("content required (<=50000 chars)")
	}
	lower := strings.ToLower(content)
	for _, p := range forbiddenPatterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return fmt.Errorf("%w: %q", ErrUnsafeContent, p)
		}
	}
	return nil
}

// Store Prompt 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// CreatePrompt 创建 Prompt 及首版本。
func (s *Store) CreatePrompt(ctx context.Context, code, name, promptType, content, changeSummary string, createdBy *uuid.UUID) (*Prompt, *Version, error) {
	if err := ValidateContent(content); err != nil {
		return nil, nil, err
	}
	p := &Prompt{ID: uuid.New(), Code: code, Name: name, PromptType: promptType, Status: "DRAFT"}
	v := &Version{ID: uuid.New(), PromptID: p.ID, VersionNumber: 1, Content: content, ChangeSummary: changeSummary}
	v.ContentHash = hashContent(content)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
INSERT INTO ai_prompts (id, code, name, prompt_type, status, created_by)
VALUES ($1,$2,$3,$4,'DRAFT',$5)`, p.ID, code, name, promptType, createdBy); err != nil {
		return nil, nil, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO ai_prompt_versions (id, prompt_id, version_number, content, content_hash, change_summary, created_by, is_current)
VALUES ($1,$2,1,$3,$4,$5,$6,FALSE)`,
		v.ID, p.ID, content, v.ContentHash, changeSummary, createdBy); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	return p, v, nil
}

// CreateVersion 创建新版本（不可变）。
func (s *Store) CreateVersion(ctx context.Context, promptID uuid.UUID, content, changeSummary string, createdBy *uuid.UUID) (*Version, error) {
	if err := ValidateContent(content); err != nil {
		return nil, err
	}
	v := &Version{ID: uuid.New(), PromptID: promptID, Content: content, ChangeSummary: changeSummary}
	v.ContentHash = hashContent(content)
	err := s.db.QueryRow(ctx, `
INSERT INTO ai_prompt_versions (id, prompt_id, version_number, content, content_hash, change_summary, created_by, is_current)
VALUES ($1, $2, (SELECT COALESCE(MAX(version_number),0)+1 FROM ai_prompt_versions WHERE prompt_id=$2), $3, $4, $5, $6, FALSE)
RETURNING version_number, created_at`,
		v.ID, promptID, content, v.ContentHash, changeSummary, createdBy).Scan(&v.VersionNumber, &v.CreatedAt)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// List 列出 Prompt。
func (s *Store) List(ctx context.Context, promptType, status string) ([]Prompt, error) {
	where := "1=1"
	args := []interface{}{}
	idx := 1
	if promptType != "" {
		where += fmt.Sprintf(" AND prompt_type = $%d", idx)
		args = append(args, promptType)
		idx++
	}
	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, status)
		idx++
	}
	rows, err := s.db.Query(ctx, `
SELECT id, code, name, prompt_type, status, current_version_id, created_at FROM ai_prompts WHERE `+where+` ORDER BY code`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Prompt
	for rows.Next() {
		var p Prompt
		if err := rows.Scan(&p.ID, &p.Code, &p.Name, &p.PromptType, &p.Status, &p.CurrentVersionID, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListVersions 列出版本。
func (s *Store) ListVersions(ctx context.Context, promptID uuid.UUID) ([]Version, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, prompt_id, version_number, content, content_hash, change_summary, test_result, created_at, published_at, is_current
FROM ai_prompt_versions WHERE prompt_id = $1 ORDER BY version_number DESC LIMIT 50`, promptID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		var v Version
		if err := rows.Scan(&v.ID, &v.PromptID, &v.VersionNumber, &v.Content, &v.ContentHash,
			&v.ChangeSummary, &v.TestResult, &v.CreatedAt, &v.PublishedAt, &v.IsCurrent); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Publish 发布版本（须先通过测试标记 PASSED）。
func (s *Store) Publish(ctx context.Context, promptID, versionID uuid.UUID, publishedBy *uuid.UUID) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var testResult string
	if err := tx.QueryRow(ctx, `SELECT test_result FROM ai_prompt_versions WHERE id=$1 AND prompt_id=$2`, versionID, promptID).Scan(&testResult); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if testResult != "PASSED" {
		return fmt.Errorf("version must pass regression test before publish (current: %q)", testResult)
	}
	if _, err := tx.Exec(ctx, `UPDATE ai_prompt_versions SET is_current = FALSE WHERE prompt_id = $1`, promptID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE ai_prompt_versions SET is_current = TRUE, published_by=$2, published_at=now() WHERE id=$1`, versionID, publishedBy); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE ai_prompts SET status='ACTIVE', current_version_id=$2, updated_by=$3, updated_at=now() WHERE id=$1`, promptID, versionID, publishedBy); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// MarkTestResult 标记版本测试结果（回归/对抗测试后）。
func (s *Store) MarkTestResult(ctx context.Context, versionID uuid.UUID, result string) error {
	if result != "PASSED" && result != "FAILED" {
		return fmt.Errorf("invalid test result")
	}
	_, err := s.db.Exec(ctx, `UPDATE ai_prompt_versions SET test_result=$2 WHERE id=$1`, versionID, result)
	return err
}

// GetVersion 查询单个版本（测试/发布前校验用）。
func (s *Store) GetVersion(ctx context.Context, versionID uuid.UUID) (*Version, error) {
	var v Version
	err := s.db.QueryRow(ctx, `
SELECT id, prompt_id, version_number, content, content_hash, change_summary, test_result, created_at, published_at, is_current
FROM ai_prompt_versions WHERE id = $1`, versionID).Scan(
		&v.ID, &v.PromptID, &v.VersionNumber, &v.Content, &v.ContentHash,
		&v.ChangeSummary, &v.TestResult, &v.CreatedAt, &v.PublishedAt, &v.IsCurrent)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &v, nil
}

// CurrentContent 读取当前发布版本内容。
func (s *Store) CurrentContent(ctx context.Context, code string) (string, error) {
	var content string
	err := s.db.QueryRow(ctx, `
SELECT v.content FROM ai_prompts p JOIN ai_prompt_versions v ON v.id = p.current_version_id WHERE p.code = $1`, code).Scan(&content)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return content, nil
}

// Rename 修改 Prompt 名称（编码不可变，仅名称可编辑）。
func (s *Store) Rename(ctx context.Context, id uuid.UUID, name string, updatedBy *uuid.UUID) (*Prompt, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return nil, fmt.Errorf("名称必填且不超过 100 字符")
	}
	var p Prompt
	err := s.db.QueryRow(ctx, `
UPDATE ai_prompts SET name=$2, updated_by=$3, updated_at=now() WHERE id=$1
RETURNING id, code, name, prompt_type, status, current_version_id, created_at`,
		id, name, updatedBy).Scan(&p.ID, &p.Code, &p.Name, &p.PromptType, &p.Status, &p.CurrentVersionID, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Delete 删除 Prompt 及其全部版本（事务）。
// 仅允许删除未发布（DRAFT）的 Prompt；已发布（ACTIVE）返回 ErrActivePrompt。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM ai_prompts WHERE id=$1 FOR UPDATE`, id).Scan(&status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if status == "ACTIVE" {
		return ErrActivePrompt
	}
	if _, err := tx.Exec(ctx, `DELETE FROM ai_prompt_versions WHERE prompt_id=$1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM ai_prompts WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Rollback 回滚到指定已发布版本。
func (s *Store) Rollback(ctx context.Context, promptID, versionID uuid.UUID, rolledBackBy *uuid.UUID) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var published bool
	if err := tx.QueryRow(ctx, `SELECT published_at IS NOT NULL FROM ai_prompt_versions WHERE id=$1 AND prompt_id=$2`, versionID, promptID).Scan(&published); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if !published {
		return fmt.Errorf("can only rollback to a previously published version")
	}
	if _, err := tx.Exec(ctx, `UPDATE ai_prompt_versions SET is_current = FALSE WHERE prompt_id = $1`, promptID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE ai_prompt_versions SET is_current = TRUE WHERE id=$1`, versionID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE ai_prompts SET status='ACTIVE', current_version_id=$2, updated_by=$3, updated_at=now() WHERE id=$1`, promptID, versionID, rolledBackBy); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func hashContent(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
