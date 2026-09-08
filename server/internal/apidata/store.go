// store.go 敏感数据管理面仓储：Repository 接口（SQL 与内存实现共用，便于诚实单测）
// + PostgreSQL 实现。过滤条件一律白名单拼接、值参数化。
package apidata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNameConflict 敏感数据类型名称冲突（name UNIQUE）。
var ErrNameConflict = errors.New("sensitive data type name conflict")

// TypeFilter 敏感数据类型列表过滤（Status/Level 已归一大写）。
type TypeFilter struct {
	Status   string
	Level    string
	Category string
	Keyword  string // name 子串匹配（不区分大小写）
	Page     int
	PageSize int
}

// RuleFilter 脱敏规则列表过滤。
type RuleFilter struct {
	Scope         string
	ApplicationID *uuid.UUID
	EndpointKey   string
	Enabled       *bool
	Page          int
	PageSize      int
}

// Repository 敏感数据管理面仓储（SQL 与内存实现共用）。
type Repository interface {
	// 敏感数据类型
	ListTypes(ctx context.Context, f TypeFilter) ([]SensitiveDataType, int64, error)
	GetType(ctx context.Context, id uuid.UUID) (*SensitiveDataType, error)
	CreateType(ctx context.Context, t *SensitiveDataType) error
	UpdateType(ctx context.Context, t *SensitiveDataType) error // version 自增在实现内
	DeleteType(ctx context.Context, id uuid.UUID) error
	ListAllTypes(ctx context.Context) ([]SensitiveDataType, error) // 导出（内置 + 自定义全量）
	// ImportTypes 导入 upsert（按 name 匹配：存在更新且 version+1，不存在创建；单事务）
	ImportTypes(ctx context.Context, items []SensitiveDataType) (created, updated int, err error)
	// 脱敏规则
	ListMaskingRules(ctx context.Context, f RuleFilter) ([]MaskingRule, int64, error)
	GetMaskingRule(ctx context.Context, id uuid.UUID) (*MaskingRule, error)
	CreateMaskingRule(ctx context.Context, r *MaskingRule) error
	UpdateMaskingRule(ctx context.Context, r *MaskingRule) error
	DeleteMaskingRule(ctx context.Context, id uuid.UUID) error
	ListEnabledMaskingRules(ctx context.Context) ([]MaskingRule, error) // MaskPlanForEndpoint 求值输入
	// 敏感数据态势（api_sensitive_fields + api_runtime_events 聚合）
	SensitiveOverview(ctx context.Context, days int) (*SensitiveOverview, error)
	// SweepOnce 运行时敏感证据清扫（api_sensitive_fields 生产写入方，实现见 sweep.go）
	SweepOnce(ctx context.Context) (*SweepResult, error)
}

// 确保 *Store / *MemStore 实现 Repository。
var (
	_ Repository = (*Store)(nil)
	_ Repository = (*MemStore)(nil)
)

// Store 敏感数据管理面 PostgreSQL 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// ---------- 敏感数据类型 ----------

// typeCols 类型查询列。
const typeCols = `id, name, description, category, level, data_type, locations, keywords,
	regex, validator, exclude_fields, status, version, is_builtin, created_at, updated_at`

// jsonStrings jsonb 数组列 → []string（空/null 归一为空切片，保证 JSON 输出 [] 而非 null）。
func jsonStrings(raw json.RawMessage) ([]string, error) {
	out := []string{}
	if len(raw) == 0 || string(raw) == "null" {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// scanType 扫描一行敏感数据类型（jsonb 数组列经 json.RawMessage 中转）。
func scanType(row pgx.Row) (*SensitiveDataType, error) {
	var t SensitiveDataType
	var locations, keywords, excludeFields json.RawMessage
	err := row.Scan(&t.ID, &t.Name, &t.Description, &t.Category, &t.Level, &t.DataType,
		&locations, &keywords, &t.Regex, &t.Validator, &excludeFields,
		&t.Status, &t.Version, &t.IsBuiltin, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if t.Locations, err = jsonStrings(locations); err != nil {
		return nil, err
	}
	if t.Keywords, err = jsonStrings(keywords); err != nil {
		return nil, err
	}
	t.ExcludeFields, err = jsonStrings(excludeFields)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// marshalStrList []string → jsonb 参数（nil 归一为 []）。
func marshalStrList(items []string) ([]byte, error) {
	if items == nil {
		items = []string{}
	}
	return json.Marshal(items)
}

// isUniqueViolation 判断是否唯一键冲突。
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// ListTypes 敏感数据类型分页列表（过滤条件白名单拼接，值一律参数化；内置优先、按名称排序）。
func (s *Store) ListTypes(ctx context.Context, f TypeFilter) ([]SensitiveDataType, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	if f.PageSize > 100 {
		f.PageSize = 100
	}
	where := []string{}
	args := []any{}
	if f.Status != "" {
		args = append(args, f.Status)
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	if f.Level != "" {
		args = append(args, f.Level)
		where = append(where, fmt.Sprintf("level = $%d", len(args)))
	}
	if f.Category != "" {
		args = append(args, f.Category)
		where = append(where, fmt.Sprintf("category = $%d", len(args)))
	}
	if f.Keyword != "" {
		args = append(args, f.Keyword)
		// position 子串匹配，避免 LIKE 通配符转义问题
		where = append(where, fmt.Sprintf("position(lower($%d) in lower(name)) > 0", len(args)))
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_sensitive_data_types"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `SELECT `+typeCols+` FROM api_sensitive_data_types`+cond+
		fmt.Sprintf(" ORDER BY is_builtin DESC, name LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []SensitiveDataType{}
	for rows.Next() {
		t, err := scanType(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *t)
	}
	return out, total, rows.Err()
}

// GetType 按 ID 读取类型。
func (s *Store) GetType(ctx context.Context, id uuid.UUID) (*SensitiveDataType, error) {
	t, err := scanType(s.db.QueryRow(ctx,
		`SELECT `+typeCols+` FROM api_sensitive_data_types WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return t, nil
}

// CreateType 新增类型（名称唯一；is_builtin 恒 FALSE，内置仅由迁移种子产生）。
func (s *Store) CreateType(ctx context.Context, t *SensitiveDataType) error {
	locations, err := marshalStrList(t.Locations)
	if err != nil {
		return err
	}
	keywords, err := marshalStrList(t.Keywords)
	if err != nil {
		return err
	}
	excludeFields, err := marshalStrList(t.ExcludeFields)
	if err != nil {
		return err
	}
	err = s.db.QueryRow(ctx, `
INSERT INTO api_sensitive_data_types
    (name, description, category, level, data_type, locations, keywords, regex, validator, exclude_fields, status)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING id, version, is_builtin, created_at, updated_at`,
		t.Name, t.Description, t.Category, t.Level, t.DataType, locations, keywords,
		t.Regex, t.Validator, excludeFields, t.Status).
		Scan(&t.ID, &t.Version, &t.IsBuiltin, &t.CreatedAt, &t.UpdatedAt)
	if isUniqueViolation(err) {
		return ErrNameConflict
	}
	return err
}

// UpdateType 更新类型（version 自增、updated_at 刷新；is_builtin 不可经此变更）。
func (s *Store) UpdateType(ctx context.Context, t *SensitiveDataType) error {
	locations, err := marshalStrList(t.Locations)
	if err != nil {
		return err
	}
	keywords, err := marshalStrList(t.Keywords)
	if err != nil {
		return err
	}
	excludeFields, err := marshalStrList(t.ExcludeFields)
	if err != nil {
		return err
	}
	err = s.db.QueryRow(ctx, `
UPDATE api_sensitive_data_types SET
    name = $2, description = $3, category = $4, level = $5, data_type = $6,
    locations = $7, keywords = $8, regex = $9, validator = $10, exclude_fields = $11,
    status = $12, version = version + 1, updated_at = now()
WHERE id = $1
RETURNING version, updated_at`,
		t.ID, t.Name, t.Description, t.Category, t.Level, t.DataType,
		locations, keywords, t.Regex, t.Validator, excludeFields, t.Status).
		Scan(&t.Version, &t.UpdatedAt)
	if isUniqueViolation(err) {
		return ErrNameConflict
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// DeleteType 删除类型（内置保护在 handler 层；此处不加 is_builtin 条件）。
func (s *Store) DeleteType(ctx context.Context, id uuid.UUID) error {
	ct, err := s.db.Exec(ctx, `DELETE FROM api_sensitive_data_types WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListAllTypes 全量类型（导出用；内置优先、按名称排序）。
func (s *Store) ListAllTypes(ctx context.Context) ([]SensitiveDataType, error) {
	rows, err := s.db.Query(ctx,
		`SELECT `+typeCols+` FROM api_sensitive_data_types ORDER BY is_builtin DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SensitiveDataType{}
	for rows.Next() {
		t, err := scanType(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// ImportTypes 导入 upsert：按 name 匹配，存在则更新（version+1，is_builtin 保持原值），
// 不存在则创建；整体单事务（任一条失败全量回滚）。
func (s *Store) ImportTypes(ctx context.Context, items []SensitiveDataType) (int, int, error) {
	created, updated := 0, 0
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for i := range items {
		t := &items[i]
		locations, err := marshalStrList(t.Locations)
		if err != nil {
			return 0, 0, err
		}
		keywords, err := marshalStrList(t.Keywords)
		if err != nil {
			return 0, 0, err
		}
		excludeFields, err := marshalStrList(t.ExcludeFields)
		if err != nil {
			return 0, 0, err
		}
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM api_sensitive_data_types WHERE name = $1)`,
			t.Name).Scan(&exists); err != nil {
			return 0, 0, err
		}
		if exists {
			// 更新：version 自增；is_builtin 不随导入变更（内置身份仅由迁移种子授予）
			_, err = tx.Exec(ctx, `
UPDATE api_sensitive_data_types SET
    description = $2, category = $3, level = $4, data_type = $5, locations = $6,
    keywords = $7, regex = $8, validator = $9, exclude_fields = $10,
    status = $11, version = version + 1, updated_at = now()
WHERE name = $1`,
				t.Name, t.Description, t.Category, t.Level, t.DataType, locations,
				keywords, t.Regex, t.Validator, excludeFields, t.Status)
			updated++
		} else {
			_, err = tx.Exec(ctx, `
INSERT INTO api_sensitive_data_types
    (name, description, category, level, data_type, locations, keywords, regex, validator, exclude_fields, status)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
				t.Name, t.Description, t.Category, t.Level, t.DataType, locations, keywords,
				t.Regex, t.Validator, excludeFields, t.Status)
			created++
		}
		if err != nil {
			return 0, 0, err
		}
	}
	return created, updated, tx.Commit(ctx)
}
