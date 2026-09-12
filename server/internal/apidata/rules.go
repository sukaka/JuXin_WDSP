// rules.go 脱敏规则（api_masking_rules）PostgreSQL 仓储。
package apidata

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ruleCols 脱敏规则查询列。
const ruleCols = `id, name, enabled, scope, application_id, endpoint_key, field_path,
	data_type, algorithm, params_json, exclusions_json, created_by, created_at, updated_at`

// scanRule 扫描一行脱敏规则（可空列经指针接收，params/exclusions 空值归一为 {}）。
func scanRule(row pgx.Row) (*MaskingRule, error) {
	var r MaskingRule
	err := row.Scan(&r.ID, &r.Name, &r.Enabled, &r.Scope, &r.ApplicationID, &r.EndpointKey,
		&r.FieldPath, &r.DataType, &r.Algorithm, &r.Params, &r.Exclusions,
		&r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if len(r.Params) == 0 {
		r.Params = []byte(`{}`)
	}
	if len(r.Exclusions) == 0 {
		r.Exclusions = []byte(`{}`)
	}
	return &r, nil
}

// ListMaskingRules 脱敏规则分页列表（过滤条件白名单拼接，值一律参数化；按创建时间倒序）。
func (s *Store) ListMaskingRules(ctx context.Context, f RuleFilter) ([]MaskingRule, int64, error) {
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
	if f.Scope != "" {
		args = append(args, f.Scope)
		where = append(where, fmt.Sprintf("scope = $%d", len(args)))
	}
	if f.ApplicationID != nil {
		args = append(args, *f.ApplicationID)
		where = append(where, fmt.Sprintf("application_id = $%d", len(args)))
	}
	if f.EndpointKey != "" {
		args = append(args, f.EndpointKey)
		where = append(where, fmt.Sprintf("endpoint_key = $%d", len(args)))
	}
	if f.Enabled != nil {
		args = append(args, *f.Enabled)
		where = append(where, fmt.Sprintf("enabled = $%d", len(args)))
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_masking_rules"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `SELECT `+ruleCols+` FROM api_masking_rules`+cond+
		fmt.Sprintf(" ORDER BY created_at DESC, id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []MaskingRule{}
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *r)
	}
	return out, total, rows.Err()
}

// GetMaskingRule 按 ID 读取规则。
func (s *Store) GetMaskingRule(ctx context.Context, id uuid.UUID) (*MaskingRule, error) {
	r, err := scanRule(s.db.QueryRow(ctx,
		`SELECT `+ruleCols+` FROM api_masking_rules WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return r, nil
}

// CreateMaskingRule 新增规则。
func (s *Store) CreateMaskingRule(ctx context.Context, r *MaskingRule) error {
	return s.db.QueryRow(ctx, `
INSERT INTO api_masking_rules
    (name, enabled, scope, application_id, endpoint_key, field_path, data_type,
     algorithm, params_json, exclusions_json, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING id, created_at, updated_at`,
		r.Name, r.Enabled, r.Scope, r.ApplicationID, r.EndpointKey, r.FieldPath, r.DataType,
		r.Algorithm, r.Params, r.Exclusions, r.CreatedBy).
		Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt)
}

// UpdateMaskingRule 更新规则（updated_at 刷新；规则不做版本列，变更追踪走操作审计）。
func (s *Store) UpdateMaskingRule(ctx context.Context, r *MaskingRule) error {
	err := s.db.QueryRow(ctx, `
UPDATE api_masking_rules SET
    name = $2, enabled = $3, scope = $4, application_id = $5, endpoint_key = $6,
    field_path = $7, data_type = $8, algorithm = $9, params_json = $10,
    exclusions_json = $11, updated_at = now()
WHERE id = $1
RETURNING updated_at`,
		r.ID, r.Name, r.Enabled, r.Scope, r.ApplicationID, r.EndpointKey, r.FieldPath,
		r.DataType, r.Algorithm, r.Params, r.Exclusions).Scan(&r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// DeleteMaskingRule 删除规则。
func (s *Store) DeleteMaskingRule(ctx context.Context, id uuid.UUID) error {
	ct, err := s.db.Exec(ctx, `DELETE FROM api_masking_rules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListEnabledMaskingRules 全量启用规则（MaskPlanForEndpoint 求值输入；确定性排序）。
func (s *Store) ListEnabledMaskingRules(ctx context.Context) ([]MaskingRule, error) {
	rows, err := s.db.Query(ctx,
		`SELECT `+ruleCols+` FROM api_masking_rules WHERE enabled ORDER BY created_at ASC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MaskingRule{}
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}
