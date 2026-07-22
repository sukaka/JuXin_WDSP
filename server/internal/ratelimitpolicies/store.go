package ratelimitpolicies

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// policyColumns 是查询列清单（与 scanPolicy 顺序一致）。
const policyColumns = `id, name, description, scope_type, application_id, uri_match_type, uri_pattern,
  dimension, algorithm, requests_limit, window_seconds, burst_capacity, action, block_duration_seconds,
  status, observe_only, priority, effective_from, effective_until,
  created_by, created_at, updated_by, updated_at, version`

// ListFilter 是列表查询筛选。
type ListFilter struct {
	ScopeType     string
	ApplicationID *uuid.UUID
	Status        string
	Action        string
	Keyword       string // 匹配名称/描述
	Page          int
	PageSize      int
}

// Store 是限速策略仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// List 分页查询限速策略。
func (s *Store) List(ctx context.Context, f ListFilter) ([]Policy, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where := "deleted_at IS NULL"
	args := []interface{}{}
	argIdx := 1
	add := func(cond string, v interface{}) {
		where += fmt.Sprintf(" AND "+cond, argIdx)
		args = append(args, v)
		argIdx++
	}
	if f.ScopeType != "" {
		add("scope_type = $%d", f.ScopeType)
	}
	if f.ApplicationID != nil {
		add("application_id = $%d", *f.ApplicationID)
	}
	if f.Status != "" {
		add("status = $%d", f.Status)
	}
	if f.Action != "" {
		add("action = $%d", f.Action)
	}
	if f.Keyword != "" {
		where += fmt.Sprintf(" AND (name ILIKE $%d OR description ILIKE $%d)", argIdx, argIdx)
		args = append(args, "%"+f.Keyword+"%")
		argIdx++
	}

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM rate_limit_policies WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	// 按优先级升序（评估顺序），同优先级按创建时间倒序
	query := `SELECT ` + policyColumns + ` FROM rate_limit_policies WHERE ` + where +
		fmt.Sprintf(" ORDER BY priority ASC, created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]Policy, 0, f.PageSize)
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *p)
	}
	return out, total, rows.Err()
}

// GetByID 查询限速策略。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Policy, error) {
	row := s.db.QueryRow(ctx,
		`SELECT `+policyColumns+` FROM rate_limit_policies WHERE id = $1 AND deleted_at IS NULL`, id)
	return scanPolicy(row)
}

// Create 创建限速策略（先校验）。
func (s *Store) Create(ctx context.Context, p *Policy, createdBy uuid.UUID) error {
	if errs := ValidateInput(p); len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	return s.db.QueryRow(ctx, `
INSERT INTO rate_limit_policies (name, description, scope_type, application_id, uri_match_type, uri_pattern,
  dimension, algorithm, requests_limit, window_seconds, burst_capacity, action, block_duration_seconds,
  status, observe_only, priority, effective_from, effective_until, created_by, updated_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$19)
RETURNING id, created_at, updated_at, version`,
		p.Name, p.Description, p.ScopeType, p.ApplicationID, p.URIMatchType, p.URIPattern,
		p.Dimension, p.Algorithm, p.RequestsLimit, p.WindowSeconds, p.BurstCapacity,
		p.Action, p.BlockDurationSeconds, p.Status, p.ObserveOnly, p.Priority,
		p.EffectiveFrom, p.EffectiveUntil, createdBy,
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt, &p.Version)
}

// Update 更新限速策略（乐观锁：version 不匹配则不更新）。
// 状态只能通过 SetStatus 变更，本方法不更新 status。
func (s *Store) Update(ctx context.Context, p *Policy, updatedBy uuid.UUID) error {
	if errs := ValidateInput(p); len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	res, err := s.db.Exec(ctx, `
UPDATE rate_limit_policies SET name=$1, description=$2, scope_type=$3, application_id=$4,
  uri_match_type=$5, uri_pattern=$6, dimension=$7, algorithm=$8, requests_limit=$9, window_seconds=$10,
  burst_capacity=$11, action=$12, block_duration_seconds=$13, observe_only=$14, priority=$15,
  effective_from=$16, effective_until=$17, updated_by=$18, updated_at=now(), version=version+1
WHERE id=$19 AND version=$20 AND deleted_at IS NULL`,
		p.Name, p.Description, p.ScopeType, p.ApplicationID, p.URIMatchType, p.URIPattern,
		p.Dimension, p.Algorithm, p.RequestsLimit, p.WindowSeconds, p.BurstCapacity,
		p.Action, p.BlockDurationSeconds, p.ObserveOnly, p.Priority,
		p.EffectiveFrom, p.EffectiveUntil, updatedBy, p.ID, p.Version)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	p.Version++
	return nil
}

// SoftDelete 软删除限速策略。
func (s *Store) SoftDelete(ctx context.Context, id, updatedBy uuid.UUID) error {
	res, err := s.db.Exec(ctx, `
UPDATE rate_limit_policies SET deleted_at=now(), updated_by=$2, updated_at=now(), version=version+1
WHERE id=$1 AND deleted_at IS NULL`, id, updatedBy)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetStatus 设置策略状态（仅允许 ACTIVE/DISABLED）。
func (s *Store) SetStatus(ctx context.Context, id, updatedBy uuid.UUID, status string) error {
	if !validStatuses[status] {
		return fmt.Errorf("%w: %s", ErrInvalidStatus, status)
	}
	res, err := s.db.Exec(ctx, `
UPDATE rate_limit_policies SET status=$1, updated_by=$3, updated_at=now(), version=version+1
WHERE id=$2 AND deleted_at IS NULL`, status, id, updatedBy)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// scanPolicy 扫描一行策略。pgx.Rows 同样实现 pgx.Row 接口，List 迭代时直接复用。
func scanPolicy(row pgx.Row) (*Policy, error) {
	var p Policy
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.ScopeType, &p.ApplicationID,
		&p.URIMatchType, &p.URIPattern, &p.Dimension, &p.Algorithm,
		&p.RequestsLimit, &p.WindowSeconds, &p.BurstCapacity, &p.Action, &p.BlockDurationSeconds,
		&p.Status, &p.ObserveOnly, &p.Priority, &p.EffectiveFrom, &p.EffectiveUntil,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedBy, &p.UpdatedAt, &p.Version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}
