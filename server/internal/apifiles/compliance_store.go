// compliance_store.go 文件合规规则 PostgreSQL 仓储（CRUD）。
// 过滤条件一律白名单拼接、值参数化；冲突/未找到映射 ErrCompliance*。
package apifiles

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ComplianceRepository 合规规则 CRUD 仓储（SQL 与内存实现共用，便于诚实单测）。
type ComplianceRepository interface {
	// ListComplianceRules 明细分页（created_at 倒序）
	ListComplianceRules(ctx context.Context, f ComplianceFilter) ([]ComplianceRule, int64, error)
	// GetComplianceRule 按 ID 取单条（PATCH 合并/审计 before 用）
	GetComplianceRule(ctx context.Context, id uuid.UUID) (*ComplianceRule, error)
	// CreateComplianceRule 新建（ID/时间戳由库生成并回填）
	CreateComplianceRule(ctx context.Context, r *ComplianceRule) error
	// UpdateComplianceRule 整体更新（updated_at 刷新；未找到 ErrComplianceNotFound）
	UpdateComplianceRule(ctx context.Context, r *ComplianceRule) error
	// DeleteComplianceRule 硬删除（规则属配置，删除前态已留操作审计）
	DeleteComplianceRule(ctx context.Context, id uuid.UUID) error
}

// 确保 *ComplianceStore 实现接口（内存实现见 compliance_mem_store.go）。
var _ ComplianceRepository = (*ComplianceStore)(nil)

// ComplianceStore 合规规则 PostgreSQL 仓储。
type ComplianceStore struct {
	db *pgxpool.Pool
}

// NewComplianceStore 创建。
func NewComplianceStore(db *pgxpool.Pool) *ComplianceStore { return &ComplianceStore{db: db} }

// complianceCols 明细查询列。
const complianceCols = `id, direction, match_type, match_value, action, reason, enabled, created_by, created_at, updated_at`

// pgUniqueViolation PG 唯一约束违例 SQLSTATE。
const pgUniqueViolation = "23505"

// scanComplianceRule 扫描一行合规规则。
func scanComplianceRule(row interface{ Scan(...any) error }) (*ComplianceRule, error) {
	var r ComplianceRule
	if err := row.Scan(&r.ID, &r.Direction, &r.MatchType, &r.MatchValue, &r.Action,
		&r.Reason, &r.Enabled, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

// ListComplianceRules 明细分页（过滤白名单拼接，值参数化；created_at 倒序）。
func (s *ComplianceStore) ListComplianceRules(ctx context.Context, f ComplianceFilter) ([]ComplianceRule, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	where := []string{"TRUE"}
	args := []any{}
	if f.Direction != "" {
		args = append(args, f.Direction)
		where = append(where, fmt.Sprintf("direction = $%d", len(args)))
	}
	if f.MatchType != "" {
		args = append(args, f.MatchType)
		where = append(where, fmt.Sprintf("match_type = $%d", len(args)))
	}
	if f.Action != "" {
		args = append(args, f.Action)
		where = append(where, fmt.Sprintf("action = $%d", len(args)))
	}
	if f.Enabled != nil {
		args = append(args, *f.Enabled)
		where = append(where, fmt.Sprintf("enabled = $%d", len(args)))
	}
	cond := " WHERE " + strings.Join(where, " AND ")
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_file_compliance_rules"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `SELECT `+complianceCols+` FROM api_file_compliance_rules`+cond+
		fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []ComplianceRule{}
	for rows.Next() {
		r, err := scanComplianceRule(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *r)
	}
	return out, total, rows.Err()
}

// GetComplianceRule 按 ID 取单条（未找到 ErrComplianceNotFound）。
func (s *ComplianceStore) GetComplianceRule(ctx context.Context, id uuid.UUID) (*ComplianceRule, error) {
	r, err := scanComplianceRule(s.db.QueryRow(ctx,
		`SELECT `+complianceCols+` FROM api_file_compliance_rules WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrComplianceNotFound
		}
		return nil, err
	}
	return r, nil
}

// CreateComplianceRule 新建（库生成 ID/时间戳并回填；去重键冲突 ErrComplianceConflict）。
func (s *ComplianceStore) CreateComplianceRule(ctx context.Context, r *ComplianceRule) error {
	err := s.db.QueryRow(ctx, `
INSERT INTO api_file_compliance_rules (direction, match_type, match_value, action, reason, enabled, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7)
RETURNING id, created_at, updated_at`,
		r.Direction, r.MatchType, r.MatchValue, r.Action, r.Reason, r.Enabled, r.CreatedBy).
		Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt)
	if isUniqueViolation(err) {
		return ErrComplianceConflict
	}
	return err
}

// UpdateComplianceRule 整体更新（updated_at 刷新；去重键冲突 ErrComplianceConflict，
// 未找到 ErrComplianceNotFound）。
func (s *ComplianceStore) UpdateComplianceRule(ctx context.Context, r *ComplianceRule) error {
	tag, err := s.db.Exec(ctx, `
UPDATE api_file_compliance_rules
SET direction=$2, match_type=$3, match_value=$4, action=$5, reason=$6, enabled=$7, updated_at=now()
WHERE id=$1`,
		r.ID, r.Direction, r.MatchType, r.MatchValue, r.Action, r.Reason, r.Enabled)
	if isUniqueViolation(err) {
		return ErrComplianceConflict
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrComplianceNotFound
	}
	return s.db.QueryRow(ctx, `SELECT updated_at FROM api_file_compliance_rules WHERE id=$1`, r.ID).
		Scan(&r.UpdatedAt)
}

// DeleteComplianceRule 硬删除（未找到 ErrComplianceNotFound）。
func (s *ComplianceStore) DeleteComplianceRule(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM api_file_compliance_rules WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrComplianceNotFound
	}
	return nil
}

// isUniqueViolation 判定 PG 唯一约束违例。
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation
}
