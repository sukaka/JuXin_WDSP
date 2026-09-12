// store.go 授权实体层仓储：Repository 接口（SQL 与内存实现共用，便于诚实单测）
// + PostgreSQL 实现。过滤条件一律白名单拼接、值参数化。
package apiauthz

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

// RoleBaselineFilter 角色基线列表过滤（Method/Source 已归一大写）。
type RoleBaselineFilter struct {
	EndpointID *uuid.UUID
	Role       string
	Method     string
	Source     string
	Confirmed  *bool
	Page       int
	PageSize   int
}

// OwnershipFilter 对象权属列表过滤（只读查询）。
type OwnershipFilter struct {
	EndpointID *uuid.UUID
	Identity   string // identity_fingerprint 精确匹配
	ObjectType string
	ObjectID   string
	Page       int
	PageSize   int
}

// FieldPermFilter 字段权限列表过滤。
type FieldPermFilter struct {
	EndpointID   *uuid.UUID
	Direction    string
	Attribute    string
	Role         string // 精确匹配（空 = 不过滤）
	Tenant       string // 精确匹配（空 = 不过滤）
	DefaultsOnly bool   // true = 只看默认行（role IS NULL AND tenant IS NULL）
	Page         int
	PageSize     int
}

// Repository 授权实体层仓储（SQL 与内存实现共用）。
type Repository interface {
	// 角色基线
	ListRoleBaselines(ctx context.Context, f RoleBaselineFilter) ([]RoleBaseline, int64, error)
	GetRoleBaseline(ctx context.Context, id uuid.UUID) (*RoleBaseline, error)
	CreateRoleBaseline(ctx context.Context, b *RoleBaseline) error
	UpdateRoleBaseline(ctx context.Context, b *RoleBaseline) error // endpoint_id 不可改
	DeleteRoleBaseline(ctx context.Context, id uuid.UUID) error
	ConfirmRoleBaseline(ctx context.Context, id uuid.UUID, confirmed bool) (*RoleBaseline, error)
	// 对象权属（只读查询；生产方为 SweepOnce，见 sweep.go）
	ListOwnership(ctx context.Context, f OwnershipFilter) ([]ObjectOwnership, int64, error)
	// 字段权限
	ListFieldPermissions(ctx context.Context, f FieldPermFilter) ([]FieldPermission, int64, error)
	GetFieldPermission(ctx context.Context, id uuid.UUID) (*FieldPermission, error)
	CreateFieldPermission(ctx context.Context, p *FieldPermission) error
	UpdateFieldPermission(ctx context.Context, p *FieldPermission) error // endpoint_id 不可改
	DeleteFieldPermission(ctx context.Context, id uuid.UUID) error
	// EvaluateBOLA 五档 BOLA 评估（判定阶梯见 evaluate.go；端点不存在返回 ErrNotFound）
	EvaluateBOLA(ctx context.Context, in EvaluateInput) (*EvaluateResult, error)
	// SweepOnce 权属生产方（扫描 api_runtime_events 提取路径对象，upsert api_object_ownership）
	SweepOnce(ctx context.Context) (*SweepResult, error)
	// SweepObjectModelsOnce 对象模型生产方（扫描 api_runtime_events 全量事件，
	// 提取路径占位段/Query 对象参数形态，upsert api_object_models；见 objectmodels.go）
	SweepObjectModelsOnce(ctx context.Context) (*ObjectModelSweepResult, error)
}

// 确保 *Store / *MemStore 实现 Repository。
var (
	_ Repository = (*Store)(nil)
	_ Repository = (*MemStore)(nil)
)

// Store 授权实体层 PostgreSQL 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// isUniqueViolation 判断是否唯一键冲突。
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// isForeignKeyViolation 判断是否外键冲突（endpoint_id 引用不存在的端点）。
func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

// normPage 分页参数归一（页码 ≥1，分页大小夹取 [1,100]，与兄弟包上限口径一致）。
func normPage(page, pageSize int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

// buildCond 过滤条件白名单拼接（值参数化）。
func buildCond(where []string, args []any) string {
	if len(where) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(where, " AND ")
}

// ---------- 角色基线 ----------

// baselineCols 角色基线查询列。
const baselineCols = `id, endpoint_id, role, method, action, allowed, source, confidence,
	confirmed, created_by, created_at, updated_at`

// scanBaseline 扫描一行角色基线。
func scanBaseline(row pgx.Row) (*RoleBaseline, error) {
	var b RoleBaseline
	err := row.Scan(&b.ID, &b.EndpointID, &b.Role, &b.Method, &b.Action, &b.Allowed,
		&b.Source, &b.Confidence, &b.Confirmed, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// ListRoleBaselines 角色基线分页列表（过滤条件白名单拼接，值一律参数化；按创建时间倒序）。
func (s *Store) ListRoleBaselines(ctx context.Context, f RoleBaselineFilter) ([]RoleBaseline, int64, error) {
	f.Page, f.PageSize = normPage(f.Page, f.PageSize)
	where := []string{}
	args := []any{}
	if f.EndpointID != nil {
		args = append(args, *f.EndpointID)
		where = append(where, fmt.Sprintf("endpoint_id = $%d", len(args)))
	}
	if f.Role != "" {
		args = append(args, f.Role)
		where = append(where, fmt.Sprintf("role = $%d", len(args)))
	}
	if f.Method != "" {
		args = append(args, f.Method)
		where = append(where, fmt.Sprintf("method = $%d", len(args)))
	}
	if f.Source != "" {
		args = append(args, f.Source)
		where = append(where, fmt.Sprintf("source = $%d", len(args)))
	}
	if f.Confirmed != nil {
		args = append(args, *f.Confirmed)
		where = append(where, fmt.Sprintf("confirmed = $%d", len(args)))
	}
	cond := buildCond(where, args)
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_role_baselines"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `SELECT `+baselineCols+` FROM api_role_baselines`+cond+
		fmt.Sprintf(" ORDER BY created_at DESC, id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []RoleBaseline{}
	for rows.Next() {
		b, err := scanBaseline(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *b)
	}
	return out, total, rows.Err()
}

// GetRoleBaseline 按 ID 读取基线。
func (s *Store) GetRoleBaseline(ctx context.Context, id uuid.UUID) (*RoleBaseline, error) {
	b, err := scanBaseline(s.db.QueryRow(ctx,
		`SELECT `+baselineCols+` FROM api_role_baselines WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return b, nil
}

// CreateRoleBaseline 新增基线（confirmed 恒 FALSE 起步，确认走 ConfirmRoleBaseline）。
func (s *Store) CreateRoleBaseline(ctx context.Context, b *RoleBaseline) error {
	err := s.db.QueryRow(ctx, `
INSERT INTO api_role_baselines
    (endpoint_id, role, method, action, allowed, source, confidence, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, confirmed, created_at, updated_at`,
		b.EndpointID, b.Role, b.Method, b.Action, b.Allowed, b.Source, b.Confidence, b.CreatedBy).
		Scan(&b.ID, &b.Confirmed, &b.CreatedAt, &b.UpdatedAt)
	if isUniqueViolation(err) {
		return ErrBaselineConflict
	}
	if isForeignKeyViolation(err) {
		return ErrEndpointNotFound
	}
	return err
}

// UpdateRoleBaseline 更新基线（endpoint_id 不可改；confirmed 不随编辑变更，确认走 Confirm）。
func (s *Store) UpdateRoleBaseline(ctx context.Context, b *RoleBaseline) error {
	err := s.db.QueryRow(ctx, `
UPDATE api_role_baselines SET
    role = $2, method = $3, action = $4, allowed = $5, source = $6,
    confidence = $7, updated_at = now()
WHERE id = $1
RETURNING updated_at`,
		b.ID, b.Role, b.Method, b.Action, b.Allowed, b.Source, b.Confidence).Scan(&b.UpdatedAt)
	if isUniqueViolation(err) {
		return ErrBaselineConflict
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// DeleteRoleBaseline 删除基线。
func (s *Store) DeleteRoleBaseline(ctx context.Context, id uuid.UUID) error {
	ct, err := s.db.Exec(ctx, `DELETE FROM api_role_baselines WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ConfirmRoleBaseline 确认/取消确认基线（候选 → 正式基线；返回更新后实体）。
func (s *Store) ConfirmRoleBaseline(ctx context.Context, id uuid.UUID, confirmed bool) (*RoleBaseline, error) {
	b, err := scanBaseline(s.db.QueryRow(ctx, `
UPDATE api_role_baselines SET confirmed = $2, updated_at = now()
WHERE id = $1
RETURNING `+baselineCols, id, confirmed))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return b, nil
}

// ---------- 对象权属（只读查询） ----------

// ownershipCols 对象权属查询列。
const ownershipCols = `id, endpoint_id, identity_fingerprint, object_type, object_id,
	first_seen, last_seen, access_count`

// scanOwnership 扫描一行对象权属。
func scanOwnership(row pgx.Row) (*ObjectOwnership, error) {
	var o ObjectOwnership
	err := row.Scan(&o.ID, &o.EndpointID, &o.IdentityFingerprint, &o.ObjectType, &o.ObjectID,
		&o.FirstSeen, &o.LastSeen, &o.AccessCount)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// ListOwnership 对象权属分页列表（按最近访问倒序；只读，生产方为 SweepOnce）。
func (s *Store) ListOwnership(ctx context.Context, f OwnershipFilter) ([]ObjectOwnership, int64, error) {
	f.Page, f.PageSize = normPage(f.Page, f.PageSize)
	where := []string{}
	args := []any{}
	if f.EndpointID != nil {
		args = append(args, *f.EndpointID)
		where = append(where, fmt.Sprintf("endpoint_id = $%d", len(args)))
	}
	if f.Identity != "" {
		args = append(args, f.Identity)
		where = append(where, fmt.Sprintf("identity_fingerprint = $%d", len(args)))
	}
	if f.ObjectType != "" {
		args = append(args, f.ObjectType)
		where = append(where, fmt.Sprintf("object_type = $%d", len(args)))
	}
	if f.ObjectID != "" {
		args = append(args, f.ObjectID)
		where = append(where, fmt.Sprintf("object_id = $%d", len(args)))
	}
	cond := buildCond(where, args)
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_object_ownership"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `SELECT `+ownershipCols+` FROM api_object_ownership`+cond+
		fmt.Sprintf(" ORDER BY last_seen DESC, id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []ObjectOwnership{}
	for rows.Next() {
		o, err := scanOwnership(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *o)
	}
	return out, total, rows.Err()
}

// ---------- 字段权限 ----------

// fieldPermCols 字段权限查询列。
const fieldPermCols = `id, endpoint_id, field_path, direction, attribute, role, tenant,
	created_by, created_at, updated_at`

// scanFieldPermission 扫描一行字段权限（可空列经指针接收）。
func scanFieldPermission(row pgx.Row) (*FieldPermission, error) {
	var p FieldPermission
	err := row.Scan(&p.ID, &p.EndpointID, &p.FieldPath, &p.Direction, &p.Attribute,
		&p.Role, &p.Tenant, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ListFieldPermissions 字段权限分页列表（过滤条件白名单拼接；按创建时间倒序）。
func (s *Store) ListFieldPermissions(ctx context.Context, f FieldPermFilter) ([]FieldPermission, int64, error) {
	f.Page, f.PageSize = normPage(f.Page, f.PageSize)
	where := []string{}
	args := []any{}
	if f.EndpointID != nil {
		args = append(args, *f.EndpointID)
		where = append(where, fmt.Sprintf("endpoint_id = $%d", len(args)))
	}
	if f.Direction != "" {
		args = append(args, f.Direction)
		where = append(where, fmt.Sprintf("direction = $%d", len(args)))
	}
	if f.Attribute != "" {
		args = append(args, f.Attribute)
		where = append(where, fmt.Sprintf("attribute = $%d", len(args)))
	}
	if f.Role != "" {
		args = append(args, f.Role)
		where = append(where, fmt.Sprintf("role = $%d", len(args)))
	}
	if f.Tenant != "" {
		args = append(args, f.Tenant)
		where = append(where, fmt.Sprintf("tenant = $%d", len(args)))
	}
	if f.DefaultsOnly {
		where = append(where, "role IS NULL AND tenant IS NULL")
	}
	cond := buildCond(where, args)
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_field_permissions"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `SELECT `+fieldPermCols+` FROM api_field_permissions`+cond+
		fmt.Sprintf(" ORDER BY created_at DESC, id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []FieldPermission{}
	for rows.Next() {
		p, err := scanFieldPermission(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *p)
	}
	return out, total, rows.Err()
}

// GetFieldPermission 按 ID 读取字段权限。
func (s *Store) GetFieldPermission(ctx context.Context, id uuid.UUID) (*FieldPermission, error) {
	p, err := scanFieldPermission(s.db.QueryRow(ctx,
		`SELECT `+fieldPermCols+` FROM api_field_permissions WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return p, nil
}

// CreateFieldPermission 新增字段权限（唯一索引含 COALESCE 表达式，冲突映射 23505）。
func (s *Store) CreateFieldPermission(ctx context.Context, p *FieldPermission) error {
	err := s.db.QueryRow(ctx, `
INSERT INTO api_field_permissions
    (endpoint_id, field_path, direction, attribute, role, tenant, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, created_at, updated_at`,
		p.EndpointID, p.FieldPath, p.Direction, p.Attribute, p.Role, p.Tenant, p.CreatedBy).
		Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
	if isUniqueViolation(err) {
		return ErrFieldPermConflict
	}
	if isForeignKeyViolation(err) {
		return ErrEndpointNotFound
	}
	return err
}

// UpdateFieldPermission 更新字段权限（endpoint_id 不可改；updated_at 刷新）。
func (s *Store) UpdateFieldPermission(ctx context.Context, p *FieldPermission) error {
	err := s.db.QueryRow(ctx, `
UPDATE api_field_permissions SET
    field_path = $2, direction = $3, attribute = $4, role = $5, tenant = $6, updated_at = now()
WHERE id = $1
RETURNING updated_at`,
		p.ID, p.FieldPath, p.Direction, p.Attribute, p.Role, p.Tenant).Scan(&p.UpdatedAt)
	if isUniqueViolation(err) {
		return ErrFieldPermConflict
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// DeleteFieldPermission 删除字段权限。
func (s *Store) DeleteFieldPermission(ctx context.Context, id uuid.UUID) error {
	ct, err := s.db.Exec(ctx, `DELETE FROM api_field_permissions WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- BOLA 评估 ----------

// EvaluateBOLA 五档 BOLA 评估（SQL 实现）：采集五路信号后走 decideVerdict 判定阶梯。
// 端点不存在返回 ErrNotFound；匿名身份（Identity 为空）跳过身份侧信号采集。
func (s *Store) EvaluateBOLA(ctx context.Context, in EvaluateInput) (*EvaluateResult, error) {
	var exists bool
	if err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM api_endpoints WHERE id = $1)`, in.EndpointID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	sig := evalSignals{}
	if in.Identity != "" {
		if err := s.db.QueryRow(ctx, `SELECT EXISTS(
	SELECT 1 FROM api_object_ownership
	WHERE endpoint_id = $1 AND identity_fingerprint = $2 AND object_id = $3)`,
			in.EndpointID, in.Identity, in.ObjectID).Scan(&sig.ownMatch); err != nil {
			return nil, err
		}
		if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_object_ownership
	WHERE endpoint_id = $1 AND identity_fingerprint = $2`,
			in.EndpointID, in.Identity).Scan(&sig.identityObjectCount); err != nil {
			return nil, err
		}
		// 历史运行时访问：经 endpoint_key 关联端点（事件身份列口径见迁移 000029）
		if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_runtime_events e
	JOIN api_endpoints ep ON ep.endpoint_key = e.endpoint_key
	WHERE ep.id = $1 AND e.identity_fingerprint = $2`,
			in.EndpointID, in.Identity).Scan(&sig.identityEventCount); err != nil {
			return nil, err
		}
	}
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_object_ownership
	WHERE endpoint_id = $1 AND object_id = $2`,
		in.EndpointID, in.ObjectID).Scan(&sig.objectOwnerCount); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_object_ownership WHERE endpoint_id = $1`,
		in.EndpointID).Scan(&sig.endpointOwnershipRows); err != nil {
		return nil, err
	}
	return buildEvaluateResult(in, sig), nil
}
