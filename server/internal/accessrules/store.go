package accessrules

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store 是 IP 访问控制规则仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

const ruleColumns = `id, name, rule_type, scope_type, application_id, address, ip_version, priority,
status, validity_type, effective_from, effective_until, reason, source_type, source_event_id,
hit_count, last_hit_at, created_by, created_at, updated_by, updated_at, version`

// rowQuerier 抽象 *pgxpool.Pool 与 pgx.Tx 共有的 QueryRow（供事务内复用）。
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
}

// prepareRule 校验并规范化输入，生成待入库规则（新建默认 ACTIVE）。
func prepareRule(in CreateInput, now time.Time) (*Rule, error) {
	if err := ValidateInput(&in, now); err != nil {
		return nil, err
	}
	norm, ipVer, err := NormalizeAddress(in.Address)
	if err != nil {
		return nil, err
	}
	if in.Priority == 0 {
		in.Priority = 100
	}
	return &Rule{
		Name:           in.Name,
		RuleType:       in.RuleType,
		ScopeType:      in.ScopeType,
		ApplicationID:  in.ApplicationID,
		Address:        norm,
		IPVersion:      ipVer,
		Priority:       in.Priority,
		Status:         StatusActive,
		ValidityType:   in.ValidityType,
		EffectiveFrom:  in.EffectiveFrom,
		EffectiveUntil: in.EffectiveUntil,
		Reason:         in.Reason,
		SourceType:     in.SourceType,
		SourceEventID:  in.SourceEventID,
	}, nil
}

// Create 创建规则。
func (s *Store) Create(ctx context.Context, in CreateInput, createdBy uuid.UUID) (*Rule, error) {
	r, err := prepareRule(in, time.Now())
	if err != nil {
		return nil, err
	}
	if err := insertRuleChecked(ctx, s.db, r, createdBy, nil); err != nil {
		return nil, err
	}
	return r, nil
}

// CreateDraft 创建草稿规则（与 Create 相同校验/规范化，状态固定 DRAFT，不进入网关生效集）。
func (s *Store) CreateDraft(ctx context.Context, in CreateInput, createdBy uuid.UUID) (*Rule, error) {
	r, err := prepareRule(in, time.Now())
	if err != nil {
		return nil, err
	}
	r.Status = StatusDraft
	if err := insertRuleChecked(ctx, s.db, r, createdBy, nil); err != nil {
		return nil, err
	}
	return r, nil
}

// CreateBatch 在一个事务中批量创建（状态 ACTIVE），任一条失败整体回滚。
func (s *Store) CreateBatch(ctx context.Context, inputs []CreateInput, createdBy uuid.UUID) error {
	return s.createBatch(ctx, inputs, createdBy, StatusActive)
}

// CreateBatchDraft 在一个事务中批量创建草稿（导入落 DRAFT，不进入网关生效集），任一条失败整体回滚。
func (s *Store) CreateBatchDraft(ctx context.Context, inputs []CreateInput, createdBy uuid.UUID) error {
	return s.createBatch(ctx, inputs, createdBy, StatusDraft)
}

func (s *Store) createBatch(ctx context.Context, inputs []CreateInput, createdBy uuid.UUID, status string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now()
	for _, in := range inputs {
		r, err := prepareRule(in, now)
		if err != nil {
			return err
		}
		r.Status = status
		if err := insertRuleChecked(ctx, tx, r, createdBy, nil); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// insertRuleChecked 唯一性检查（同 scope+application+address+rule_type 且未删除）后插入。
func insertRuleChecked(ctx context.Context, q rowQuerier, r *Rule, createdBy uuid.UUID, excludeID *uuid.UUID) error {
	ok, err := conflictExists(ctx, q, r.ScopeType, r.ApplicationID, r.Address, r.RuleType, excludeID)
	if err != nil {
		return err
	}
	if ok {
		return fmt.Errorf("%w: 相同范围下已存在地址 %s 的 %s 规则", ErrConflict, r.Address, r.RuleType)
	}
	return q.QueryRow(ctx, `
INSERT INTO ip_access_rules (name, rule_type, scope_type, application_id, address, ip_version,
  priority, status, validity_type, effective_from, effective_until, reason, source_type,
  source_event_id, created_by, updated_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15)
RETURNING id, created_at, updated_at, version`,
		r.Name, r.RuleType, r.ScopeType, r.ApplicationID, r.Address, r.IPVersion,
		r.Priority, r.Status, r.ValidityType, r.EffectiveFrom, r.EffectiveUntil, r.Reason,
		r.SourceType, r.SourceEventID, createdBy,
	).Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt, &r.Version)
}

// conflictExists 检查唯一性冲突。application_id 可能为 NULL，用 IS NOT DISTINCT FROM 比较。
func conflictExists(ctx context.Context, q rowQuerier, scopeType string, appID *uuid.UUID, address, ruleType string, excludeID *uuid.UUID) (bool, error) {
	query := `SELECT count(*) FROM ip_access_rules
WHERE deleted_at IS NULL AND scope_type = $1 AND application_id IS NOT DISTINCT FROM $2
  AND address = $3 AND rule_type = $4`
	args := []interface{}{scopeType, appID, address, ruleType}
	if excludeID != nil {
		query += " AND id <> $5"
		args = append(args, *excludeID)
	}
	var n int64
	if err := q.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// GetByID 查询规则（不含已删除）。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Rule, error) {
	row := s.db.QueryRow(ctx, `SELECT `+ruleColumns+` FROM ip_access_rules WHERE id = $1 AND deleted_at IS NULL`, id)
	return scanRule(row)
}

func buildListWhere(f ListFilter) (string, []interface{}) {
	where := "deleted_at IS NULL"
	args := []interface{}{}
	argIdx := 1
	add := func(cond string, v interface{}) {
		where += fmt.Sprintf(" AND "+cond, argIdx)
		args = append(args, v)
		argIdx++
	}
	if f.RuleType != "" {
		add("rule_type = $%d", f.RuleType)
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
	if f.SourceType != "" {
		add("source_type = $%d", f.SourceType)
	}
	if f.Keyword != "" {
		where += fmt.Sprintf(" AND (name ILIKE $%d OR address ILIKE $%d)", argIdx, argIdx)
		args = append(args, "%"+f.Keyword+"%")
		argIdx++
	}
	if f.Address != "" {
		// 能规范化则按规范形式精确匹配，否则按原样匹配（通常匹配不到）
		addr := f.Address
		if norm, _, err := NormalizeAddress(f.Address); err == nil {
			addr = norm
		}
		add("address = $%d", addr)
	}
	if len(f.IDs) > 0 {
		add("id = ANY($%d::uuid[])", f.IDs)
	}
	return where, args
}

// List 分页查询规则。
func (s *Store) List(ctx context.Context, f ListFilter) ([]Rule, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where, args := buildListWhere(f)
	argIdx := len(args) + 1
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM ip_access_rules WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + ruleColumns + ` FROM ip_access_rules WHERE ` + where +
		fmt.Sprintf(" ORDER BY priority ASC, created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *r)
	}
	return out, total, rows.Err()
}

// Update 更新规则（乐观锁：version 不匹配返回 ErrVersionConflict）。
func (s *Store) Update(ctx context.Context, in UpdateInput, updatedBy uuid.UUID) (*Rule, error) {
	if err := validateUpdateInput(&in, time.Now()); err != nil {
		return nil, err
	}
	norm, ipVer, err := NormalizeAddress(in.Address)
	if err != nil {
		return nil, err
	}
	cur, err := s.GetByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	ok, err := conflictExists(ctx, s.db, cur.ScopeType, cur.ApplicationID, norm, cur.RuleType, &in.ID)
	if err != nil {
		return nil, err
	}
	if ok {
		return nil, fmt.Errorf("%w: 相同范围下已存在地址 %s 的 %s 规则", ErrConflict, norm, cur.RuleType)
	}
	res, err := s.db.Exec(ctx, `
UPDATE ip_access_rules SET name=$1, address=$2, ip_version=$3, priority=$4, validity_type=$5,
  effective_from=$6, effective_until=$7, reason=$8, updated_by=$9, updated_at=now(), version=version+1
WHERE id=$10 AND version=$11 AND deleted_at IS NULL`,
		in.Name, norm, ipVer, in.Priority, in.ValidityType,
		in.EffectiveFrom, in.EffectiveUntil, in.Reason, updatedBy,
		in.ID, in.Version)
	if err != nil {
		return nil, err
	}
	if res.RowsAffected() == 0 {
		return nil, fmt.Errorf("%w: 规则已被其他人修改，请刷新后重试", ErrVersionConflict)
	}
	return s.GetByID(ctx, in.ID)
}

// SoftDelete 软删除规则（status=DELETED + deleted_at）。
func (s *Store) SoftDelete(ctx context.Context, id, deletedBy uuid.UUID) error {
	res, err := s.db.Exec(ctx, `
UPDATE ip_access_rules SET status=$1, deleted_at=now(), updated_by=$2, updated_at=now(), version=version+1
WHERE id=$3 AND deleted_at IS NULL`, StatusDeleted, deletedBy, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetStatus 设置规则状态（仅 ACTIVE / DISABLED）。
func (s *Store) SetStatus(ctx context.Context, id uuid.UUID, status string, updatedBy uuid.UUID) error {
	if status != StatusActive && status != StatusDisabled {
		return fmt.Errorf("%w: 状态必须为 ACTIVE 或 DISABLED", ErrInvalidInput)
	}
	res, err := s.db.Exec(ctx, `
UPDATE ip_access_rules SET status=$1, updated_by=$2, updated_at=now(), version=version+1
WHERE id=$3 AND deleted_at IS NULL AND status <> $4`, status, updatedBy, id, StatusDeleted)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Extend 延长临时规则失效时间；已过期的规则恢复为 ACTIVE。
func (s *Store) Extend(ctx context.Context, id uuid.UUID, newUntil time.Time, updatedBy uuid.UUID) error {
	res, err := s.db.Exec(ctx, `
UPDATE ip_access_rules SET effective_until=$1,
  status = CASE WHEN status = $2 THEN $3 ELSE status END,
  updated_by=$4, updated_at=now(), version=version+1
WHERE id=$5 AND validity_type=$6 AND deleted_at IS NULL AND status <> $7`,
		newUntil, StatusExpired, StatusActive, updatedBy, id, ValidityTemporary, StatusDeleted)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("%w: 仅临时规则支持延期", ErrInvalidState)
	}
	return nil
}

// Release 立即解封临时规则（status=DISABLED）。
func (s *Store) Release(ctx context.Context, id, releasedBy uuid.UUID) error {
	res, err := s.db.Exec(ctx, `
UPDATE ip_access_rules SET status=$1, updated_by=$2, updated_at=now(), version=version+1
WHERE id=$3 AND validity_type=$4 AND deleted_at IS NULL AND status <> $5`,
		StatusDisabled, releasedBy, id, ValidityTemporary, StatusDeleted)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("%w: 仅临时规则支持解封", ErrInvalidState)
	}
	return nil
}

// IncrementHit 命中计数（供事件采集用）。不更新 updated_at / version，避免高频写放大。
func (s *Store) IncrementHit(ctx context.Context, id uuid.UUID, at time.Time) error {
	res, err := s.db.Exec(ctx, `
UPDATE ip_access_rules SET hit_count = hit_count + 1, last_hit_at = $2
WHERE id = $1 AND deleted_at IS NULL`, id, at)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkExpired 将到期的 ACTIVE 临时规则批量标记为 EXPIRED（调度任务用），返回数量。
// 网关按规则内嵌时间窗已停止执行，此处仅回写管理状态并保留历史。
func (s *Store) MarkExpired(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.Exec(ctx, `
UPDATE ip_access_rules SET status=$1, updated_at=now()
WHERE status=$2 AND validity_type=$3 AND effective_until IS NOT NULL AND effective_until <= $4
  AND deleted_at IS NULL`,
		StatusExpired, StatusActive, ValidityTemporary, now)
	if err != nil {
		return 0, err
	}
	return int(res.RowsAffected()), nil
}

// ApplicationIDByCode 按应用编码查应用 ID（导入 CSV 的 application_code 列解析用）。
func (s *Store) ApplicationIDByCode(ctx context.Context, code string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.db.QueryRow(ctx,
		`SELECT id FROM applications WHERE code = $1 AND deleted_at IS NULL`, code).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrAppNotFound
		}
		return uuid.Nil, err
	}
	return id, nil
}

// ApplicationCodes 批量查询应用 ID → 编码（导出用）。
func (s *Store) ApplicationCodes(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	out := map[uuid.UUID]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(ctx, `SELECT id, code FROM applications WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var code string
		if err := rows.Scan(&id, &code); err != nil {
			return nil, err
		}
		out[id] = code
	}
	return out, rows.Err()
}

func scanRule(row pgx.Row) (*Rule, error) {
	var r Rule
	err := row.Scan(&r.ID, &r.Name, &r.RuleType, &r.ScopeType, &r.ApplicationID, &r.Address,
		&r.IPVersion, &r.Priority, &r.Status, &r.ValidityType, &r.EffectiveFrom, &r.EffectiveUntil,
		&r.Reason, &r.SourceType, &r.SourceEventID, &r.HitCount, &r.LastHitAt,
		&r.CreatedBy, &r.CreatedAt, &r.UpdatedBy, &r.UpdatedAt, &r.Version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &r, nil
}
