package urlwhitelists

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store 是 URL 白名单规则仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

const ruleColumns = `id, name, scope_type, application_id, match_type, uri_pattern, methods,
priority, status, validity_type, effective_from, effective_until, reason, source_type,
source_event_id, hit_count, last_hit_at, created_by, created_at, updated_by, updated_at, version`

type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
}

func prepareRule(in CreateInput, now time.Time) (*Rule, error) {
	if err := ValidateInput(&in, now); err != nil {
		return nil, err
	}
	if in.Priority == 0 {
		in.Priority = 100
	}
	return &Rule{
		Name:           in.Name,
		ScopeType:      in.ScopeType,
		ApplicationID:  in.ApplicationID,
		MatchType:      in.MatchType,
		URIPattern:     in.URIPattern,
		Methods:        in.Methods,
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

// Create 创建规则（默认 ACTIVE）。
func (s *Store) Create(ctx context.Context, in CreateInput, createdBy uuid.UUID) (*Rule, error) {
	r, err := prepareRule(in, time.Now())
	if err != nil {
		return nil, err
	}
	ok, err := conflictExists(ctx, s.db, r.ScopeType, r.ApplicationID, r.MatchType, r.URIPattern, nil)
	if err != nil {
		return nil, err
	}
	if ok {
		return nil, fmt.Errorf("%w: 相同范围下已存在 %s 路径 %s 的 URL 白名单规则", ErrConflict, r.MatchType, r.URIPattern)
	}
	err = s.db.QueryRow(ctx, `
INSERT INTO url_whitelist_rules (name, scope_type, application_id, match_type, uri_pattern, methods,
  priority, status, validity_type, effective_from, effective_until, reason, source_type,
  source_event_id, created_by, updated_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15)
RETURNING id, created_at, updated_at, version`,
		r.Name, r.ScopeType, r.ApplicationID, r.MatchType, r.URIPattern, r.Methods,
		r.Priority, r.Status, r.ValidityType, r.EffectiveFrom, r.EffectiveUntil, r.Reason,
		r.SourceType, r.SourceEventID, createdBy,
	).Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt, &r.Version)
	if err != nil {
		return nil, mapPGError(err)
	}
	return r, nil
}

func conflictExists(ctx context.Context, q rowQuerier, scopeType string, appID *uuid.UUID, matchType, uriPattern string, excludeID *uuid.UUID) (bool, error) {
	query := `SELECT count(*) FROM url_whitelist_rules
WHERE deleted_at IS NULL AND scope_type = $1 AND application_id IS NOT DISTINCT FROM $2
  AND match_type = $3 AND uri_pattern = $4`
	args := []interface{}{scopeType, appID, matchType, uriPattern}
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

// GetByID 查询规则详情（不含已删除）。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Rule, error) {
	row := s.db.QueryRow(ctx, `SELECT `+ruleColumns+` FROM url_whitelist_rules WHERE id = $1 AND deleted_at IS NULL`, id)
	return scanRule(row)
}

// List 分页查询规则。
func (s *Store) List(ctx context.Context, f ListFilter) ([]Rule, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	if f.PageSize > 10000 {
		f.PageSize = 10000
	}
	where := []string{"deleted_at IS NULL"}
	var args []interface{}
	add := func(cond string, val interface{}) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.ScopeType != "" {
		add("scope_type = $%d", strings.ToUpper(f.ScopeType))
	}
	if f.ApplicationID != nil {
		add("application_id = $%d", *f.ApplicationID)
	}
	if f.MatchType != "" {
		add("match_type = $%d", strings.ToUpper(f.MatchType))
	}
	if f.Status != "" {
		add("status = $%d", strings.ToUpper(f.Status))
	}
	if f.SourceType != "" {
		add("source_type = $%d", strings.ToUpper(f.SourceType))
	}
	if f.Keyword != "" {
		kw := "%" + strings.TrimSpace(f.Keyword) + "%"
		args = append(args, kw)
		where = append(where, fmt.Sprintf("(name ILIKE $%d OR uri_pattern ILIKE $%d)", len(args), len(args)))
	}
	wClause := "WHERE " + strings.Join(where, " AND ")

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM url_whitelist_rules `+wClause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	q := fmt.Sprintf(`SELECT %s FROM url_whitelist_rules %s ORDER BY priority ASC, created_at DESC LIMIT $%d OFFSET $%d`,
		ruleColumns, wClause, len(args)-1, len(args))
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *r)
	}
	return out, total, rows.Err()
}

// Update 更新规则（乐观锁）。
func (s *Store) Update(ctx context.Context, in UpdateInput, updatedBy uuid.UUID) (*Rule, error) {
	if err := validateUpdateInput(&in, time.Now()); err != nil {
		return nil, err
	}
	cur, err := s.GetByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if cur.Version != in.Version {
		return nil, ErrVersionConflict
	}
	ok, err := conflictExists(ctx, s.db, cur.ScopeType, cur.ApplicationID, in.MatchType, in.URIPattern, &cur.ID)
	if err != nil {
		return nil, err
	}
	if ok {
		return nil, fmt.Errorf("%w: 相同范围下已存在 %s 路径 %s 的 URL 白名单规则", ErrConflict, in.MatchType, in.URIPattern)
	}
	row := s.db.QueryRow(ctx, `
UPDATE url_whitelist_rules
SET name=$1, match_type=$2, uri_pattern=$3, methods=$4, priority=$5,
    validity_type=$6, effective_from=$7, effective_until=$8, reason=$9,
    updated_by=$10, updated_at=now(), version=version+1
WHERE id=$11 AND version=$12 AND deleted_at IS NULL
RETURNING `+ruleColumns,
		in.Name, in.MatchType, in.URIPattern, in.Methods, in.Priority,
		in.ValidityType, in.EffectiveFrom, in.EffectiveUntil, in.Reason,
		updatedBy, in.ID, in.Version,
	)
	r, err := scanRule(row)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrVersionConflict
	}
	return r, err
}

// SoftDelete 软删除规则。
func (s *Store) SoftDelete(ctx context.Context, id, operatorID uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `
UPDATE url_whitelist_rules
SET status=$1, deleted_at=now(), updated_by=$2, updated_at=now(), version=version+1
WHERE id=$3 AND deleted_at IS NULL`, StatusDeleted, operatorID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetStatus 切换规则状态（ACTIVE/DISABLED/EXPIRED）。
func (s *Store) SetStatus(ctx context.Context, id uuid.UUID, status string, operatorID uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `
UPDATE url_whitelist_rules
SET status=$1, updated_by=$2, updated_at=now(), version=version+1
WHERE id=$3 AND deleted_at IS NULL`, status, operatorID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Extend 延长临时规则失效时间（已过期规则延期后自动恢复为 ACTIVE）。
func (s *Store) Extend(ctx context.Context, id uuid.UUID, until time.Time, operatorID uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `
UPDATE url_whitelist_rules
SET effective_until=$1,
    status = CASE WHEN status = 'EXPIRED' THEN 'ACTIVE' ELSE status END,
    updated_by=$2, updated_at=now(), version=version+1
WHERE id=$3 AND deleted_at IS NULL`, until, operatorID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkExpired 将已到期的 ACTIVE 临时规则批量标为 EXPIRED（供 guardjanitor 调用）。
func (s *Store) MarkExpired(ctx context.Context, now time.Time) (int, error) {
	tag, err := s.db.Exec(ctx, `
UPDATE url_whitelist_rules
SET status=$1, updated_at=now(), version=version+1
WHERE deleted_at IS NULL AND status=$2 AND validity_type=$3
  AND effective_until IS NOT NULL AND effective_until <= $4`,
		StatusExpired, StatusActive, ValidityTemporary, now)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// IncrementHit 累加命中计数与最近命中时间（供访问控制事件采集器回调）。
func (s *Store) IncrementHit(ctx context.Context, id uuid.UUID, hitAt time.Time) error {
	_, err := s.db.Exec(ctx, `
UPDATE url_whitelist_rules
SET hit_count = hit_count + 1,
    last_hit_at = GREATEST(COALESCE(last_hit_at, $2), $2)
WHERE id = $1 AND deleted_at IS NULL`, id, hitAt)
	return err
}

// EventExists 检查来源安全事件是否存在。
func (s *Store) EventExists(ctx context.Context, id uuid.UUID) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM security_events WHERE id = $1)`, id).Scan(&ok)
	return ok, err
}

// ApplicationCodes 批量解析应用 ID → 编码（供 guardconfig 发布组装）。
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

// ExistingMatch 用于安全事件白名单预填检查是否已有同路径 URL 白名单。
type ExistingMatch struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	MatchType  string    `json:"match_type"`
	URIPattern string    `json:"uri_pattern"`
	Status     string    `json:"status"`
}

// FindExistingForPath 查找同路径（精确匹配或同模式）已存在的 URL 白名单（全局或指定应用）。
func (s *Store) FindExistingForPath(ctx context.Context, pathStr string, appID *uuid.UUID) (*ExistingMatch, error) {
	if pathStr == "" {
		return nil, nil
	}
	var m ExistingMatch
	err := s.db.QueryRow(ctx, `
SELECT id, name, match_type, uri_pattern, status
FROM url_whitelist_rules
WHERE deleted_at IS NULL AND status IN ('ACTIVE', 'DRAFT')
  AND uri_pattern = $1
  AND (scope_type = 'GLOBAL' OR ($2::uuid IS NOT NULL AND application_id = $2::uuid))
ORDER BY created_at DESC LIMIT 1`, pathStr, appID).
		Scan(&m.ID, &m.Name, &m.MatchType, &m.URIPattern, &m.Status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &m, nil
}

func scanRule(row pgx.Row) (*Rule, error) {
	var r Rule
	err := row.Scan(
		&r.ID, &r.Name, &r.ScopeType, &r.ApplicationID, &r.MatchType, &r.URIPattern, &r.Methods,
		&r.Priority, &r.Status, &r.ValidityType, &r.EffectiveFrom, &r.EffectiveUntil,
		&r.Reason, &r.SourceType, &r.SourceEventID, &r.HitCount, &r.LastHitAt,
		&r.CreatedBy, &r.CreatedAt, &r.UpdatedBy, &r.UpdatedAt, &r.Version,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if r.Methods == nil {
		r.Methods = []string{}
	}
	return &r, nil
}

func mapPGError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrAppNotFound
	}
	return err
}
