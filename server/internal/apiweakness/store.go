// store.go 弱点仓储：Repository 接口（SQL 与内存实现共用，便于诚实单测）+ PostgreSQL 实现。
package apiweakness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ListFilter 弱点列表过滤（Status/Severity/Category 大小写已归一，EndpointID 已解析）。
type ListFilter struct {
	Status     string
	Severity   string
	Category   string
	EndpointID *uuid.UUID
	Page       int
	PageSize   int
}

// DerivedInput 派生扫描一次命中输入（Evidence 只含脱敏摘要：规则/计数/窗口）。
type DerivedInput struct {
	EndpointID   uuid.UUID
	WeaknessCode string
	WeaknessName string
	Category     string
	Severity     string
	Evidence     json.RawMessage
	Now          time.Time
}

// UpsertResult 派生 upsert 结果。
type UpsertResult struct {
	ID         uuid.UUID
	Inserted   bool // 首次发现（状态 NEW）
	Reproduced bool // 原为 FIXED，本次命中回到 REPRODUCED
}

// Repository 弱点仓储（SQL 与内存实现共用）。
type Repository interface {
	// 查询
	List(ctx context.Context, f ListFilter) ([]Weakness, int64, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Weakness, error)
	ListActions(ctx context.Context, weaknessID uuid.UUID, page, pageSize int) ([]WeaknessAction, int64, error)
	// 生命周期流转（校验状态机 + 更新 + 动作历史，一个事务；非法迁移返回 ErrInvalidTransition）
	Transition(ctx context.Context, id uuid.UUID, action string, in TransitionInput) (*Weakness, error)
	// 派生 upsert（SweepOnce 写入方；同端点同码 trigger_count++/last_seen，FIXED 再触发回 REPRODUCED）
	UpsertDerived(ctx context.Context, in DerivedInput) (UpsertResult, error)
}

// 确保 *Store / *MemStore 实现 Repository。
var (
	_ Repository = (*Store)(nil)
	_ Repository = (*MemStore)(nil)
)

// Store 弱点 PostgreSQL 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// weaknessCols 弱点查询列（w 别名；endpoint_key 由 JOIN 带出）。
const weaknessCols = `
w.id, w.endpoint_id, COALESCE(e.endpoint_key, ''), w.weakness_code, w.weakness_name, w.category,
w.severity, w.status, w.evidence_json, w.first_seen, w.last_seen, w.trigger_count, w.owner,
w.due_date, w.fixed_at, w.retested_at, w.created_at, w.updated_at`

// scanWeakness 扫描一行弱点。
func scanWeakness(row pgx.Row) (*Weakness, error) {
	var w Weakness
	err := row.Scan(&w.ID, &w.EndpointID, &w.EndpointKey, &w.WeaknessCode, &w.WeaknessName, &w.Category,
		&w.Severity, &w.Status, &w.Evidence, &w.FirstSeen, &w.LastSeen, &w.TriggerCount, &w.Owner,
		&w.DueDate, &w.FixedAt, &w.RetestedAt, &w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &w, nil
}

// List 弱点分页列表（过滤条件白名单拼接，值一律参数化；按 last_seen 倒序）。
func (s *Store) List(ctx context.Context, f ListFilter) ([]Weakness, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	where := []string{}
	args := []any{}
	if f.Status != "" {
		args = append(args, f.Status)
		where = append(where, fmt.Sprintf("w.status = $%d", len(args)))
	}
	if f.Severity != "" {
		args = append(args, f.Severity)
		where = append(where, fmt.Sprintf("w.severity = $%d", len(args)))
	}
	if f.Category != "" {
		args = append(args, f.Category)
		where = append(where, fmt.Sprintf("w.category = $%d", len(args)))
	}
	if f.EndpointID != nil {
		args = append(args, *f.EndpointID)
		where = append(where, fmt.Sprintf("w.endpoint_id = $%d", len(args)))
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_weaknesses w"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `
SELECT `+weaknessCols+`
FROM api_weaknesses w
LEFT JOIN api_endpoints e ON e.id = w.endpoint_id`+cond+
		fmt.Sprintf(" ORDER BY w.last_seen DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Weakness{}
	for rows.Next() {
		w, err := scanWeakness(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *w)
	}
	return out, total, rows.Err()
}

// GetByID 弱点详情（不存在返回 ErrNotFound）。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Weakness, error) {
	w, err := scanWeakness(s.db.QueryRow(ctx, `
SELECT `+weaknessCols+`
FROM api_weaknesses w
LEFT JOIN api_endpoints e ON e.id = w.endpoint_id
WHERE w.id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return w, nil
}

// ListActions 整改/复测历史分页（created_at 倒序）。
func (s *Store) ListActions(ctx context.Context, weaknessID uuid.UUID, page, pageSize int) ([]WeaknessAction, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	var total int64
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM api_weakness_actions WHERE weakness_id = $1`, weaknessID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `
SELECT id, weakness_id, action, actor, note, created_at
FROM api_weakness_actions WHERE weakness_id = $1
ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`, weaknessID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []WeaknessAction{}
	for rows.Next() {
		var a WeaknessAction
		if err := rows.Scan(&a.ID, &a.WeaknessID, &a.Action, &a.Actor, &a.Note, &a.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// Transition 生命周期流转：行锁读当前状态 → 状态机校验 → 更新 → 动作历史，一个事务。
func (s *Store) Transition(ctx context.Context, id uuid.UUID, action string, in TransitionInput) (*Weakness, error) {
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var from string
	err = tx.QueryRow(ctx, `SELECT status FROM api_weaknesses WHERE id = $1 FOR UPDATE`, id).Scan(&from)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	to, ok := ResolveTransition(action, from)
	if !ok {
		return nil, fmt.Errorf("%w: %s 状态不允许 %s", ErrInvalidTransition, from, action)
	}

	// 各动作的副作用字段（assign 写负责人/期限，fixed/retest 写时间戳）
	args := []any{to, in.Now}
	setExtra := ""
	switch action {
	case ActionAssign:
		setExtra = ", owner = $3, due_date = $4"
		args = append(args, in.Owner, in.DueDate)
	case ActionMarkFixed:
		setExtra = ", fixed_at = $2"
	case ActionRetestPass, ActionRetestFail:
		setExtra = ", retested_at = $2"
	}
	args = append(args, id)
	ct, err := tx.Exec(ctx, `
UPDATE api_weaknesses SET status = $1, updated_at = $2`+setExtra+
		fmt.Sprintf(" WHERE id = $%d", len(args)), args...)
	if err != nil {
		return nil, err
	}
	if ct.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO api_weakness_actions (weakness_id, action, actor, note) VALUES ($1, $2, $3, $4)`,
		id, action, in.Actor, in.Note); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetByID(ctx, id)
}

// UpsertDerived 派生 upsert：同端点同码存在则 trigger_count+1/last_seen/证据刷新，
// 原 FIXED 状态回 REPRODUCED（写 REPRODUCED 历史）；不存在则按 NEW 新建（写 DERIVED 历史）。
// IGNORED / ARCHIVED 不复活（只累计数与证据），由人工另行处置。
func (s *Store) UpsertDerived(ctx context.Context, in DerivedInput) (UpsertResult, error) {
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return UpsertResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id uuid.UUID
	var status string
	err = tx.QueryRow(ctx, `
SELECT id, status FROM api_weaknesses
WHERE endpoint_id = $1 AND weakness_code = $2 FOR UPDATE`, in.EndpointID, in.WeaknessCode).Scan(&id, &status)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// 首次发现
		err = tx.QueryRow(ctx, `
INSERT INTO api_weaknesses (endpoint_id, weakness_code, weakness_name, category, severity, status, evidence_json, first_seen, last_seen)
VALUES ($1, $2, $3, $4, $5, 'NEW', $6, $7, $7)
RETURNING id`, in.EndpointID, in.WeaknessCode, in.WeaknessName, in.Category, in.Severity, in.Evidence, in.Now).Scan(&id)
		if err != nil {
			return UpsertResult{}, err
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO api_weakness_actions (weakness_id, action, actor, note) VALUES ($1, $2, 'system', $3)`,
			id, ActionDerived, "派生扫描发现"); err != nil {
			return UpsertResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return UpsertResult{}, err
		}
		return UpsertResult{ID: id, Inserted: true}, nil
	case err != nil:
		return UpsertResult{}, err
	}

	// 已存在：计数 +1、刷新证据；FIXED 再触发回 REPRODUCED
	reproduced := status == StatusFixed
	newStatus := status
	if reproduced {
		newStatus = StatusReproduced
	}
	if _, err := tx.Exec(ctx, `
UPDATE api_weaknesses
SET trigger_count = trigger_count + 1, last_seen = $2, evidence_json = $3, status = $4, updated_at = $2
WHERE id = $1`, id, in.Now, in.Evidence, newStatus); err != nil {
		return UpsertResult{}, err
	}
	if reproduced {
		if _, err := tx.Exec(ctx, `
INSERT INTO api_weakness_actions (weakness_id, action, actor, note) VALUES ($1, $2, 'system', $3)`,
			id, ActionReproduced, "整改后再次被扫描命中"); err != nil {
			return UpsertResult{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return UpsertResult{}, err
	}
	return UpsertResult{ID: id, Reproduced: reproduced}, nil
}
