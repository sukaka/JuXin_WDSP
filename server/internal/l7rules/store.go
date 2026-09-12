package l7rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/accesscontrolevents"
)

// Store 是 L7 访问控制规则仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

const ruleColumns = `id, name, priority, enabled, conditions, action, action_config, created_by, created_at, updated_by, updated_at`

// Create 创建规则（校验 + 总数上限 500）。
func (s *Store) Create(ctx context.Context, in RuleInput, createdBy uuid.UUID) (*Rule, error) {
	if err := ValidateInput(&in); err != nil {
		return nil, err
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM l7_access_rules`).Scan(&total); err != nil {
		return nil, err
	}
	if total >= MaxRules {
		return nil, fmt.Errorf("%w: 规则总数已达上限%d条", ErrTooManyRules, MaxRules)
	}
	conds, err := json.Marshal(in.Conditions)
	if err != nil {
		return nil, err
	}
	cfg, err := json.Marshal(in.ActionConfig)
	if err != nil {
		return nil, err
	}
	r := &Rule{
		Name:         in.Name,
		Priority:     in.Priority,
		Enabled:      in.Enabled,
		Conditions:   in.Conditions,
		Action:       in.Action,
		ActionConfig: in.ActionConfig,
	}
	err = s.db.QueryRow(ctx, `
INSERT INTO l7_access_rules (name, priority, enabled, conditions, action, action_config, created_by, updated_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
RETURNING id, created_at, updated_at`,
		in.Name, in.Priority, in.Enabled, conds, in.Action, cfg, createdBy,
	).Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	r.CreatedBy = &createdBy
	r.UpdatedBy = &createdBy
	return r, nil
}

// GetByID 查询规则。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Rule, error) {
	row := s.db.QueryRow(ctx, `SELECT `+ruleColumns+` FROM l7_access_rules WHERE id = $1`, id)
	return scanRule(row)
}

// List 分页查询规则（按 priority 升序、created_at 升序，与评估顺序一致）。
func (s *Store) List(ctx context.Context, f ListFilter) ([]Rule, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where := "1=1"
	args := []interface{}{}
	argIdx := 1
	if f.Keyword != "" {
		where += fmt.Sprintf(" AND name ILIKE $%d", argIdx)
		args = append(args, "%"+f.Keyword+"%")
		argIdx++
	}
	if f.Enabled != nil {
		where += fmt.Sprintf(" AND enabled = $%d", argIdx)
		args = append(args, *f.Enabled)
		argIdx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM l7_access_rules WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + ruleColumns + ` FROM l7_access_rules WHERE ` + where +
		fmt.Sprintf(" ORDER BY priority ASC, created_at ASC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
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

// Update 全量更新规则（名称/优先级/启停/条件/动作）。
func (s *Store) Update(ctx context.Context, id uuid.UUID, in RuleInput, updatedBy uuid.UUID) (*Rule, error) {
	if err := ValidateInput(&in); err != nil {
		return nil, err
	}
	conds, err := json.Marshal(in.Conditions)
	if err != nil {
		return nil, err
	}
	cfg, err := json.Marshal(in.ActionConfig)
	if err != nil {
		return nil, err
	}
	res, err := s.db.Exec(ctx, `
UPDATE l7_access_rules SET name=$1, priority=$2, enabled=$3, conditions=$4, action=$5, action_config=$6,
  updated_by=$7, updated_at=now()
WHERE id=$8`,
		in.Name, in.Priority, in.Enabled, conds, in.Action, cfg, updatedBy, id)
	if err != nil {
		return nil, err
	}
	if res.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.GetByID(ctx, id)
}

// Delete 删除规则（硬删除；删除前摘要由 handler 写操作审计）。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.Exec(ctx, `DELETE FROM l7_access_rules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListAllOrdered 查询全部规则（含停用），按 (priority, created_at) 升序。
// 供发布载荷组装与规则测试器使用。
func (s *Store) ListAllOrdered(ctx context.Context) ([]Rule, error) {
	rows, err := s.db.Query(ctx, `SELECT `+ruleColumns+` FROM l7_access_rules ORDER BY priority ASC, created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// HitCounts24h 聚合近 24h 各规则命中数（L7_RULE_* 事件，按 access_rule_id 分组）。
func (s *Store) HitCounts24h(ctx context.Context, ids []uuid.UUID, since time.Time) (map[uuid.UUID]int64, error) {
	out := map[uuid.UUID]int64{}
	if len(ids) == 0 {
		return out, nil
	}
	strs := make([]string, 0, len(ids))
	for _, id := range ids {
		strs = append(strs, id.String())
	}
	rows, err := s.db.Query(ctx, `
SELECT access_rule_id, count(*) FROM access_control_events
WHERE access_rule_id = ANY($1) AND event_type = ANY($2) AND occurred_at >= $3
GROUP BY access_rule_id`,
		strs, accesscontrolevents.L7RuleEventTypes, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ruleID string
		var n int64
		if err := rows.Scan(&ruleID, &n); err != nil {
			return nil, err
		}
		if id, err := uuid.Parse(ruleID); err == nil {
			out[id] = n
		}
	}
	return out, rows.Err()
}

func scanRule(row pgx.Row) (*Rule, error) {
	var r Rule
	var conds, cfg []byte
	err := row.Scan(&r.ID, &r.Name, &r.Priority, &r.Enabled, &conds, &r.Action, &cfg,
		&r.CreatedBy, &r.CreatedAt, &r.UpdatedBy, &r.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal(conds, &r.Conditions); err != nil {
		return nil, fmt.Errorf("decode conditions of rule %s: %w", r.ID, err)
	}
	if err := json.Unmarshal(cfg, &r.ActionConfig); err != nil {
		return nil, fmt.Errorf("decode action_config of rule %s: %w", r.ID, err)
	}
	return &r, nil
}
