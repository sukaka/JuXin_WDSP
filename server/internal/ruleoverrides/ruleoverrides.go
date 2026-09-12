// Package ruleoverrides 提供 CRS/WAF 规则覆盖：策略级/应用级/全局启停。
// 优先级：APPLICATION > POLICY > GLOBAL；发布时对 DISABLE 生成 ctl:ruleRemoveById。
package ruleoverrides

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 作用域与动作
const (
	ScopeGlobal      = "GLOBAL"
	ScopePolicy      = "POLICY"
	ScopeApplication = "APPLICATION"

	ActionDisable = "DISABLE"
	ActionEnable  = "ENABLE"
	// 以下动作可入库，当前发布管线仅对 DISABLE 生效
	ActionSeverityOverride = "SEVERITY_OVERRIDE"
	ActionActionOverride   = "ACTION_OVERRIDE"
)

// 覆盖规则 SecLang 使用的 ctl 规则 ID 段（与自定义 7100000、例外 8000000 区分）
const OverrideSecLangBaseID = 7200000

// 错误
var (
	ErrNotFound     = errors.New("rule override not found")
	ErrInvalidInput = errors.New("invalid rule override")
	ErrConflict     = errors.New("rule override conflict")
)

// Override 规则覆盖。
type Override struct {
	ID               uuid.UUID  `json:"id"`
	RuleID           int        `json:"rule_id"`
	ScopeType        string     `json:"scope_type"`
	ScopeID          *uuid.UUID `json:"scope_id"`
	Action           string     `json:"action"`
	SeverityOverride string     `json:"severity_override"`
	EffectiveFrom    *time.Time `json:"effective_from"`
	EffectiveUntil   *time.Time `json:"effective_until"`
	Reason           string     `json:"reason"`
	CreatedBy        *uuid.UUID `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedBy        *uuid.UUID `json:"updated_by"`
	UpdatedAt        time.Time  `json:"updated_at"`
	Version          int        `json:"version"`
}

// Store 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// ValidateInput 校验创建/更新输入。
func ValidateInput(o *Override) error {
	if o.RuleID <= 0 {
		return fmt.Errorf("%w: rule_id 必须为正整数", ErrInvalidInput)
	}
	switch o.ScopeType {
	case ScopeGlobal:
		o.ScopeID = nil
	case ScopePolicy, ScopeApplication:
		if o.ScopeID == nil || *o.ScopeID == uuid.Nil {
			return fmt.Errorf("%w: %s 范围必须指定 scope_id", ErrInvalidInput, o.ScopeType)
		}
	default:
		return fmt.Errorf("%w: scope_type 必须为 GLOBAL/POLICY/APPLICATION", ErrInvalidInput)
	}
	switch o.Action {
	case ActionDisable, ActionEnable, ActionSeverityOverride, ActionActionOverride:
	default:
		return fmt.Errorf("%w: action 无效", ErrInvalidInput)
	}
	if o.Action == ActionSeverityOverride {
		sev := strings.ToUpper(strings.TrimSpace(o.SeverityOverride))
		switch sev {
		case "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO":
			o.SeverityOverride = sev
		default:
			return fmt.Errorf("%w: severity_override 无效", ErrInvalidInput)
		}
	}
	if len(o.Reason) > 2000 {
		return fmt.Errorf("%w: reason 过长", ErrInvalidInput)
	}
	if o.EffectiveFrom != nil && o.EffectiveUntil != nil && !o.EffectiveUntil.After(*o.EffectiveFrom) {
		return fmt.Errorf("%w: effective_until 必须晚于 effective_from", ErrInvalidInput)
	}
	return nil
}

// active 是否在当前时间生效。
func (o *Override) active(now time.Time) bool {
	if o.EffectiveFrom != nil && now.Before(*o.EffectiveFrom) {
		return false
	}
	if o.EffectiveUntil != nil && !now.Before(*o.EffectiveUntil) {
		return false
	}
	return true
}

// Create 创建覆盖。
func (s *Store) Create(ctx context.Context, o *Override, operator uuid.UUID) error {
	if err := ValidateInput(o); err != nil {
		return err
	}
	// 同 rule_id + scope_type + scope_id 唯一（应用层校验）
	exists, err := s.existsSameScope(ctx, o.RuleID, o.ScopeType, o.ScopeID, uuid.Nil)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: 同范围下该规则已有覆盖，请先删除或更新", ErrConflict)
	}
	o.CreatedBy = &operator
	o.UpdatedBy = &operator
	err = s.db.QueryRow(ctx, `
INSERT INTO rule_overrides (
  rule_id, scope_type, scope_id, action, severity_override,
  effective_from, effective_until, reason, created_by, updated_by
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)
RETURNING id, created_at, updated_at, version`,
		o.RuleID, o.ScopeType, o.ScopeID, o.Action, o.SeverityOverride,
		o.EffectiveFrom, o.EffectiveUntil, o.Reason, operator,
	).Scan(&o.ID, &o.CreatedAt, &o.UpdatedAt, &o.Version)
	return err
}

// Update 更新覆盖（乐观锁）。
func (s *Store) Update(ctx context.Context, o *Override, operator uuid.UUID) error {
	if err := ValidateInput(o); err != nil {
		return err
	}
	exists, err := s.existsSameScope(ctx, o.RuleID, o.ScopeType, o.ScopeID, o.ID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: 同范围下该规则已有其他覆盖", ErrConflict)
	}
	tag, err := s.db.Exec(ctx, `
UPDATE rule_overrides SET
  rule_id=$1, scope_type=$2, scope_id=$3, action=$4, severity_override=$5,
  effective_from=$6, effective_until=$7, reason=$8, updated_by=$9, updated_at=now(), version=version+1
WHERE id=$10 AND version=$11`,
		o.RuleID, o.ScopeType, o.ScopeID, o.Action, o.SeverityOverride,
		o.EffectiveFrom, o.EffectiveUntil, o.Reason, operator, o.ID, o.Version,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	o.Version++
	o.UpdatedBy = &operator
	return nil
}

func (s *Store) existsSameScope(ctx context.Context, ruleID int, scopeType string, scopeID *uuid.UUID, excludeID uuid.UUID) (bool, error) {
	var n int
	var err error
	if scopeID == nil {
		err = s.db.QueryRow(ctx, `
SELECT count(*) FROM rule_overrides
WHERE rule_id=$1 AND scope_type=$2 AND scope_id IS NULL AND id <> $3`,
			ruleID, scopeType, excludeID).Scan(&n)
	} else {
		err = s.db.QueryRow(ctx, `
SELECT count(*) FROM rule_overrides
WHERE rule_id=$1 AND scope_type=$2 AND scope_id=$3 AND id <> $4`,
			ruleID, scopeType, *scopeID, excludeID).Scan(&n)
	}
	return n > 0, err
}

// GetByID 查询。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Override, error) {
	row := s.db.QueryRow(ctx, `
SELECT id, rule_id, scope_type, scope_id, action, severity_override,
  effective_from, effective_until, reason, created_by, created_at, updated_by, updated_at, version
FROM rule_overrides WHERE id=$1`, id)
	return scanOverride(row)
}

// Delete 删除。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM rule_overrides WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListFilter 列表筛选。
type ListFilter struct {
	RuleID    int
	ScopeType string
	ScopeID   *uuid.UUID
	Action    string
	Page      int
	PageSize  int
}

// List 分页列表。
func (s *Store) List(ctx context.Context, f ListFilter) ([]Override, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where := "1=1"
	args := []interface{}{}
	arg := 1
	if f.RuleID > 0 {
		where += fmt.Sprintf(" AND rule_id = $%d", arg)
		args = append(args, f.RuleID)
		arg++
	}
	if f.ScopeType != "" {
		where += fmt.Sprintf(" AND scope_type = $%d", arg)
		args = append(args, f.ScopeType)
		arg++
	}
	if f.ScopeID != nil {
		where += fmt.Sprintf(" AND scope_id = $%d", arg)
		args = append(args, *f.ScopeID)
		arg++
	}
	if f.Action != "" {
		where += fmt.Sprintf(" AND action = $%d", arg)
		args = append(args, f.Action)
		arg++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM rule_overrides WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `
SELECT id, rule_id, scope_type, scope_id, action, severity_override,
  effective_from, effective_until, reason, created_by, created_at, updated_by, updated_at, version
FROM rule_overrides WHERE ` + where + fmt.Sprintf(" ORDER BY rule_id, scope_type, created_at DESC LIMIT $%d OFFSET $%d", arg, arg+1)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Override
	for rows.Next() {
		o, err := scanOverrideRows(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *o)
	}
	if out == nil {
		out = []Override{}
	}
	return out, total, rows.Err()
}

// ListActiveForPublish 返回当前生效的覆盖（供发布解析）。
func (s *Store) ListActiveForPublish(ctx context.Context) ([]Override, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, rule_id, scope_type, scope_id, action, severity_override,
  effective_from, effective_until, reason, created_by, created_at, updated_by, updated_at, version
FROM rule_overrides
ORDER BY rule_id, scope_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now().UTC()
	var out []Override
	for rows.Next() {
		o, err := scanOverrideRows(rows)
		if err != nil {
			return nil, err
		}
		if o.active(now) {
			out = append(out, *o)
		}
	}
	if out == nil {
		out = []Override{}
	}
	return out, rows.Err()
}

// ResolveDisableRuleIDs 对指定应用解析最终应 DISABLE 的 CRS 规则 ID。
// 优先级：APPLICATION > POLICY > GLOBAL；ENABLE 覆盖同层/下层的 DISABLE。
func ResolveDisableRuleIDs(all []Override, appID uuid.UUID, policyID *uuid.UUID) []int {
	type winner struct {
		prio   int // 3 app, 2 policy, 1 global
		action string
	}
	best := map[int]winner{}
	prioOf := func(scope string) int {
		switch scope {
		case ScopeApplication:
			return 3
		case ScopePolicy:
			return 2
		case ScopeGlobal:
			return 1
		}
		return 0
	}
	for _, o := range all {
		switch o.ScopeType {
		case ScopeGlobal:
			// ok
		case ScopePolicy:
			if policyID == nil || o.ScopeID == nil || *o.ScopeID != *policyID {
				continue
			}
		case ScopeApplication:
			if o.ScopeID == nil || *o.ScopeID != appID {
				continue
			}
		default:
			continue
		}
		p := prioOf(o.ScopeType)
		if cur, ok := best[o.RuleID]; ok && cur.prio > p {
			continue
		}
		if cur, ok := best[o.RuleID]; ok && cur.prio == p {
			// 同层后写覆盖前写（列表顺序）；这里后到者覆盖
		}
		best[o.RuleID] = winner{prio: p, action: o.Action}
	}
	var ids []int
	for rid, w := range best {
		if w.action == ActionDisable {
			ids = append(ids, rid)
		}
	}
	// 确定性排序
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			if ids[j] < ids[i] {
				ids[i], ids[j] = ids[j], ids[i]
			}
		}
	}
	return ids
}

// SecLangForApp 实现 gatewayconfig.RuleOverridesProvider：解析并生成该应用的 DISABLE SecLang。
func (s *Store) SecLangForApp(ctx context.Context, appID uuid.UUID, policyID *uuid.UUID) ([]string, error) {
	all, err := s.ListActiveForPublish(ctx)
	if err != nil {
		return nil, err
	}
	ids := ResolveDisableRuleIDs(all, appID, policyID)
	return BuildDisableSecLang(ids), nil
}

// BuildDisableSecLang 生成 DISABLE 覆盖的 SecLang 列表（确定性）。
func BuildDisableSecLang(ruleIDs []int) []string {
	if len(ruleIDs) == 0 {
		return nil
	}
	out := make([]string, 0, len(ruleIDs))
	for i, rid := range ruleIDs {
		ctlID := OverrideSecLangBaseID + 1 + i
		// phase:1 在 CRS 前注入；unconditional 用 URI 匹配全部
		line := fmt.Sprintf(
			`SecRule REQUEST_URI "@rx .*" "id:%d,phase:1,pass,nolog,ctl:ruleRemoveById=%d,tag:'jiuzhang-rule-override'"`,
			ctlID, rid,
		)
		out = append(out, line)
	}
	return out
}

func scanOverride(row pgx.Row) (*Override, error) {
	var o Override
	err := row.Scan(
		&o.ID, &o.RuleID, &o.ScopeType, &o.ScopeID, &o.Action, &o.SeverityOverride,
		&o.EffectiveFrom, &o.EffectiveUntil, &o.Reason, &o.CreatedBy, &o.CreatedAt,
		&o.UpdatedBy, &o.UpdatedAt, &o.Version,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &o, nil
}

func scanOverrideRows(rows pgx.Rows) (*Override, error) {
	var o Override
	err := rows.Scan(
		&o.ID, &o.RuleID, &o.ScopeType, &o.ScopeID, &o.Action, &o.SeverityOverride,
		&o.EffectiveFrom, &o.EffectiveUntil, &o.Reason, &o.CreatedBy, &o.CreatedAt,
		&o.UpdatedBy, &o.UpdatedAt, &o.Version,
	)
	if err != nil {
		return nil, err
	}
	return &o, nil
}
