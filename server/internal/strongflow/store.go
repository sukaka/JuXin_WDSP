// store.go 强流程定义 PostgreSQL 仓储：CRUD + 版本冻结语义（D1）+ activate 前
// 端点归属核对（绑定前缀下已 CONFIRMED）。写路径全部事务化（整体替换步骤/激活
// 同事务 RETIRED 旧 ACTIVE——不留中间态）。
package strongflow

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

// Store 强流程定义仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

const definitionCols = `id, application_id, name, version, status, binding_path_prefix,
	instance_key_param, mode, COALESCE(created_by_name,''), created_at, activated_at`

func scanDefinition(row pgx.Row) (Definition, error) {
	var d Definition
	err := row.Scan(&d.ID, &d.ApplicationID, &d.Name, &d.Version, &d.Status,
		&d.BindingPathPrefix, &d.InstanceKeyParam, &d.Mode, &d.CreatedByName, &d.CreatedAt, &d.ActivatedAt)
	return d, err
}

// Create 新建定义：同（应用,名称）不存在 → version=1；已存在 → version=max+1
// 新草稿（D1「编辑产新草稿」承载：同名再创即版本递进；DRAFT 间互不冻结）。
func (s *Store) Create(ctx context.Context, in DefinitionInput, operatorID uuid.UUID, operatorName string) (*DefinitionDetail, error) {
	if msg := validateDefinitionInput(in); msg != "" {
		return nil, &ValidationError{Msg: msg}
	}
	appID, _ := uuid.Parse(strings.TrimSpace(in.ApplicationID))
	mode := strings.ToUpper(strings.TrimSpace(in.Mode))
	if mode == "" {
		mode = ModeObserve
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var version int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0)+1 FROM api_strong_flow_definitions
		WHERE application_id=$1 AND name=$2`, appID, strings.TrimSpace(in.Name)).Scan(&version); err != nil {
		return nil, err
	}
	var d Definition
	if err := tx.QueryRow(ctx, `INSERT INTO api_strong_flow_definitions
		(application_id, name, version, binding_path_prefix, instance_key_param, mode, created_by, created_by_name)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+definitionCols,
		appID, strings.TrimSpace(in.Name), version, strings.TrimSpace(in.BindingPathPrefix),
		strings.TrimSpace(in.InstanceKeyParam), mode, operatorID, operatorName).Scan(
		&d.ID, &d.ApplicationID, &d.Name, &d.Version, &d.Status, &d.BindingPathPrefix,
		&d.InstanceKeyParam, &d.Mode, &d.CreatedByName, &d.CreatedAt, &d.ActivatedAt); err != nil {
		return nil, err
	}
	if err := replaceSteps(ctx, tx, d.ID, in.Steps); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &DefinitionDetail{Definition: d, Steps: in.Steps}, nil
}

// replaceSteps 整体替换步骤（事务内；调用方已完成载荷校验）。
func replaceSteps(ctx context.Context, tx pgx.Tx, definitionID uuid.UUID, steps []StepInput) error {
	if _, err := tx.Exec(ctx, `DELETE FROM api_strong_flow_steps WHERE definition_id=$1`, definitionID); err != nil {
		return err
	}
	for _, st := range steps {
		rule, err := json.Marshal(st.SuccessRule)
		if err != nil {
			return fmt.Errorf("marshal success_rule: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO api_strong_flow_steps
			(definition_id, step_key, endpoint_key, sequence, success_rule, timeout_seconds,
			 retry_semantics, parallel_group, lease_seconds, allows_202)
			VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10)`,
			definitionID, strings.TrimSpace(st.StepKey), strings.TrimSpace(st.EndpointKey),
			st.Sequence, rule, st.TimeoutSeconds, strings.ToUpper(strings.TrimSpace(st.RetrySemantics)),
			strings.TrimSpace(st.ParallelGroup), st.LeaseSeconds, st.Allows202); err != nil {
			return err
		}
	}
	return nil
}

// List 定义分页列表（application_id/status 过滤；名称+版本倒序）。
func (s *Store) List(ctx context.Context, applicationID uuid.UUID, status string, page, pageSize int) ([]Definition, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	where, args := []string{}, []any{}
	if applicationID != uuid.Nil {
		args = append(args, applicationID)
		where = append(where, fmt.Sprintf("application_id = $%d", len(args)))
	}
	if status != "" {
		args = append(args, status)
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_strong_flow_definitions"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `SELECT `+definitionCols+` FROM api_strong_flow_definitions`+cond+
		fmt.Sprintf(" ORDER BY name, version DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Definition{}
	for rows.Next() {
		d, err := scanDefinition(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, d)
	}
	return out, total, rows.Err()
}

// Get 按 ID 读定义+步骤。
func (s *Store) Get(ctx context.Context, id uuid.UUID) (*DefinitionDetail, error) {
	d, err := scanDefinition(s.db.QueryRow(ctx, `SELECT `+definitionCols+` FROM api_strong_flow_definitions WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	steps, err := s.listSteps(ctx, id)
	if err != nil {
		return nil, err
	}
	return &DefinitionDetail{Definition: d, Steps: steps}, nil
}

func (s *Store) listSteps(ctx context.Context, id uuid.UUID) ([]StepInput, error) {
	rows, err := s.db.Query(ctx, `SELECT step_key, endpoint_key, sequence, success_rule,
		timeout_seconds, retry_semantics, parallel_group, lease_seconds, allows_202
	FROM api_strong_flow_steps WHERE definition_id=$1 ORDER BY sequence`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StepInput{}
	for rows.Next() {
		var st StepInput
		var rule []byte
		if err := rows.Scan(&st.StepKey, &st.EndpointKey, &st.Sequence, &rule,
			&st.TimeoutSeconds, &st.RetrySemantics, &st.ParallelGroup, &st.LeaseSeconds, &st.Allows202); err != nil {
			return nil, err
		}
		st.SuccessRule = &SuccessRule{}
		if err := json.Unmarshal(rule, st.SuccessRule); err != nil {
			return nil, fmt.Errorf("decode success_rule: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// Update 编辑定义（整体替换步骤；仅 DRAFT——激活即冻结，ACTIVE/RETIRED ErrNotDraft）。
func (s *Store) Update(ctx context.Context, id uuid.UUID, in DefinitionInput) (*DefinitionDetail, error) {
	if msg := validateDefinitionInput(in); msg != "" {
		return nil, &ValidationError{Msg: msg}
	}
	mode := strings.ToUpper(strings.TrimSpace(in.Mode))
	if mode == "" {
		mode = ModeObserve
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM api_strong_flow_definitions WHERE id=$1 FOR UPDATE`, id).Scan(&status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if status != StatusDraft {
		return nil, ErrNotDraft
	}
	ct, err := tx.Exec(ctx, `UPDATE api_strong_flow_definitions SET
		binding_path_prefix=$2, instance_key_param=$3, mode=$4 WHERE id=$1`,
		id, strings.TrimSpace(in.BindingPathPrefix), strings.TrimSpace(in.InstanceKeyParam), mode)
	if err != nil {
		return nil, err
	}
	if ct.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	if err := replaceSteps(ctx, tx, id, in.Steps); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// Activate 激活定义：activate 前全量校验（载荷 + 端点归属核对）→ 同事务
// DRAFT→ACTIVE 且同（应用,名称）旧 ACTIVE→RETIRED（恰一个 ACTIVE 由部分唯一索引兜底）。
func (s *Store) Activate(ctx context.Context, id uuid.UUID) (*Definition, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var d Definition
	if err := tx.QueryRow(ctx, `SELECT `+definitionCols+` FROM api_strong_flow_definitions WHERE id=$1 FOR UPDATE`, id).
		Scan(&d.ID, &d.ApplicationID, &d.Name, &d.Version, &d.Status, &d.BindingPathPrefix,
			&d.InstanceKeyParam, &d.Mode, &d.CreatedByName, &d.CreatedAt, &d.ActivatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if d.Status != StatusDraft {
		return nil, ErrNotDraft
	}
	steps, err := s.listStepsTx(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if len(steps) == 0 {
		return nil, ErrNoSteps
	}
	if msg := validateSteps(steps); msg != "" {
		return nil, &ValidationError{Msg: msg}
	}
	// 端点归属核对：逐步 endpoint_key 必须属于绑定前缀下已 CONFIRMED 端点（§1.1）
	for _, st := range steps {
		if err := checkEndpointEligible(ctx, tx, d.ApplicationID, d.BindingPathPrefix, st.EndpointKey); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE api_strong_flow_definitions SET status='RETIRED'
		WHERE application_id=$1 AND name=$2 AND status='ACTIVE'`, d.ApplicationID, d.Name); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE api_strong_flow_definitions SET status='ACTIVE', activated_at=now()
		WHERE id=$1`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	d.Status = StatusActive
	now := time.Now().UTC()
	d.ActivatedAt = &now
	return &d, nil
}

// Retire 停用定义（ACTIVE/DRAFT→RETIRED；RETIRED 单向终态 ErrInvalidTransition）。
func (s *Store) Retire(ctx context.Context, id uuid.UUID) error {
	ct, err := s.db.Exec(ctx, `UPDATE api_strong_flow_definitions SET status='RETIRED'
		WHERE id=$1 AND status IN ('DRAFT','ACTIVE')`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		var exists bool
		if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM api_strong_flow_definitions WHERE id=$1)`, id).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		return ErrInvalidTransition
	}
	return nil
}

// listStepsTx 事务内读步骤（activate 核对用）。
func (s *Store) listStepsTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) ([]StepInput, error) {
	rows, err := tx.Query(ctx, `SELECT step_key, endpoint_key, sequence, success_rule,
		timeout_seconds, retry_semantics, parallel_group, lease_seconds, allows_202
	FROM api_strong_flow_steps WHERE definition_id=$1 ORDER BY sequence`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StepInput{}
	for rows.Next() {
		var st StepInput
		var rule []byte
		if err := rows.Scan(&st.StepKey, &st.EndpointKey, &st.Sequence, &rule,
			&st.TimeoutSeconds, &st.RetrySemantics, &st.ParallelGroup, &st.LeaseSeconds, &st.Allows202); err != nil {
			return nil, err
		}
		st.SuccessRule = &SuccessRule{}
		if err := json.Unmarshal(rule, st.SuccessRule); err != nil {
			return nil, fmt.Errorf("decode success_rule: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// checkEndpointEligible 端点归属核对：endpoint_key（"METHOD /path" 形态）路径部分
// 须以绑定前缀开头，且端点属同应用、asset_status='CONFIRMED'（§1.1；非法即
// ValidationError——激活拒绝不降级放行）。
func checkEndpointEligible(ctx context.Context, tx pgx.Tx, applicationID uuid.UUID, bindingPrefix, endpointKey string) error {
	parts := strings.SplitN(strings.TrimSpace(endpointKey), " ", 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[1], bindingPrefix) {
		return &ValidationError{Msg: fmt.Sprintf("endpoint_key %q 不属于绑定前缀 %q 下", endpointKey, bindingPrefix)}
	}
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM api_endpoints WHERE application_id=$1 AND endpoint_key=$2 AND asset_status='CONFIRMED')`,
		applicationID, endpointKey).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return &ValidationError{Msg: fmt.Sprintf("endpoint_key %q 不是本应用已 CONFIRMED 端点", endpointKey)}
	}
	return nil
}
