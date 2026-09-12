// store.go api_flow_baselines / api_flow_baseline_steps 表读写（表由迁移 000155 建立）。
// 写入均为「主表 + 步骤表」事务；Update 为整体替换（删旧步骤插新步骤 + version+1
// 乐观锁），与 bot_policies 草稿同一纪律。
package apiflows

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

// Repository 流程基线仓储接口（pgx 实现见 Store；单测可注入内存 fake）。
type Repository interface {
	Create(ctx context.Context, in FlowInput, createdBy string) (*Flow, error)
	List(ctx context.Context, enabled *bool) ([]Summary, error)
	Get(ctx context.Context, id uuid.UUID) (*Flow, error)
	Update(ctx context.Context, id uuid.UUID, in FlowInput, expectedVersion int) (*Flow, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// Store 流程基线 pgx 实现。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建流程基线仓储。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

var _ Repository = (*Store)(nil)

// Create 新建流程基线（flow_id 唯一冲突返回 ErrDuplicateFlowID；
// 步骤 endpoint_id 外键违规返回 ErrUnknownEndpoint）。
func (s *Store) Create(ctx context.Context, in FlowInput, createdBy string) (*Flow, error) {
	if err := validateFlow(&in); err != nil {
		return nil, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id uuid.UUID
	err = tx.QueryRow(ctx, `
INSERT INTO api_flow_baselines (flow_id, name, description, enabled, max_per_window, rate_window_seconds, created_by)
VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7,''))
RETURNING id`,
		in.FlowID, in.Name, in.Description, in.Enabled, in.MaxPerWindow, in.RateWindowSeconds, createdBy).Scan(&id)
	if err != nil {
		if mapped := mapWriteError(err); mapped != nil {
			return nil, mapped
		}
		return nil, fmt.Errorf("insert api_flow_baselines: %w", err)
	}
	if err := insertSteps(ctx, tx, id, in.Steps); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return s.Get(ctx, id)
}

// List 流程基线列表（enabled 过滤可选；按 flow_id 稳定排序；不含步骤明细）。
func (s *Store) List(ctx context.Context, enabled *bool) ([]Summary, error) {
	query := `
SELECT fb.id, fb.flow_id, fb.name, fb.description, fb.enabled, fb.version,
       COALESCE(fb.created_by,''), fb.created_at, fb.updated_at,
       (SELECT count(*) FROM api_flow_baseline_steps s WHERE s.flow_baseline_id = fb.id)
FROM api_flow_baselines fb`
	args := []any{}
	if enabled != nil {
		query += ` WHERE fb.enabled = $1`
		args = append(args, *enabled)
	}
	query += ` ORDER BY fb.flow_id`
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list api_flow_baselines: %w", err)
	}
	defer rows.Close()
	out := []Summary{}
	for rows.Next() {
		var m Summary
		if err := rows.Scan(&m.ID, &m.FlowID, &m.Name, &m.Description, &m.Enabled,
			&m.Version, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt, &m.StepCount); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Get 读取单条流程基线（含步骤，按 sequence/step_id 稳定排序；EndpointKey 关联带出）。
func (s *Store) Get(ctx context.Context, id uuid.UUID) (*Flow, error) {
	var f Flow
	err := s.db.QueryRow(ctx, `
SELECT id, flow_id, name, description, enabled, version, max_per_window, rate_window_seconds,
       COALESCE(created_by,''), created_at, updated_at
FROM api_flow_baselines WHERE id = $1`, id).
		Scan(&f.ID, &f.FlowID, &f.Name, &f.Description, &f.Enabled,
			&f.Version, &f.MaxPerWindow, &f.RateWindowSeconds, &f.CreatedBy, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get api_flow_baselines: %w", err)
	}
	steps, err := s.listSteps(ctx, id)
	if err != nil {
		return nil, err
	}
	f.Steps = steps
	return &f, nil
}

// Update 整体替换（乐观锁：version 不匹配返回 ErrVersionConflict；目标不存在返回
// ErrNotFound——先读当前版本区分两种情形，再以 version 为条件原子更新防并发覆盖）。
func (s *Store) Update(ctx context.Context, id uuid.UUID, in FlowInput, expectedVersion int) (*Flow, error) {
	if err := validateFlow(&in); err != nil {
		return nil, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var curVersion int
	err = tx.QueryRow(ctx, `SELECT version FROM api_flow_baselines WHERE id = $1 FOR UPDATE`, id).Scan(&curVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("lock api_flow_baselines: %w", err)
	}
	if curVersion != expectedVersion {
		return nil, ErrVersionConflict
	}
	_, err = tx.Exec(ctx, `
UPDATE api_flow_baselines
SET flow_id = $2, name = $3, description = $4, enabled = $5,
    max_per_window = $6, rate_window_seconds = $7,
    version = version + 1, updated_at = now()
WHERE id = $1`,
		id, in.FlowID, in.Name, in.Description, in.Enabled, in.MaxPerWindow, in.RateWindowSeconds)
	if err != nil {
		if mapped := mapWriteError(err); mapped != nil {
			return nil, mapped
		}
		return nil, fmt.Errorf("update api_flow_baselines: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM api_flow_baseline_steps WHERE flow_baseline_id = $1`, id); err != nil {
		return nil, fmt.Errorf("delete old api_flow_baseline_steps: %w", err)
	}
	if err := insertSteps(ctx, tx, id, in.Steps); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return s.Get(ctx, id)
}

// Delete 删除流程基线（步骤级联删除；不存在返回 ErrNotFound）。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM api_flow_baselines WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete api_flow_baselines: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// listSteps 读取流程步骤（sequence/step_id 稳定排序；endpoint_key 关联带出）。
func (s *Store) listSteps(ctx context.Context, flowID uuid.UUID) ([]Step, error) {
	rows, err := s.db.Query(ctx, `
SELECT s.id, s.step_id, s.endpoint_id, ep.endpoint_key, s.sequence, s.predecessors,
       s.terminal, s.state_from, s.state_to, s.max_per_window, s.rate_window_seconds, s.cancels_flow
FROM api_flow_baseline_steps s
JOIN api_endpoints ep ON ep.id = s.endpoint_id
WHERE s.flow_baseline_id = $1
ORDER BY s.sequence, s.step_id`, flowID)
	if err != nil {
		return nil, fmt.Errorf("list api_flow_baseline_steps: %w", err)
	}
	defer rows.Close()
	out := []Step{}
	for rows.Next() {
		var st Step
		if err := rows.Scan(&st.ID, &st.StepID, &st.EndpointID, &st.EndpointKey,
			&st.Sequence, &st.Predecessors, &st.Terminal, &st.StateFrom, &st.StateTo,
			&st.MaxPerWindow, &st.RateWindowSeconds, &st.CancelsFlow); err != nil {
			return nil, err
		}
		if st.Predecessors == nil {
			st.Predecessors = []string{}
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// insertSteps 批量插入步骤（调用方已 validateFlow；endpoint_id 此处已校验为 UUID）。
func insertSteps(ctx context.Context, tx pgx.Tx, flowID uuid.UUID, steps []StepInput) error {
	for _, st := range steps {
		endpointID, _ := uuid.Parse(strings.TrimSpace(st.EndpointID))
		predecessors := st.Predecessors
		if predecessors == nil {
			predecessors = []string{}
		}
		_, err := tx.Exec(ctx, `
INSERT INTO api_flow_baseline_steps
    (flow_baseline_id, step_id, endpoint_id, sequence, predecessors, terminal, state_from, state_to,
     max_per_window, rate_window_seconds, cancels_flow)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			flowID, st.StepID, endpointID, st.Sequence, predecessors, st.Terminal, st.StateFrom, st.StateTo,
			st.MaxPerWindow, st.RateWindowSeconds, st.CancelsFlow)
		if err != nil {
			if mapped := mapWriteError(err); mapped != nil {
				return mapped
			}
			return fmt.Errorf("insert api_flow_baseline_steps: %w", err)
		}
	}
	return nil
}

// mapWriteError 唯一冲突/外键违规映射为领域错误（23505 flow_id 唯一 → 409；
// 23503 endpoint_id 外键 → 400）。
func mapWriteError(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return nil
	}
	switch pgErr.Code {
	case "23505":
		return ErrDuplicateFlowID
	case "23503":
		return ErrUnknownEndpoint
	}
	return nil
}
