// store.go AI 定时运营任务仓储：Repository 接口（SQL 与内存实现共用，便于诚实单测）
// + PostgreSQL 实现。两表：api_ai_schedules（计划）/ api_ai_schedule_runs（执行记录，
// 迁移 000062）。
package apiops

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

// ScheduleFilter 计划列表过滤（TaskType/Enabled 已归一校验）。
type ScheduleFilter struct {
	TaskType string
	Enabled  *bool
	Page     int
	PageSize int
}

// Repository AI 运营定时计划仓储（SQL 与内存实现共用）。
type Repository interface {
	CreateSchedule(ctx context.Context, s *Schedule) error
	GetSchedule(ctx context.Context, id uuid.UUID) (*Schedule, error)
	ListSchedules(ctx context.Context, f ScheduleFilter) ([]Schedule, int64, error)
	// UpdateSchedule 更新 name/cron_expr/config（task_type 不可变，handler 侧校验）；
	// NextRunAt 由调用方按新 cron 重算后一并写入（停用时传 nil）。
	UpdateSchedule(ctx context.Context, s *Schedule) error
	DeleteSchedule(ctx context.Context, id uuid.UUID) error
	// SetScheduleEnabled 启停计划（启用时写入 next_run_at，停用时清空）。
	SetScheduleEnabled(ctx context.Context, id uuid.UUID, enabled bool, nextRunAt *time.Time) (*Schedule, error)
	// ListDueSchedules 取到期 ENABLED 计划（next_run_at <= now，按到期升序，限 limit 条）。
	ListDueSchedules(ctx context.Context, now time.Time, limit int) ([]Schedule, error)
	// UpdateNextRunAt 仅推进到期游标（调度 claim 先行，防下一 tick 重入）。
	UpdateNextRunAt(ctx context.Context, id uuid.UUID, next *time.Time) error
	// UpdateScheduleRunState 执行轨迹回填（last_run_at/last_status/last_error）。
	UpdateScheduleRunState(ctx context.Context, id uuid.UUID, lastRunAt time.Time, status, errMsg string) error
	CreateRun(ctx context.Context, r *Run) error
	// FinishRun 终结执行记录（RUNNING → SUCCESS/FAILED；附带产物）。
	FinishRun(ctx context.Context, id uuid.UUID, status, summary string, report json.RawMessage, finishedAt time.Time) error
	// HasRunningRun 是否存在 RUNNING 执行记录（手动执行/调度防重入）。
	HasRunningRun(ctx context.Context, scheduleID uuid.UUID) (bool, error)
	ListRuns(ctx context.Context, scheduleID uuid.UUID, page, pageSize int) ([]Run, int64, error)
	GetRun(ctx context.Context, id uuid.UUID) (*Run, error)
}

// 确保 *Store / *MemStore 实现 Repository。
var (
	_ Repository = (*Store)(nil)
	_ Repository = (*MemStore)(nil)
)

// Store AI 运营定时计划 PostgreSQL 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// scheduleCols 计划列清单（扫描顺序与 scanSchedule 一致）。
const scheduleCols = `id, task_type, name, cron_expr, enabled, config_json, next_run_at, last_run_at, last_status, last_error, created_by, created_at, updated_at`

// scanSchedule 行扫描公共路径。
func scanSchedule(row pgx.Row) (*Schedule, error) {
	var s Schedule
	err := row.Scan(&s.ID, &s.TaskType, &s.Name, &s.CronExpr, &s.Enabled, &s.Config,
		&s.NextRunAt, &s.LastRunAt, &s.LastStatus, &s.LastError, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrScheduleNotFound
		}
		return nil, err
	}
	return &s, nil
}

// normalizeConfig 空配置落库为 '{}'（jsonb NOT NULL 约束）。
func normalizeConfig(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`{}`)
	}
	return raw
}

func (s *Store) CreateSchedule(ctx context.Context, sc *Schedule) error {
	if sc.ID == uuid.Nil {
		sc.ID = uuid.New()
	}
	now := time.Now().UTC()
	sc.CreatedAt, sc.UpdatedAt = now, now
	_, err := s.db.Exec(ctx, `
INSERT INTO api_ai_schedules (id, task_type, name, cron_expr, enabled, config_json, next_run_at, created_by, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		sc.ID, sc.TaskType, sc.Name, sc.CronExpr, sc.Enabled, normalizeConfig(sc.Config), sc.NextRunAt, sc.CreatedBy, sc.CreatedAt, sc.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create api ai schedule: %w", err)
	}
	return nil
}

func (s *Store) GetSchedule(ctx context.Context, id uuid.UUID) (*Schedule, error) {
	sc, err := scanSchedule(s.db.QueryRow(ctx, `SELECT `+scheduleCols+` FROM api_ai_schedules WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("get api ai schedule: %w", err)
	}
	return sc, nil
}

func (s *Store) ListSchedules(ctx context.Context, f ScheduleFilter) ([]Schedule, int64, error) {
	var conds []string
	var args []any
	if f.TaskType != "" {
		args = append(args, f.TaskType)
		conds = append(conds, fmt.Sprintf("task_type = $%d", len(args)))
	}
	if f.Enabled != nil {
		args = append(args, *f.Enabled)
		conds = append(conds, fmt.Sprintf("enabled = $%d", len(args)))
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_ai_schedules`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count api ai schedules: %w", err)
	}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `
SELECT `+scheduleCols+` FROM api_ai_schedules`+where+`
ORDER BY created_at DESC LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list api ai schedules: %w", err)
	}
	defer rows.Close()
	out := []Schedule{}
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *sc)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (s *Store) UpdateSchedule(ctx context.Context, sc *Schedule) error {
	sc.UpdatedAt = time.Now().UTC()
	tag, err := s.db.Exec(ctx, `
UPDATE api_ai_schedules SET name=$2, cron_expr=$3, config_json=$4, next_run_at=$5, updated_at=$6
WHERE id=$1`, sc.ID, sc.Name, sc.CronExpr, normalizeConfig(sc.Config), sc.NextRunAt, sc.UpdatedAt)
	if err != nil {
		return fmt.Errorf("update api ai schedule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrScheduleNotFound
	}
	return nil
}

func (s *Store) DeleteSchedule(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM api_ai_schedules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete api ai schedule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrScheduleNotFound
	}
	return nil
}

func (s *Store) SetScheduleEnabled(ctx context.Context, id uuid.UUID, enabled bool, nextRunAt *time.Time) (*Schedule, error) {
	sc, err := scanSchedule(s.db.QueryRow(ctx, `
UPDATE api_ai_schedules SET enabled=$2, next_run_at=$3, updated_at=now() WHERE id=$1 RETURNING `+scheduleCols,
		id, enabled, nextRunAt))
	if err != nil {
		return nil, fmt.Errorf("set api ai schedule enabled: %w", err)
	}
	return sc, nil
}

func (s *Store) ListDueSchedules(ctx context.Context, now time.Time, limit int) ([]Schedule, error) {
	rows, err := s.db.Query(ctx, `
SELECT `+scheduleCols+` FROM api_ai_schedules
WHERE enabled AND next_run_at IS NOT NULL AND next_run_at <= $1
ORDER BY next_run_at LIMIT $2`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("list due api ai schedules: %w", err)
	}
	defer rows.Close()
	out := []Schedule{}
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) UpdateNextRunAt(ctx context.Context, id uuid.UUID, next *time.Time) error {
	if _, err := s.db.Exec(ctx, `UPDATE api_ai_schedules SET next_run_at=$2, updated_at=now() WHERE id=$1`, id, next); err != nil {
		return fmt.Errorf("update api ai schedule next_run_at: %w", err)
	}
	return nil
}

func (s *Store) UpdateScheduleRunState(ctx context.Context, id uuid.UUID, lastRunAt time.Time, status, errMsg string) error {
	if _, err := s.db.Exec(ctx, `
UPDATE api_ai_schedules SET last_run_at=$2, last_status=$3, last_error=$4, updated_at=now() WHERE id=$1`,
		id, lastRunAt, status, errMsg); err != nil {
		return fmt.Errorf("update api ai schedule run state: %w", err)
	}
	return nil
}

// runCols 执行记录列清单（扫描顺序与 scanRun 一致）。
const runCols = `id, schedule_id, started_at, finished_at, status, summary, report_json, created_at`

// scanRun 执行记录行扫描公共路径。
func scanRun(row pgx.Row) (*Run, error) {
	var r Run
	err := row.Scan(&r.ID, &r.ScheduleID, &r.StartedAt, &r.FinishedAt, &r.Status, &r.Summary, &r.Report, &r.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRunNotFound
		}
		return nil, err
	}
	return &r, nil
}

func (s *Store) CreateRun(ctx context.Context, r *Run) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	r.Status = RunStatusRunning
	r.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(ctx, `
INSERT INTO api_ai_schedule_runs (id, schedule_id, started_at, status, created_at)
VALUES ($1,$2,$3,$4,$5)`, r.ID, r.ScheduleID, r.StartedAt, r.Status, r.CreatedAt)
	if err != nil {
		return fmt.Errorf("create api ai schedule run: %w", err)
	}
	return nil
}

func (s *Store) FinishRun(ctx context.Context, id uuid.UUID, status, summary string, report json.RawMessage, finishedAt time.Time) error {
	if len(report) == 0 {
		report = json.RawMessage(`{}`)
	}
	tag, err := s.db.Exec(ctx, `
UPDATE api_ai_schedule_runs SET status=$2, summary=$3, report_json=$4, finished_at=$5
WHERE id=$1 AND status='RUNNING'`, id, status, summary, report, finishedAt)
	if err != nil {
		return fmt.Errorf("finish api ai schedule run: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrRunNotFound
	}
	return nil
}

func (s *Store) HasRunningRun(ctx context.Context, scheduleID uuid.UUID) (bool, error) {
	var exists bool
	if err := s.db.QueryRow(ctx, `
SELECT EXISTS(SELECT 1 FROM api_ai_schedule_runs WHERE schedule_id=$1 AND status='RUNNING')`, scheduleID).Scan(&exists); err != nil {
		return false, fmt.Errorf("check running api ai schedule run: %w", err)
	}
	return exists, nil
}

func (s *Store) ListRuns(ctx context.Context, scheduleID uuid.UUID, page, pageSize int) ([]Run, int64, error) {
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_ai_schedule_runs WHERE schedule_id=$1`, scheduleID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count api ai schedule runs: %w", err)
	}
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	rows, err := s.db.Query(ctx, `
SELECT `+runCols+` FROM api_ai_schedule_runs WHERE schedule_id=$1
ORDER BY started_at DESC LIMIT $2 OFFSET $3`, scheduleID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("list api ai schedule runs: %w", err)
	}
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (s *Store) GetRun(ctx context.Context, id uuid.UUID) (*Run, error) {
	r, err := scanRun(s.db.QueryRow(ctx, `SELECT `+runCols+` FROM api_ai_schedule_runs WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("get api ai schedule run: %w", err)
	}
	return r, nil
}
