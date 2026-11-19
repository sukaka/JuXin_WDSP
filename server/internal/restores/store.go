// store.go restore_jobs 仓储。
package restores

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Job 恢复任务。
type Job struct {
	ID             uuid.UUID       `json:"id"`
	BackupJobID    *uuid.UUID      `json:"backup_job_id"`
	RestoreScope   string          `json:"restore_scope"`
	Status         string          `json:"status"`
	Preview        json.RawMessage `json:"preview"`
	ConfirmedBy    *uuid.UUID      `json:"confirmed_by"`
	ConfirmedAt    *time.Time      `json:"confirmed_at"`
	RequestedBy    *uuid.UUID      `json:"requested_by"`
	RequestedAt    time.Time       `json:"requested_at"`
	StartedAt      *time.Time      `json:"started_at"`
	FinishedAt     *time.Time      `json:"finished_at"`
	FailureCode    string          `json:"failure_code"`
	FailureMessage string          `json:"failure_message"`
	RequestID      string          `json:"request_id"`
}

// Store 恢复仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

const jobColumns = `id, backup_job_id, restore_scope, status, preview, confirmed_by, confirmed_at,
requested_by, requested_at, started_at, finished_at, failure_code, failure_message, request_id`

// restoreJobLockKey 串行化活动恢复任务的检查与创建，避免并发请求同时通过 HasActive 校验。
const restoreJobLockKey int64 = 0x4a5a574146525354

func (s *Store) scanJob(row pgx.Row) (*Job, error) {
	var j Job
	err := row.Scan(&j.ID, &j.BackupJobID, &j.RestoreScope, &j.Status, &j.Preview,
		&j.ConfirmedBy, &j.ConfirmedAt, &j.RequestedBy, &j.RequestedAt, &j.StartedAt,
		&j.FinishedAt, &j.FailureCode, &j.FailureMessage, &j.RequestID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &j, nil
}

// CreateIfNoActive 在同一事务中以事务级咨询锁串行化活动任务检查并创建 PENDING 恢复任务。
func (s *Store) CreateIfNoActive(ctx context.Context, backupJobID uuid.UUID, scope string, requestedBy *uuid.UUID, requestID string) (*Job, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, restoreJobLockKey); err != nil {
		return nil, err
	}
	var active bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS(SELECT 1 FROM restore_jobs
  WHERE status IN ($1,$2,$3,$4,$5,$6))`,
		StatusPending, StatusValidating, StatusIsolatedRestore, StatusVerifying,
		StatusAwaitingConfirm, StatusRestoring).Scan(&active); err != nil {
		return nil, err
	}
	if active {
		return nil, ErrActiveRestore
	}
	row := tx.QueryRow(ctx, `
INSERT INTO restore_jobs (backup_job_id, restore_scope, status, requested_by, request_id)
VALUES ($1, $2, $3, $4, $5)
RETURNING `+jobColumns, backupJobID, scope, StatusPending, requestedBy, requestID)
	job, err := s.scanJob(row)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return job, nil
}

// Create 创建 PENDING 恢复任务。
func (s *Store) Create(ctx context.Context, backupJobID uuid.UUID, scope string, requestedBy *uuid.UUID, requestID string) (*Job, error) {
	row := s.db.QueryRow(ctx, `
INSERT INTO restore_jobs (backup_job_id, restore_scope, status, requested_by, request_id)
VALUES ($1, $2, $3, $4, $5)
RETURNING `+jobColumns, backupJobID, scope, StatusPending, requestedBy, requestID)
	return s.scanJob(row)
}

// GetByID 查询任务。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Job, error) {
	row := s.db.QueryRow(ctx, `SELECT `+jobColumns+` FROM restore_jobs WHERE id = $1`, id)
	return s.scanJob(row)
}

// List 分页查询。
func (s *Store) List(ctx context.Context, status string, page, pageSize int) ([]Job, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	where := "1=1"
	args := []interface{}{}
	argIdx := 1
	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM restore_jobs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + jobColumns + ` FROM restore_jobs WHERE ` + where +
		fmt.Sprintf(" ORDER BY requested_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.BackupJobID, &j.RestoreScope, &j.Status, &j.Preview,
			&j.ConfirmedBy, &j.ConfirmedAt, &j.RequestedBy, &j.RequestedAt, &j.StartedAt,
			&j.FinishedAt, &j.FailureCode, &j.FailureMessage, &j.RequestID); err != nil {
			return nil, 0, err
		}
		out = append(out, j)
	}
	return out, total, rows.Err()
}

// HasActive 是否存在进行中的恢复任务（全局互斥）。
func (s *Store) HasActive(ctx context.Context) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `
SELECT EXISTS(SELECT 1 FROM restore_jobs
  WHERE status IN ($1,$2,$3,$4,$5,$6))`,
		StatusPending, StatusValidating, StatusIsolatedRestore, StatusVerifying,
		StatusAwaitingConfirm, StatusRestoring).Scan(&exists)
	return exists, err
}

// SetStatus 更新状态。
func (s *Store) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := s.db.Exec(ctx, `UPDATE restore_jobs SET status = $1 WHERE id = $2`, status, id)
	return err
}

// MarkAwaitingConfirm 隔离恢复完成，写入预览并等待确认。
func (s *Store) MarkAwaitingConfirm(ctx context.Context, id uuid.UUID, preview *Preview) error {
	body, err := json.Marshal(preview)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `
UPDATE restore_jobs SET status = $1, preview = $2 WHERE id = $3`, StatusAwaitingConfirm, body, id)
	return err
}

// MarkFailed 标记失败（原因可查询）。
func (s *Store) MarkFailed(ctx context.Context, id uuid.UUID, code string, err error) error {
	_, dbErr := s.db.Exec(ctx, `
UPDATE restore_jobs SET status = $1, failure_code = $2, failure_message = $3, finished_at = now()
WHERE id = $4`, StatusFailed, code, failMsg(err), id)
	return dbErr
}

// MarkRestoring 进入正式恢复（仅 AWAITING_CONFIRM 可转换，原子防并发确认）。
func (s *Store) MarkRestoring(ctx context.Context, id uuid.UUID, confirmedBy uuid.UUID) error {
	res, err := s.db.Exec(ctx, `
UPDATE restore_jobs SET status = $1, confirmed_by = $2, confirmed_at = now(), started_at = now()
WHERE id = $3 AND status = $4`, StatusRestoring, confirmedBy, id, StatusAwaitingConfirm)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrInvalidStatus
	}
	return nil
}

// MarkSuccess 标记成功。
func (s *Store) MarkSuccess(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.Exec(ctx, `
UPDATE restore_jobs SET status = $1, finished_at = now(), failure_code = '', failure_message = ''
WHERE id = $2`, StatusSuccess, id)
	return err
}

// MarkCancelled 取消（仅 AWAITING_CONFIRM 可取消）。
func (s *Store) MarkCancelled(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.Exec(ctx, `
UPDATE restore_jobs SET status = $1, finished_at = now()
WHERE id = $2 AND status = $3`, StatusCancelled, id, StatusAwaitingConfirm)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrInvalidStatus
	}
	return nil
}
