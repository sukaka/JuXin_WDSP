// store.go upgrade_packages / upgrade_jobs 仓储。
package upgrades

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

// Package 升级包登记记录。
type Package struct {
	ID          uuid.UUID       `json:"id"`
	FileName    string          `json:"file_name"`
	VersionFrom string          `json:"version_from"`
	VersionTo   string          `json:"version_to"`
	FileHash    string          `json:"file_hash"`
	FileSize    int64           `json:"file_size"`
	Manifest    json.RawMessage `json:"manifest"`
	Status      string          `json:"status"`
	UploadedBy  *uuid.UUID      `json:"uploaded_by"`
	UploadedAt  time.Time       `json:"uploaded_at"`
}

// Job 升级任务。
type Job struct {
	ID             uuid.UUID       `json:"id"`
	PackageID      *uuid.UUID      `json:"package_id"`
	Status         string          `json:"status"`
	Precheck       json.RawMessage `json:"precheck"`
	BackupJobID    *uuid.UUID      `json:"backup_job_id"`
	RequestedBy    *uuid.UUID      `json:"requested_by"`
	RequestedAt    time.Time       `json:"requested_at"`
	StartedAt      *time.Time      `json:"started_at"`
	FinishedAt     *time.Time      `json:"finished_at"`
	FailureCode    string          `json:"failure_code"`
	FailureMessage string          `json:"failure_message"`
	RequestID      string          `json:"request_id"`
}

// Store 升级仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// DB 返回连接池（同阶段模块复用）。
func (s *Store) DB() *pgxpool.Pool {
	return s.db
}

// ---------- 升级包 ----------

const packageColumns = `id, file_name, version_from, version_to, file_hash, file_size,
manifest, status, uploaded_by, uploaded_at`

func scanPackage(row pgx.Row) (*Package, error) {
	var p Package
	err := row.Scan(&p.ID, &p.FileName, &p.VersionFrom, &p.VersionTo, &p.FileHash,
		&p.FileSize, &p.Manifest, &p.Status, &p.UploadedBy, &p.UploadedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

// CreatePackage 登记升级包。
func (s *Store) CreatePackage(ctx context.Context, p *Package) error {
	manifest := p.Manifest
	if len(manifest) == 0 {
		manifest = json.RawMessage(`{}`)
	}
	row := s.db.QueryRow(ctx, `
INSERT INTO upgrade_packages (file_name, version_from, version_to, file_hash, file_size, manifest, status, uploaded_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
RETURNING `+packageColumns,
		p.FileName, p.VersionFrom, p.VersionTo, p.FileHash, p.FileSize, manifest, p.Status, p.UploadedBy)
	created, err := scanPackage(row)
	if err != nil {
		return err
	}
	*p = *created
	return nil
}

// GetPackage 查询升级包。
func (s *Store) GetPackage(ctx context.Context, id uuid.UUID) (*Package, error) {
	row := s.db.QueryRow(ctx, `SELECT `+packageColumns+` FROM upgrade_packages WHERE id = $1`, id)
	return scanPackage(row)
}

// ListPackages 分页查询升级包。
func (s *Store) ListPackages(ctx context.Context, status string, page, pageSize int) ([]Package, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	where := "1=1"
	args := []interface{}{}
	if status != "" {
		where += " AND status = $1"
		args = append(args, status)
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM upgrade_packages WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + packageColumns + ` FROM upgrade_packages WHERE ` + where +
		fmt.Sprintf(" ORDER BY uploaded_at DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	rows, err := s.db.Query(ctx, query, append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Package
	for rows.Next() {
		var p Package
		if err := rows.Scan(&p.ID, &p.FileName, &p.VersionFrom, &p.VersionTo, &p.FileHash,
			&p.FileSize, &p.Manifest, &p.Status, &p.UploadedBy, &p.UploadedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	return out, total, rows.Err()
}

// ---------- 升级任务 ----------

const jobColumns = `id, package_id, status, precheck, backup_job_id, requested_by, requested_at,
started_at, finished_at, failure_code, failure_message, request_id`

func scanJob(row pgx.Row) (*Job, error) {
	var j Job
	err := row.Scan(&j.ID, &j.PackageID, &j.Status, &j.Precheck, &j.BackupJobID,
		&j.RequestedBy, &j.RequestedAt, &j.StartedAt, &j.FinishedAt,
		&j.FailureCode, &j.FailureMessage, &j.RequestID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &j, nil
}

// CreateJob 创建 PENDING 升级任务。
func (s *Store) CreateJob(ctx context.Context, packageID uuid.UUID, requestedBy *uuid.UUID, requestID string) (*Job, error) {
	row := s.db.QueryRow(ctx, `
INSERT INTO upgrade_jobs (package_id, status, requested_by, request_id)
VALUES ($1, $2, $3, $4)
RETURNING `+jobColumns, packageID, StatusPending, requestedBy, requestID)
	return scanJob(row)
}

// GetJob 查询任务。
func (s *Store) GetJob(ctx context.Context, id uuid.UUID) (*Job, error) {
	row := s.db.QueryRow(ctx, `SELECT `+jobColumns+` FROM upgrade_jobs WHERE id = $1`, id)
	return scanJob(row)
}

// ListJobs 分页查询任务。
func (s *Store) ListJobs(ctx context.Context, status string, page, pageSize int) ([]Job, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	where := "1=1"
	args := []interface{}{}
	if status != "" {
		where += " AND status = $1"
		args = append(args, status)
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM upgrade_jobs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + jobColumns + ` FROM upgrade_jobs WHERE ` + where +
		fmt.Sprintf(" ORDER BY requested_at DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	rows, err := s.db.Query(ctx, query, append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.PackageID, &j.Status, &j.Precheck, &j.BackupJobID,
			&j.RequestedBy, &j.RequestedAt, &j.StartedAt, &j.FinishedAt,
			&j.FailureCode, &j.FailureMessage, &j.RequestID); err != nil {
			return nil, 0, err
		}
		out = append(out, j)
	}
	return out, total, rows.Err()
}

// HasActiveJob 是否存在未终结的升级任务。
func (s *Store) HasActiveJob(ctx context.Context) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `
SELECT EXISTS(SELECT 1 FROM upgrade_jobs
WHERE status NOT IN ($1, $2, $3))`, StatusSuccess, StatusFailed, StatusRolledBack).Scan(&exists)
	return exists, err
}

// Transition 状态机迁移（乐观校验：仅当当前状态匹配时才更新，防并发乱序）。
func (s *Store) Transition(ctx context.Context, id uuid.UUID, from, to string) error {
	if !CanTransition(from, to) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidStatus, from, to)
	}
	tag, err := s.db.Exec(ctx, `
UPDATE upgrade_jobs SET status = $3,
  started_at = COALESCE(started_at, CASE WHEN $3::varchar <> 'PENDING' THEN now() END)
WHERE id = $1 AND status = $2`, id, from, to)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: job not in status %s", ErrInvalidStatus, from)
	}
	return nil
}

// SetPrecheck 写入预检结果（JSON 数组）。
func (s *Store) SetPrecheck(ctx context.Context, id uuid.UUID, items []CheckItem) error {
	b, err := json.Marshal(items)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `UPDATE upgrade_jobs SET precheck = $2 WHERE id = $1`, id, b)
	return err
}

// SetBackupJob 关联升级前备份任务。
func (s *Store) SetBackupJob(ctx context.Context, id, backupJobID uuid.UUID) error {
	_, err := s.db.Exec(ctx, `UPDATE upgrade_jobs SET backup_job_id = $2 WHERE id = $1`, id, backupJobID)
	return err
}

// MarkFailed 标记失败（原因可查询）。
func (s *Store) MarkFailed(ctx context.Context, id uuid.UUID, code string, err error) error {
	_, dbErr := s.db.Exec(ctx, `
UPDATE upgrade_jobs SET status = $2, failure_code = $3, failure_message = $4, finished_at = now()
WHERE id = $1`, id, StatusFailed, code, failMsg(err))
	return dbErr
}

// MarkFinished 标记终态成功/已回滚。
func (s *Store) MarkFinished(ctx context.Context, id uuid.UUID, status string) error {
	if status != StatusSuccess && status != StatusRolledBack {
		return fmt.Errorf("%w: %s", ErrInvalidStatus, status)
	}
	_, err := s.db.Exec(ctx, `
UPDATE upgrade_jobs SET status = $2, finished_at = now(), failure_code = '', failure_message = ''
WHERE id = $1`, id, status)
	return err
}
