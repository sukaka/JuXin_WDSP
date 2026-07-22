// store.go backup_jobs / backup_files 仓储。
package backups

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

// Job 备份任务。
type Job struct {
	ID             uuid.UUID       `json:"id"`
	BackupType     string          `json:"backup_type"`
	Status         string          `json:"status"`
	IncludeLogs    bool            `json:"include_logs"`
	FileReference  string          `json:"file_reference"`
	FileSize       int64           `json:"file_size"`
	FileHash       string          `json:"file_hash"`
	Manifest       json.RawMessage `json:"manifest"`
	RequestedBy    *uuid.UUID      `json:"requested_by"`
	RequestedAt    time.Time       `json:"requested_at"`
	StartedAt      *time.Time      `json:"started_at"`
	FinishedAt     *time.Time      `json:"finished_at"`
	Verified       bool            `json:"verified"`
	VerifiedAt     *time.Time      `json:"verified_at"`
	FailureCode    string          `json:"failure_code"`
	FailureMessage string          `json:"failure_message"`
	RequestID      string          `json:"request_id"`
}

// Store 备份仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// DB 返回连接池（同阶段模块复用，避免重复构造）。
func (s *Store) DB() *pgxpool.Pool {
	return s.db
}

const jobColumns = `id, backup_type, status, include_logs, file_reference, file_size, file_hash,
manifest, requested_by, requested_at, started_at, finished_at, verified, verified_at,
failure_code, failure_message, request_id`

func scanJob(row pgx.Row) (*Job, error) {
	var j Job
	err := row.Scan(&j.ID, &j.BackupType, &j.Status, &j.IncludeLogs, &j.FileReference,
		&j.FileSize, &j.FileHash, &j.Manifest, &j.RequestedBy, &j.RequestedAt,
		&j.StartedAt, &j.FinishedAt, &j.Verified, &j.VerifiedAt,
		&j.FailureCode, &j.FailureMessage, &j.RequestID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &j, nil
}

// Create 创建 PENDING 备份任务。
func (s *Store) Create(ctx context.Context, backupType string, requestedBy *uuid.UUID, requestID string) (*Job, error) {
	if !ValidType(backupType) {
		return nil, ErrInvalidType
	}
	row := s.db.QueryRow(ctx, `
INSERT INTO backup_jobs (backup_type, status, requested_by, request_id)
VALUES ($1, $2, $3, $4)
RETURNING `+jobColumns, backupType, StatusPending, requestedBy, requestID)
	return scanJob(row)
}

// GetByID 查询任务。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Job, error) {
	row := s.db.QueryRow(ctx, `SELECT `+jobColumns+` FROM backup_jobs WHERE id = $1`, id)
	return scanJob(row)
}

// InsertImported 登记一个外部导入且已通过完整性验证的备份文件（全新环境恢复入口）。
// 调用方必须先完成 Exporter.Verify，本方法只落库（状态 SUCCESS + verified）。
func (s *Store) InsertImported(ctx context.Context, id uuid.UUID, backupType, fileRef string, fileSize int64, fileHash string, manifest []byte, requestedBy *uuid.UUID) (*Job, error) {
	if !ValidType(backupType) {
		return nil, ErrInvalidType
	}
	row := s.db.QueryRow(ctx, `
INSERT INTO backup_jobs (id, backup_type, status, file_reference, file_size, file_hash, manifest,
  requested_by, started_at, finished_at, verified, verified_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now(), TRUE, now())
RETURNING `+jobColumns, id, backupType, StatusSuccess, fileRef, fileSize, fileHash, manifest, requestedBy)
	return scanJob(row)
}

// List 分页查询（按类型/状态过滤）。
func (s *Store) List(ctx context.Context, backupType, status string, page, pageSize int) ([]Job, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	where := "1=1"
	args := []interface{}{}
	argIdx := 1
	if backupType != "" {
		where += fmt.Sprintf(" AND backup_type = $%d", argIdx)
		args = append(args, backupType)
		argIdx++
	}
	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM backup_jobs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + jobColumns + ` FROM backup_jobs WHERE ` + where +
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
		if err := rows.Scan(&j.ID, &j.BackupType, &j.Status, &j.IncludeLogs, &j.FileReference,
			&j.FileSize, &j.FileHash, &j.Manifest, &j.RequestedBy, &j.RequestedAt,
			&j.StartedAt, &j.FinishedAt, &j.Verified, &j.VerifiedAt,
			&j.FailureCode, &j.FailureMessage, &j.RequestID); err != nil {
			return nil, 0, err
		}
		out = append(out, j)
	}
	return out, total, rows.Err()
}

// Claim 认领一个 PENDING 任务（FOR UPDATE SKIP LOCKED，多实例安全）。
// 无待处理任务时返回 (nil, nil)。
func (s *Store) Claim(ctx context.Context) (*Job, error) {
	row := s.db.QueryRow(ctx, `
UPDATE backup_jobs SET status = $1, started_at = now()
WHERE id = (
  SELECT id FROM backup_jobs WHERE status = $2 ORDER BY requested_at
  FOR UPDATE SKIP LOCKED LIMIT 1
)
RETURNING `+jobColumns, StatusRunning, StatusPending)
	j, err := scanJob(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return j, nil
}

// SetStatus 更新状态（通用）。
func (s *Store) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := s.db.Exec(ctx, `UPDATE backup_jobs SET status = $1 WHERE id = $2`, status, id)
	return err
}

// MarkSuccess 标记成功（必须先通过验证：verified=true）。
func (s *Store) MarkSuccess(ctx context.Context, id uuid.UUID, m *Manifest, fileRef string, fileSize int64, fileHash string) error {
	manifestJSON, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
UPDATE backup_jobs SET status = $1, manifest = $2, file_reference = $3, file_size = $4, file_hash = $5,
  verified = TRUE, verified_at = now(), finished_at = now(), failure_code = '', failure_message = ''
WHERE id = $6`, StatusSuccess, manifestJSON, fileRef, fileSize, fileHash, id)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO backup_files (backup_job_id, file_path, file_size, file_hash)
VALUES ($1, $2, $3, $4)`, id, fileRef, fileSize, fileHash)
	return tx.Commit(ctx)
}

// MarkFailed 标记失败（原因可查询）。
func (s *Store) MarkFailed(ctx context.Context, id uuid.UUID, code string, err error) error {
	_, dbErr := s.db.Exec(ctx, `
UPDATE backup_jobs SET status = $1, failure_code = $2, failure_message = $3, finished_at = now()
WHERE id = $4`, StatusFailed, code, failMsg(err), id)
	return dbErr
}

// MarkVerified 更新手动验证结果；验证失败的任务不得保持 SUCCESS。
func (s *Store) MarkVerified(ctx context.Context, id uuid.UUID, ok bool, verifyErr error) error {
	if ok {
		_, err := s.db.Exec(ctx, `UPDATE backup_jobs SET verified = TRUE, verified_at = now() WHERE id = $1`, id)
		return err
	}
	_, err := s.db.Exec(ctx, `
UPDATE backup_jobs SET status = $1, verified = FALSE, failure_code = $2, failure_message = $3, finished_at = now()
WHERE id = $4`, StatusFailed, FailVerifyFailed, failMsg(verifyErr), id)
	return err
}

// IsReferencedByRestore 是否存在关联恢复任务（存在则禁止删除）。
func (s *Store) IsReferencedByRestore(ctx context.Context, id uuid.UUID) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM restore_jobs WHERE backup_job_id = $1)`, id).Scan(&exists)
	return exists, err
}

// Delete 删除任务与文件记录（调用方先校验引用与状态、先删文件）。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM backup_files WHERE backup_job_id = $1`, id); err != nil {
		return err
	}
	res, err := tx.Exec(ctx, `
DELETE FROM backup_jobs WHERE id = $1
  AND status NOT IN ($2, $3)
  AND NOT EXISTS (SELECT 1 FROM restore_jobs WHERE backup_job_id = $1)`, id, StatusRunning, StatusVerifying)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrInvalidStatus
	}
	return tx.Commit(ctx)
}

// RetentionCandidates 保留策略候选：
//   - 成功任务中超出最近 keepSuccess 个的；
//   - 任何 requested_at 早于 cutoff 的任务。
//
// 跳过被恢复任务引用的记录（保留审计线索与可恢复性）。
func (s *Store) RetentionCandidates(ctx context.Context, keepSuccess int, cutoff time.Time) ([]Job, error) {
	rows, err := s.db.Query(ctx, `
SELECT `+jobColumns+` FROM backup_jobs
WHERE NOT EXISTS (SELECT 1 FROM restore_jobs WHERE backup_job_id = backup_jobs.id)
  AND (
    requested_at < $1
    OR id IN (
      SELECT id FROM backup_jobs WHERE status = $2
      ORDER BY requested_at DESC OFFSET $3
    )
  )`, cutoff, StatusSuccess, keepSuccess)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.BackupType, &j.Status, &j.IncludeLogs, &j.FileReference,
			&j.FileSize, &j.FileHash, &j.Manifest, &j.RequestedBy, &j.RequestedAt,
			&j.StartedAt, &j.FinishedAt, &j.Verified, &j.VerifiedAt,
			&j.FailureCode, &j.FailureMessage, &j.RequestID); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
