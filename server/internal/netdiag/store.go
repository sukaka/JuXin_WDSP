// store.go netdiag_jobs 仓储。
package netdiag

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

// ErrNotFound 任务不存在。
var ErrNotFound = errors.New("netdiag job not found")

// Job 网络诊断任务。
type Job struct {
	ID          uuid.UUID       `json:"id"`
	Node        string          `json:"node"`
	Action      string          `json:"action"`
	Target      string          `json:"target"`
	Params      json.RawMessage `json:"params"`
	Status      string          `json:"status"`
	ResultText  string          `json:"result_text"`
	ExitCode    *int            `json:"exit_code"`
	DurationMs  *int64          `json:"duration_ms"`
	CaptureFile string          `json:"capture_file"`
	CaptureSize *int64          `json:"capture_size"`
	CaptureHash string          `json:"capture_hash"`
	// CapturePackets 抓包数据包解析列表（仅详情查询带出；列表不查该列故恒为 null）。
	CapturePackets json.RawMessage `json:"capture_packets"`
	FailureMessage string          `json:"failure_message"`
	RequestedBy    *uuid.UUID      `json:"requested_by"`
	RequestID      string          `json:"request_id"`
	CreatedAt      time.Time       `json:"created_at"`
	StartedAt      *time.Time      `json:"started_at"`
	FinishedAt     *time.Time      `json:"finished_at"`
}

// DecodeParams 解析任务参数。
func (j *Job) DecodeParams() Params {
	var p Params
	if len(j.Params) > 0 {
		_ = json.Unmarshal(j.Params, &p)
	}
	return p
}

// Store 网络诊断仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// jobColumns 基础列（列表/写入路径使用，不含 capture_packets 大字段）。
const jobColumns = `id, node, action, target, params, status, result_text, exit_code, duration_ms,
capture_file, capture_size, capture_hash, failure_message, requested_by, request_id,
created_at, started_at, finished_at`

// jobDetailColumns 详情列（含 capture_packets 解析列表，仅 GetByID 使用）。
const jobDetailColumns = jobColumns + `, capture_packets`

// scanJobBase 扫描基础列（capture_packets 保持 nil）。
func scanJobBase(scan func(dest ...interface{}) error) (*Job, error) {
	var j Job
	err := scan(&j.ID, &j.Node, &j.Action, &j.Target, &j.Params, &j.Status, &j.ResultText,
		&j.ExitCode, &j.DurationMs, &j.CaptureFile, &j.CaptureSize, &j.CaptureHash,
		&j.FailureMessage, &j.RequestedBy, &j.RequestID, &j.CreatedAt, &j.StartedAt, &j.FinishedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &j, nil
}

func scanJob(row pgx.Row) (*Job, error) {
	return scanJobBase(row.Scan)
}

// scanJobDetail 扫描详情列（含 capture_packets）。
func scanJobDetail(row pgx.Row) (*Job, error) {
	var packets json.RawMessage
	j, err := scanJobBase(func(dest ...interface{}) error {
		return row.Scan(append(dest, &packets)...)
	})
	if err != nil {
		return nil, err
	}
	j.CapturePackets = packets
	return j, nil
}

func scanJobs(rows pgx.Rows) ([]Job, error) {
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.Node, &j.Action, &j.Target, &j.Params, &j.Status, &j.ResultText,
			&j.ExitCode, &j.DurationMs, &j.CaptureFile, &j.CaptureSize, &j.CaptureHash,
			&j.FailureMessage, &j.RequestedBy, &j.RequestID, &j.CreatedAt, &j.StartedAt, &j.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// Create 创建 PENDING 诊断任务。
func (s *Store) Create(ctx context.Context, node, action, target string, params Params, requestedBy *uuid.UUID, requestID string) (*Job, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal params: %w", err)
	}
	row := s.db.QueryRow(ctx, `
INSERT INTO netdiag_jobs (node, action, target, params, requested_by, request_id)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING `+jobColumns, node, action, target, raw, requestedBy, requestID)
	return scanJob(row)
}

// GetByID 查询任务详情（含 capture_packets 抓包解析列表）。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Job, error) {
	row := s.db.QueryRow(ctx, `SELECT `+jobDetailColumns+` FROM netdiag_jobs WHERE id = $1`, id)
	return scanJobDetail(row)
}

// List 分页查询（按动作/状态过滤，按创建时间倒序）。
func (s *Store) List(ctx context.Context, action, status string, page, pageSize int) ([]Job, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	where := "1=1"
	args := []interface{}{}
	argIdx := 1
	if action != "" {
		where += fmt.Sprintf(" AND action = $%d", argIdx)
		args = append(args, action)
		argIdx++
	}
	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM netdiag_jobs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `SELECT `+jobColumns+` FROM netdiag_jobs WHERE `+where+
		fmt.Sprintf(" ORDER BY created_at DESC, id LIMIT $%d OFFSET $%d", argIdx, argIdx+1), args...)
	if err != nil {
		return nil, 0, err
	}
	jobs, err := scanJobs(rows)
	if err != nil {
		return nil, 0, err
	}
	return jobs, total, nil
}

// ListByStatus 查询指定状态的任务（Worker 调度用）。
func (s *Store) ListByStatus(ctx context.Context, statuses ...string) ([]Job, error) {
	rows, err := s.db.Query(ctx, `SELECT `+jobColumns+` FROM netdiag_jobs WHERE status = ANY($1) ORDER BY created_at`, statuses)
	if err != nil {
		return nil, err
	}
	return scanJobs(rows)
}

// MarkRunning PENDING → RUNNING（乐观条件更新；已被停止/完成时返回 false）。
func (s *Store) MarkRunning(ctx context.Context, id uuid.UUID) (bool, error) {
	tag, err := s.db.Exec(ctx, `
UPDATE netdiag_jobs SET status = $2, started_at = now() WHERE id = $1 AND status = $3`,
		id, StatusRunning, StatusPending)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// StopPending PENDING → STOPPED（用户主动停止尚未下发的任务；返回是否生效）。
func (s *Store) StopPending(ctx context.Context, id uuid.UUID) (bool, error) {
	tag, err := s.db.Exec(ctx, `
UPDATE netdiag_jobs SET status = $2, finished_at = now(), failure_message = '任务已停止'
WHERE id = $1 AND status = $3`,
		id, StatusStopped, StatusPending)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// Finish 落库终态（RUNNING → 终态之一；result_text 已按上限截断）。
func (s *Store) Finish(ctx context.Context, id uuid.UUID, status, resultText string, exitCode *int, durationMs *int64, failureMsg string) error {
	tag, err := s.db.Exec(ctx, `
UPDATE netdiag_jobs SET status = $2, result_text = $3, exit_code = $4, duration_ms = $5,
  failure_message = $6, finished_at = now()
WHERE id = $1 AND status IN ($7, $8)`,
		id, status, resultText, exitCode, durationMs, failureMsg, StatusPending, StatusRunning)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetCaptureArtifact 登记抓包产物（文件名/大小/sha256）。
func (s *Store) SetCaptureArtifact(ctx context.Context, id uuid.UUID, file string, size int64, hash string) error {
	_, err := s.db.Exec(ctx, `
UPDATE netdiag_jobs SET capture_file = $2, capture_size = $3, capture_hash = $4 WHERE id = $1`,
		id, file, size, hash)
	return err
}

// SetCapturePackets 登记抓包数据包解析列表（JSON 数组）。
func (s *Store) SetCapturePackets(ctx context.Context, id uuid.UUID, packets []byte) error {
	_, err := s.db.Exec(ctx, `
UPDATE netdiag_jobs SET capture_packets = $2 WHERE id = $1`, id, packets)
	return err
}
