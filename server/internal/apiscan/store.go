// store.go 主动扫描仓储：Repository 接口（SQL 与内存实现共用，便于诚实单测）+ PostgreSQL 实现。
package apiscan

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

// JobFilter 任务列表过滤（Status 已归一校验）。
type JobFilter struct {
	TargetID *uuid.UUID
	Status   string
	Page     int
	PageSize int
}

// FindingFilter 发现列表过滤（Status/Severity/Template 已归一校验）。
type FindingFilter struct {
	JobID    *uuid.UUID
	Status   string
	Severity string
	Template string
	Page     int
	PageSize int
}

// Repository 主动扫描仓储（SQL 与内存实现共用）。
type Repository interface {
	// 目标
	CreateTarget(ctx context.Context, t *Target) error
	UpdateTarget(ctx context.Context, t *Target) error
	GetTarget(ctx context.Context, id uuid.UUID) (*Target, error)
	ListTargets(ctx context.Context, applicationID *uuid.UUID, status string, page, pageSize int) ([]Target, int64, error)
	// 授权
	CreateAuthorization(ctx context.Context, a *Authorization) error
	GetAuthorization(ctx context.Context, id uuid.UUID) (*Authorization, error)
	ListAuthorizations(ctx context.Context, targetID uuid.UUID, page, pageSize int) ([]Authorization, int64, error)
	// RevokeAuthorization 撤销授权（幂等：已撤销返回现状）；撤销后应由调用方联动停止在跑任务。
	RevokeAuthorization(ctx context.Context, id uuid.UUID, now time.Time) (*Authorization, error)
	// 任务
	CreateJob(ctx context.Context, j *Job) error
	GetJob(ctx context.Context, id uuid.UUID) (*Job, error)
	ListJobs(ctx context.Context, f JobFilter) ([]Job, int64, error)
	// ClaimPendingJob 取一个 PENDING 任务置 RUNNING（同目标互斥：该目标无 RUNNING 任务才可取）；
	// 无可取任务返回 (nil, nil)。
	ClaimPendingJob(ctx context.Context, now time.Time) (*Job, error)
	// StartJob 将 PENDING/PAUSED 任务置 RUNNING（手动启动入口；状态不允许返回 ErrInvalidTransition）。
	StartJob(ctx context.Context, id uuid.UUID, now time.Time) (*Job, error)
	// SaveJobProgress 保存执行进度（仅 RUNNING 任务；已被停止/终结的任务忽略，返回现状）。
	SaveJobProgress(ctx context.Context, id uuid.UUID, p Progress) (*Job, error)
	// FinishJob 终结任务（仅 RUNNING → 目标状态；已被外部停止的任务不覆盖，返回现状）。
	FinishJob(ctx context.Context, id uuid.UUID, status string, p Progress, now time.Time) (*Job, error)
	// StopJob 停止单个任务（PENDING/PAUSED/RUNNING → STOPPED；终态返回 ErrInvalidTransition）。
	StopJob(ctx context.Context, id uuid.UUID, now time.Time) (*Job, error)
	// StopJobsByAuthorization 停止授权单下全部未终结任务（授权撤销/紧急停止联动），返回停止数。
	StopJobsByAuthorization(ctx context.Context, authorizationID uuid.UUID, now time.Time) (int64, error)
	// 发现
	CreateFinding(ctx context.Context, f *Finding) error
	GetFinding(ctx context.Context, id uuid.UUID) (*Finding, error)
	ListFindings(ctx context.Context, f FindingFilter) ([]Finding, int64, error)
	// SetFindingStatus 发现处置（仅 NEW → CONFIRMED/FALSE_POSITIVE/RETIRED；
	// 其余迁移返回 ErrInvalidTransition；weaknessID 仅 CONFIRMED 时可携带）。
	SetFindingStatus(ctx context.Context, id uuid.UUID, status string, weaknessID *uuid.UUID) (*Finding, error)
}

// 确保 *Store / *MemStore 实现 Repository。
var (
	_ Repository = (*Store)(nil)
	_ Repository = (*MemStore)(nil)
)

// Store 主动扫描 PostgreSQL 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// ---------- 目标 ----------

func (s *Store) CreateTarget(ctx context.Context, t *Target) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if t.Status == "" {
		t.Status = TargetStatusEnabled
	}
	paths, _ := json.Marshal(t.AllowedPaths)
	now := time.Now().UTC()
	err := s.db.QueryRow(ctx, `
INSERT INTO api_scan_targets (id, application_id, name, base_url, allowed_paths, status, created_by, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8) RETURNING created_at, updated_at`,
		t.ID, t.ApplicationID, t.Name, t.BaseURL, paths, t.Status, t.CreatedBy, now).
		Scan(&t.CreatedAt, &t.UpdatedAt)
	return err
}

func (s *Store) UpdateTarget(ctx context.Context, t *Target) error {
	paths, _ := json.Marshal(t.AllowedPaths)
	ct, err := s.db.Exec(ctx, `
UPDATE api_scan_targets SET name=$2, base_url=$3, allowed_paths=$4, status=$5, updated_at=$6 WHERE id=$1`,
		t.ID, t.Name, t.BaseURL, paths, t.Status, time.Now().UTC())
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// scanTarget 扫描一行目标。
func scanTarget(row pgx.Row) (*Target, error) {
	var t Target
	var paths []byte
	err := row.Scan(&t.ID, &t.ApplicationID, &t.Name, &t.BaseURL, &paths, &t.Status,
		&t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	t.AllowedPaths = []string{}
	_ = json.Unmarshal(paths, &t.AllowedPaths)
	return &t, nil
}

const targetCols = `id, application_id, name, base_url, allowed_paths, status, created_by, created_at, updated_at`

func (s *Store) GetTarget(ctx context.Context, id uuid.UUID) (*Target, error) {
	t, err := scanTarget(s.db.QueryRow(ctx, `SELECT `+targetCols+` FROM api_scan_targets WHERE id=$1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return t, nil
}

func (s *Store) ListTargets(ctx context.Context, applicationID *uuid.UUID, status string, page, pageSize int) ([]Target, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	where := []string{}
	args := []any{}
	if applicationID != nil {
		args = append(args, *applicationID)
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
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_scan_targets"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `SELECT `+targetCols+` FROM api_scan_targets`+cond+
		fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Target{}
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *t)
	}
	return out, total, rows.Err()
}

// ---------- 授权 ----------

func (s *Store) CreateAuthorization(ctx context.Context, a *Authorization) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	allowlist, _ := json.Marshal(a.Allowlist)
	window, _ := json.Marshal(a.TimeWindow)
	err := s.db.QueryRow(ctx, `
INSERT INTO api_scan_authorizations (id, target_id, authorized_by, allowlist, time_window, max_qps, max_concurrency, test_profile, expires_at, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING created_at`,
		a.ID, a.TargetID, a.AuthorizedBy, allowlist, window, a.MaxQPS, a.MaxConcurrency,
		a.TestProfile, a.ExpiresAt, time.Now().UTC()).Scan(&a.CreatedAt)
	return err
}

// scanAuthorization 扫描一行授权单。
func scanAuthorization(row pgx.Row) (*Authorization, error) {
	var a Authorization
	var allowlist, window []byte
	err := row.Scan(&a.ID, &a.TargetID, &a.AuthorizedBy, &allowlist, &window,
		&a.MaxQPS, &a.MaxConcurrency, &a.TestProfile, &a.ExpiresAt, &a.RevokedAt, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	a.Allowlist = []string{}
	_ = json.Unmarshal(allowlist, &a.Allowlist)
	_ = json.Unmarshal(window, &a.TimeWindow)
	return &a, nil
}

const authzCols = `id, target_id, authorized_by, allowlist, time_window, max_qps, max_concurrency, test_profile, expires_at, revoked_at, created_at`

func (s *Store) GetAuthorization(ctx context.Context, id uuid.UUID) (*Authorization, error) {
	a, err := scanAuthorization(s.db.QueryRow(ctx, `SELECT `+authzCols+` FROM api_scan_authorizations WHERE id=$1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return a, nil
}

func (s *Store) ListAuthorizations(ctx context.Context, targetID uuid.UUID, page, pageSize int) ([]Authorization, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	var total int64
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM api_scan_authorizations WHERE target_id=$1`, targetID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `SELECT `+authzCols+` FROM api_scan_authorizations
WHERE target_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, targetID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Authorization{}
	for rows.Next() {
		a, err := scanAuthorization(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *a)
	}
	return out, total, rows.Err()
}

func (s *Store) RevokeAuthorization(ctx context.Context, id uuid.UUID, now time.Time) (*Authorization, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// 幂等：已撤销不覆盖原撤销时间
	ct, err := s.db.Exec(ctx, `
UPDATE api_scan_authorizations SET revoked_at=$2 WHERE id=$1 AND revoked_at IS NULL`, id, now)
	if err != nil {
		return nil, err
	}
	a, err := s.GetAuthorization(ctx, id)
	if err != nil {
		return nil, err
	}
	if ct.RowsAffected() == 0 && a.RevokedAt == nil {
		return nil, ErrNotFound
	}
	return a, nil
}

// ---------- 任务 ----------

func (s *Store) CreateJob(ctx context.Context, j *Job) error {
	if j.ID == uuid.Nil {
		j.ID = uuid.New()
	}
	if j.Status == "" {
		j.Status = JobStatusPending
	}
	progress, _ := json.Marshal(j.Progress)
	err := s.db.QueryRow(ctx, `
INSERT INTO api_scan_jobs (id, target_id, authorization_id, probe_set, status, progress, created_by, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at`,
		j.ID, j.TargetID, j.AuthorizationID, j.ProbeSet, j.Status, progress, j.CreatedBy, time.Now().UTC()).
		Scan(&j.CreatedAt)
	return err
}

// scanJob 扫描一行任务。
func scanJob(row pgx.Row) (*Job, error) {
	var j Job
	var progress []byte
	err := row.Scan(&j.ID, &j.TargetID, &j.AuthorizationID, &j.ProbeSet, &j.Status, &progress,
		&j.StartedAt, &j.FinishedAt, &j.CreatedBy, &j.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(progress, &j.Progress)
	return &j, nil
}

const jobCols = `id, target_id, authorization_id, probe_set, status, progress, started_at, finished_at, created_by, created_at`

func (s *Store) GetJob(ctx context.Context, id uuid.UUID) (*Job, error) {
	j, err := scanJob(s.db.QueryRow(ctx, `SELECT `+jobCols+` FROM api_scan_jobs WHERE id=$1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return j, nil
}

func (s *Store) ListJobs(ctx context.Context, f JobFilter) ([]Job, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	where := []string{}
	args := []any{}
	if f.TargetID != nil {
		args = append(args, *f.TargetID)
		where = append(where, fmt.Sprintf("target_id = $%d", len(args)))
	}
	if f.Status != "" {
		args = append(args, f.Status)
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_scan_jobs"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `SELECT `+jobCols+` FROM api_scan_jobs`+cond+
		fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *j)
	}
	return out, total, rows.Err()
}

// ClaimPendingJob 取一个 PENDING 任务置 RUNNING：行锁 + SKIP LOCKED 防多实例竞争，
// 同目标互斥（该目标无 RUNNING 任务才可取），一个事务内完成。
func (s *Store) ClaimPendingJob(ctx context.Context, now time.Time) (*Job, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var id uuid.UUID
	err = tx.QueryRow(ctx, `
SELECT j.id FROM api_scan_jobs j
WHERE j.status = 'PENDING'
  AND NOT EXISTS (SELECT 1 FROM api_scan_jobs r WHERE r.target_id = j.target_id AND r.status = 'RUNNING')
ORDER BY j.created_at LIMIT 1 FOR UPDATE OF j SKIP LOCKED`).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
UPDATE api_scan_jobs SET status='RUNNING', started_at=$2 WHERE id=$1`, id, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetJob(ctx, id)
}

func (s *Store) StartJob(ctx context.Context, id uuid.UUID, now time.Time) (*Job, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ct, err := s.db.Exec(ctx, `
UPDATE api_scan_jobs SET status='RUNNING', started_at=$2 WHERE id=$1 AND status IN ('PENDING','PAUSED')`, id, now)
	if err != nil {
		return nil, err
	}
	if ct.RowsAffected() == 0 {
		if _, err := s.GetJob(ctx, id); err != nil {
			return nil, err
		}
		return nil, ErrInvalidTransition
	}
	return s.GetJob(ctx, id)
}

func (s *Store) SaveJobProgress(ctx context.Context, id uuid.UUID, p Progress) (*Job, error) {
	progress, _ := json.Marshal(p)
	if _, err := s.db.Exec(ctx, `
UPDATE api_scan_jobs SET progress=$2 WHERE id=$1 AND status='RUNNING'`, id, progress); err != nil {
		return nil, err
	}
	return s.GetJob(ctx, id)
}

func (s *Store) FinishJob(ctx context.Context, id uuid.UUID, status string, p Progress, now time.Time) (*Job, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	progress, _ := json.Marshal(p)
	// 仅 RUNNING 可终结：外部已停止（STOPPED）的任务不被完成态覆盖（停止优先）
	if _, err := s.db.Exec(ctx, `
UPDATE api_scan_jobs SET status=$2, progress=$3, finished_at=$4 WHERE id=$1 AND status='RUNNING'`,
		id, status, progress, now); err != nil {
		return nil, err
	}
	return s.GetJob(ctx, id)
}

func (s *Store) StopJob(ctx context.Context, id uuid.UUID, now time.Time) (*Job, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ct, err := s.db.Exec(ctx, `
UPDATE api_scan_jobs SET status='STOPPED', finished_at=$2 WHERE id=$1 AND status IN ('PENDING','PAUSED','RUNNING')`, id, now)
	if err != nil {
		return nil, err
	}
	if ct.RowsAffected() == 0 {
		if _, err := s.GetJob(ctx, id); err != nil {
			return nil, err
		}
		return nil, ErrInvalidTransition
	}
	return s.GetJob(ctx, id)
}

func (s *Store) StopJobsByAuthorization(ctx context.Context, authorizationID uuid.UUID, now time.Time) (int64, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ct, err := s.db.Exec(ctx, `
UPDATE api_scan_jobs SET status='STOPPED', finished_at=$2
WHERE authorization_id=$1 AND status IN ('PENDING','PAUSED','RUNNING')`, authorizationID, now)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// ---------- 发现 ----------

func (s *Store) CreateFinding(ctx context.Context, f *Finding) error {
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	if f.Engine == "" {
		f.Engine = "builtin"
	}
	if f.Status == "" {
		f.Status = FindingStatusNew
	}
	evidence, _ := json.Marshal(f.Evidence)
	if f.Evidence == nil {
		evidence = []byte("{}")
	}
	err := s.db.QueryRow(ctx, `
INSERT INTO api_scan_findings (id, job_id, engine, template, endpoint_key, category, severity, confidence, evidence_json, request_sample, response_sample, status, weakness_id, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING created_at`,
		f.ID, f.JobID, f.Engine, f.Template, f.EndpointKey, f.Category, f.Severity, f.Confidence,
		evidence, f.RequestSample, f.ResponseSample, f.Status, f.WeaknessID, time.Now().UTC()).
		Scan(&f.CreatedAt)
	return err
}

// scanFinding 扫描一行发现。
func scanFinding(row pgx.Row) (*Finding, error) {
	var f Finding
	var evidence []byte
	err := row.Scan(&f.ID, &f.JobID, &f.Engine, &f.Template, &f.EndpointKey, &f.Category,
		&f.Severity, &f.Confidence, &evidence, &f.RequestSample, &f.ResponseSample,
		&f.Status, &f.WeaknessID, &f.CreatedAt)
	if err != nil {
		return nil, err
	}
	var ev any
	_ = json.Unmarshal(evidence, &ev)
	f.Evidence = ev
	return &f, nil
}

const findingCols = `id, job_id, engine, template, endpoint_key, category, severity, confidence, evidence_json, request_sample, response_sample, status, weakness_id, created_at`

func (s *Store) GetFinding(ctx context.Context, id uuid.UUID) (*Finding, error) {
	f, err := scanFinding(s.db.QueryRow(ctx, `SELECT `+findingCols+` FROM api_scan_findings WHERE id=$1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return f, nil
}

func (s *Store) ListFindings(ctx context.Context, fl FindingFilter) ([]Finding, int64, error) {
	if fl.Page <= 0 {
		fl.Page = 1
	}
	if fl.PageSize <= 0 {
		fl.PageSize = 20
	}
	where := []string{}
	args := []any{}
	if fl.JobID != nil {
		args = append(args, *fl.JobID)
		where = append(where, fmt.Sprintf("job_id = $%d", len(args)))
	}
	if fl.Status != "" {
		args = append(args, fl.Status)
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	if fl.Severity != "" {
		args = append(args, fl.Severity)
		where = append(where, fmt.Sprintf("severity = $%d", len(args)))
	}
	if fl.Template != "" {
		args = append(args, fl.Template)
		where = append(where, fmt.Sprintf("template = $%d", len(args)))
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_scan_findings"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, fl.PageSize, (fl.Page-1)*fl.PageSize)
	rows, err := s.db.Query(ctx, `SELECT `+findingCols+` FROM api_scan_findings`+cond+
		fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *f)
	}
	return out, total, rows.Err()
}

func (s *Store) SetFindingStatus(ctx context.Context, id uuid.UUID, status string, weaknessID *uuid.UUID) (*Finding, error) {
	// 仅 NEW 可处置（一次性确认/误报/退役；重复处置返回 ErrInvalidTransition）
	ct, err := s.db.Exec(ctx, `
UPDATE api_scan_findings SET status=$2, weakness_id=$3 WHERE id=$1 AND status='NEW'`, id, status, weaknessID)
	if err != nil {
		return nil, err
	}
	if ct.RowsAffected() == 0 {
		if _, err := s.GetFinding(ctx, id); err != nil {
			return nil, err
		}
		return nil, ErrInvalidTransition
	}
	return s.GetFinding(ctx, id)
}
