package reports

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

// 错误
var (
	ErrNotFound        = errors.New("report resource not found")
	ErrBuiltinTemplate = errors.New("builtin template cannot be modified or deleted")
	ErrInvalidInput    = errors.New("invalid report input")
	ErrInvalidState    = errors.New("invalid job state")
)

// Store 报告仓储（模板 + 任务）。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建报告仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// BuiltinTemplate 内置默认模板定义。
func BuiltinTemplate() *Template {
	return &Template{
		Name:           "默认报告模板",
		IsBuiltin:      true,
		CompanyName:    "",
		ProductName:    "九章WEB应用智能防护系统",
		LogoText:       "九章",
		HeaderText:     "",
		FooterText:     "",
		ReportNoFormat: DefaultReportNoFormat,
		PreparedBy:     "",
		ReviewedBy:     "",
		Description:    "系统内置默认报告模板，包含全部21个章节。",
		Sections:       DefaultSections(),
	}
}

// EnsureBuiltinTemplate 确保内置模板存在（幂等）。
func (s *Store) EnsureBuiltinTemplate(ctx context.Context) error {
	var exists bool
	if err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM report_templates WHERE is_builtin AND deleted_at IS NULL)`).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	t := BuiltinTemplate()
	sections, _ := json.Marshal(t.Sections)
	_, err := s.db.Exec(ctx, `
INSERT INTO report_templates (name, is_builtin, company_name, product_name, logo_text,
	header_text, footer_text, report_no_format, prepared_by, reviewed_by, description, sections)
VALUES ($1, TRUE, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		t.Name, t.CompanyName, t.ProductName, t.LogoText, t.HeaderText, t.FooterText,
		t.ReportNoFormat, t.PreparedBy, t.ReviewedBy, t.Description, sections)
	return err
}

// ValidateTemplateInput 校验模板输入（模板字段仅作为数据使用，不得包含占位执行逻辑）。
func ValidateTemplateInput(t *Template) error {
	if strings.TrimSpace(t.Name) == "" || len(t.Name) > 100 {
		return fmt.Errorf("%w: 模板名称不能为空且不超过100字符", ErrInvalidInput)
	}
	if len(t.CompanyName) > 200 || len(t.ProductName) > 200 || len(t.HeaderText) > 200 || len(t.FooterText) > 200 {
		return fmt.Errorf("%w: 模板文本字段长度超限", ErrInvalidInput)
	}
	if len(t.LogoText) > 50 || len(t.ReportNoFormat) > 50 || len(t.Description) > 500 {
		return fmt.Errorf("%w: 模板字段长度超限", ErrInvalidInput)
	}
	if len(t.PreparedBy) > 100 || len(t.ReviewedBy) > 100 {
		return fmt.Errorf("%w: 编制/审核人字段长度超限", ErrInvalidInput)
	}
	for k := range t.Sections {
		if !validSectionKey(k) {
			return fmt.Errorf("%w: 未知章节键 %q", ErrInvalidInput, k)
		}
	}
	return nil
}

// CreateTemplate 创建模板。
func (s *Store) CreateTemplate(ctx context.Context, t *Template, userID uuid.UUID) error {
	if err := ValidateTemplateInput(t); err != nil {
		return err
	}
	// 未提供章节配置时使用默认（避免写入 NULL 违反 NOT NULL，并保证备份可恢复）
	if t.Sections == nil {
		t.Sections = DefaultSections()
	}
	sections, _ := json.Marshal(t.Sections)
	return s.db.QueryRow(ctx, `
INSERT INTO report_templates (name, company_name, product_name, logo_text, header_text,
	footer_text, report_no_format, prepared_by, reviewed_by, description, sections, created_by, updated_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)
RETURNING id, created_at, updated_at`,
		t.Name, t.CompanyName, t.ProductName, t.LogoText, t.HeaderText, t.FooterText,
		t.ReportNoFormat, t.PreparedBy, t.ReviewedBy, t.Description, sections, userID).
		Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
}

// scanTemplate 扫描模板行。
func scanTemplate(row pgx.Row) (*Template, error) {
	var t Template
	var sections []byte
	err := row.Scan(&t.ID, &t.Name, &t.IsBuiltin, &t.CompanyName, &t.ProductName, &t.LogoText,
		&t.HeaderText, &t.FooterText, &t.ReportNoFormat, &t.PreparedBy, &t.ReviewedBy,
		&t.Description, &sections, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt, &t.Version)
	if err != nil {
		return nil, err
	}
	t.Sections = map[string]bool{}
	if len(sections) > 0 {
		if err := json.Unmarshal(sections, &t.Sections); err != nil {
			return nil, fmt.Errorf("parse template sections: %w", err)
		}
	}
	return &t, nil
}

const templateColumns = `id, name, is_builtin, company_name, product_name, logo_text,
	header_text, footer_text, report_no_format, prepared_by, reviewed_by,
	description, sections, created_by, created_at, updated_at, version`

// GetTemplate 查询模板详情。
func (s *Store) GetTemplate(ctx context.Context, id uuid.UUID) (*Template, error) {
	t, err := scanTemplate(s.db.QueryRow(ctx,
		`SELECT `+templateColumns+` FROM report_templates WHERE id = $1 AND deleted_at IS NULL`, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return t, nil
}

// DefaultTemplate 返回默认模板（内置优先，否则最早创建的模板）。
func (s *Store) DefaultTemplate(ctx context.Context) (*Template, error) {
	t, err := scanTemplate(s.db.QueryRow(ctx, `
SELECT `+templateColumns+` FROM report_templates WHERE deleted_at IS NULL
ORDER BY is_builtin DESC, created_at ASC LIMIT 1`))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return t, nil
}

// ListTemplates 分页查询模板。
func (s *Store) ListTemplates(ctx context.Context, page, pageSize int) ([]Template, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	var total int64
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM report_templates WHERE deleted_at IS NULL`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `
SELECT `+templateColumns+` FROM report_templates WHERE deleted_at IS NULL
ORDER BY is_builtin DESC, created_at DESC LIMIT $1 OFFSET $2`, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Template
	for rows.Next() {
		var t Template
		var sections []byte
		if err := rows.Scan(&t.ID, &t.Name, &t.IsBuiltin, &t.CompanyName, &t.ProductName, &t.LogoText,
			&t.HeaderText, &t.FooterText, &t.ReportNoFormat, &t.PreparedBy, &t.ReviewedBy,
			&t.Description, &sections, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt, &t.Version); err != nil {
			return nil, 0, err
		}
		t.Sections = map[string]bool{}
		if len(sections) > 0 {
			if err := json.Unmarshal(sections, &t.Sections); err != nil {
				return nil, 0, fmt.Errorf("parse template sections: %w", err)
			}
		}
		out = append(out, t)
	}
	return out, total, rows.Err()
}

// UpdateTemplate 更新模板（内置模板禁止修改）。
func (s *Store) UpdateTemplate(ctx context.Context, t *Template, userID uuid.UUID) error {
	cur, err := s.GetTemplate(ctx, t.ID)
	if err != nil {
		return err
	}
	if cur.IsBuiltin {
		return ErrBuiltinTemplate
	}
	if err := ValidateTemplateInput(t); err != nil {
		return err
	}
	sections, _ := json.Marshal(t.Sections)
	tag, err := s.db.Exec(ctx, `
UPDATE report_templates SET name=$2, company_name=$3, product_name=$4, logo_text=$5,
	header_text=$6, footer_text=$7, report_no_format=$8, prepared_by=$9, reviewed_by=$10,
	description=$11, sections=$12, updated_by=$13, updated_at=now(), version=version+1
WHERE id=$1 AND deleted_at IS NULL`,
		t.ID, t.Name, t.CompanyName, t.ProductName, t.LogoText, t.HeaderText, t.FooterText,
		t.ReportNoFormat, t.PreparedBy, t.ReviewedBy, t.Description, sections, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteTemplate 删除模板（软删；内置模板禁止删除）。
func (s *Store) DeleteTemplate(ctx context.Context, id uuid.UUID) error {
	cur, err := s.GetTemplate(ctx, id)
	if err != nil {
		return err
	}
	if cur.IsBuiltin {
		return ErrBuiltinTemplate
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE report_templates SET deleted_at=now() WHERE id=$1 AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- 报告任务 ----------

const jobColumns = `id, report_type, time_range_start, time_range_end, application_ids, template_id,
	status, progress, requested_by, requested_at, started_at, finished_at,
	file_reference, file_hash, file_format, file_size, report_no,
	failure_code, failure_message, request_id`

func scanJob(row pgx.Row) (*Job, error) {
	var j Job
	var appIDs []byte
	err := row.Scan(&j.ID, &j.ReportType, &j.Start, &j.End, &appIDs, &j.TemplateID,
		&j.Status, &j.Progress, &j.RequestedBy, &j.RequestedAt, &j.StartedAt, &j.FinishedAt,
		&j.FileReference, &j.FileHash, &j.FileFormat, &j.FileSize, &j.ReportNo,
		&j.FailureCode, &j.FailureMessage, &j.RequestID)
	if err != nil {
		return nil, err
	}
	if len(appIDs) > 0 {
		if err := json.Unmarshal(appIDs, &j.ApplicationIDs); err != nil {
			return nil, fmt.Errorf("parse job application_ids: %w", err)
		}
	}
	return &j, nil
}

// CreateJob 创建报告任务（PENDING）。
func (s *Store) CreateJob(ctx context.Context, j *Job) error {
	if !validReportType(j.ReportType) {
		return fmt.Errorf("%w: 无效的报告类型", ErrInvalidInput)
	}
	if !validFormat(j.FileFormat) {
		return fmt.Errorf("%w: 无效的导出格式", ErrInvalidInput)
	}
	if !j.End.After(j.Start) {
		return fmt.Errorf("%w: 报告时间范围无效", ErrInvalidInput)
	}
	var appIDs interface{}
	if len(j.ApplicationIDs) > 0 {
		b, _ := json.Marshal(j.ApplicationIDs)
		appIDs = b
	}
	return s.db.QueryRow(ctx, `
INSERT INTO report_jobs (report_type, time_range_start, time_range_end, application_ids,
	template_id, status, requested_by, file_format, request_id)
VALUES ($1,$2,$3,$4,$5,'PENDING',$6,$7,$8)
RETURNING id, requested_at`,
		j.ReportType, j.Start, j.End, appIDs, j.TemplateID, j.RequestedBy, j.FileFormat, j.RequestID).
		Scan(&j.ID, &j.RequestedAt)
}

// GetJob 查询任务详情。
func (s *Store) GetJob(ctx context.Context, id uuid.UUID) (*Job, error) {
	j, err := scanJob(s.db.QueryRow(ctx,
		`SELECT `+jobColumns+` FROM report_jobs WHERE id = $1`, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return j, nil
}

// ListJobs 分页查询任务（按类型/状态过滤）。
func (s *Store) ListJobs(ctx context.Context, reportType, status string, page, pageSize int) ([]Job, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	where := "1=1"
	args := []interface{}{}
	idx := 1
	if reportType != "" {
		where += fmt.Sprintf(" AND report_type = $%d", idx)
		args = append(args, reportType)
		idx++
	}
	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, status)
		idx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM report_jobs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx,
		`SELECT `+jobColumns+` FROM report_jobs WHERE `+where+
			fmt.Sprintf(" ORDER BY requested_at DESC LIMIT $%d OFFSET $%d", idx, idx+1),
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *j)
	}
	return out, total, rows.Err()
}

// ClaimPending 认领一个 PENDING 任务（FOR UPDATE SKIP LOCKED），原子置为 COLLECTING。
// 无待处理任务时返回 (nil, nil)。
func (s *Store) ClaimPending(ctx context.Context) (*Job, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var id uuid.UUID
	err = tx.QueryRow(ctx, `
SELECT id FROM report_jobs WHERE status = 'PENDING'
ORDER BY requested_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
UPDATE report_jobs SET status = 'COLLECTING', started_at = now(), progress = 10
WHERE id = $1 AND status = 'PENDING'`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetJob(ctx, id)
}

// UpdateProgress 推进任务状态与进度。
func (s *Store) UpdateProgress(ctx context.Context, id uuid.UUID, status string, progress int) error {
	_, err := s.db.Exec(ctx,
		`UPDATE report_jobs SET status = $2, progress = $3 WHERE id = $1`, id, status, progress)
	return err
}

// CompleteJob 标记任务成功，记录产物信息。
func (s *Store) CompleteJob(ctx context.Context, id uuid.UUID, fileRef, fileHash, format string, size int64, reportNo string) error {
	_, err := s.db.Exec(ctx, `
UPDATE report_jobs SET status = 'SUCCESS', progress = 100, finished_at = now(),
	file_reference = $2, file_hash = $3, file_format = $4, file_size = $5, report_no = $6,
	failure_code = '', failure_message = ''
WHERE id = $1`, id, fileRef, fileHash, format, size, reportNo)
	return err
}

// FailJob 标记任务失败。
func (s *Store) FailJob(ctx context.Context, id uuid.UUID, code, message string) error {
	if len(message) > 500 {
		message = message[:500]
	}
	_, err := s.db.Exec(ctx, `
UPDATE report_jobs SET status = 'FAILED', finished_at = now(),
	failure_code = $2, failure_message = $3
WHERE id = $1`, id, code, message)
	return err
}

// ResetJobForRetry 将 FAILED/CANCELLED 任务重置为 PENDING。
func (s *Store) ResetJobForRetry(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `
UPDATE report_jobs SET status = 'PENDING', progress = 0, started_at = NULL, finished_at = NULL,
	file_reference = '', file_hash = '', file_size = 0, report_no = '',
	failure_code = '', failure_message = ''
WHERE id = $1 AND status IN ('FAILED','CANCELLED')`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidState
	}
	return nil
}

// ReclaimStaleJobs 将超时仍停留在中间态的任务标记为 FAILED（WORKER_LOST），允许重试。
func (s *Store) ReclaimStaleJobs(ctx context.Context, olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		olderThan = 10 * time.Minute
	}
	cutoff := time.Now().UTC().Add(-olderThan)
	tag, err := s.db.Exec(ctx, `
UPDATE report_jobs SET status = 'FAILED', finished_at = now(), progress = 0,
	failure_code = 'WORKER_LOST',
	failure_message = '报告生成超时或 worker 中断，请重试'
WHERE status IN ('COLLECTING','AGGREGATING','RENDERING')
  AND started_at IS NOT NULL
  AND started_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteJob 删除任务记录。
func (s *Store) DeleteJob(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM report_jobs WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// NextMonthlySeq 计算报告在该月内的序号（count + 1，用于 {SEQ} 占位符）。
func (s *Store) NextMonthlySeq(ctx context.Context, t time.Time) (int, error) {
	t = t.UTC()
	monthStart := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)
	var n int
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM report_jobs
WHERE requested_at >= $1 AND requested_at < $2 AND report_no <> ''`, monthStart, monthEnd).Scan(&n); err != nil {
		return 0, err
	}
	return n + 1, nil
}

// ArchiveJob 归档成功任务（report_archives）。
func (s *Store) ArchiveJob(ctx context.Context, jobID, archivedBy uuid.UUID, note string) error {
	if len(note) > 500 {
		note = note[:500]
	}
	_, err := s.db.Exec(ctx, `
INSERT INTO report_archives (report_job_id, archived_by, note) VALUES ($1, $2, $3)`,
		jobID, archivedBy, note)
	return err
}

// ArchiveItem 归档列表条目（report_archives JOIN report_jobs）。
type ArchiveItem struct {
	ArchiveID   uuid.UUID `json:"archive_id"`
	ReportJobID uuid.UUID `json:"report_job_id"`
	ReportNo    string    `json:"report_no"`
	ReportType  string    `json:"report_type"`
	Status      string    `json:"status"`
	ArchivedAt  time.Time `json:"archived_at"`
	Note        string    `json:"note"`
	ArchivedBy  string    `json:"archived_by"`
}

// ListArchives 分页查询报告归档（JOIN report_jobs 取报告信息，LEFT JOIN users 取归档人）。
func (s *Store) ListArchives(ctx context.Context, page, pageSize int) ([]ArchiveItem, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM report_archives`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `
SELECT a.id, a.report_job_id, j.report_no, j.report_type, j.status,
       a.archived_at, a.note, COALESCE(u.username, '')
FROM report_archives a
JOIN report_jobs j ON j.id = a.report_job_id
LEFT JOIN users u ON u.id = a.archived_by
ORDER BY a.archived_at DESC LIMIT $1 OFFSET $2`, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []ArchiveItem
	for rows.Next() {
		var it ArchiveItem
		var jobID *uuid.UUID
		if err := rows.Scan(&it.ArchiveID, &jobID, &it.ReportNo, &it.ReportType, &it.Status,
			&it.ArchivedAt, &it.Note, &it.ArchivedBy); err != nil {
			return nil, 0, err
		}
		if jobID != nil {
			it.ReportJobID = *jobID
		}
		out = append(out, it)
	}
	return out, total, rows.Err()
}
