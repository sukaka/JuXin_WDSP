package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 定时报告计划存储：CRUD + 到期认领（FOR UPDATE SKIP LOCKED 防重入）+ 结果回写。

const scheduleColumns = `id, name, report_type, content_scope, application_ids, template_id, file_format,
	include_api_assets, page_orientation, time_of_day, day_of_week, day_of_month, send_email, emails, enabled,
	next_run_at, last_run_at, last_job_id, last_email_status, last_email_error,
	created_by, created_at, updated_at`

func scanSchedule(row pgx.Row) (*ReportSchedule, error) {
	var s ReportSchedule
	var appIDs, emails []byte
	err := row.Scan(&s.ID, &s.Name, &s.ReportType, &s.ContentScope, &appIDs, &s.TemplateID, &s.FileFormat,
		&s.IncludeAPIAssets, &s.PageOrientation, &s.TimeOfDay, &s.DayOfWeek, &s.DayOfMonth, &s.SendEmail, &emails, &s.Enabled,
		&s.NextRunAt, &s.LastRunAt, &s.LastJobID, &s.LastEmailStatus, &s.LastEmailError,
		&s.CreatedBy, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if len(appIDs) > 0 {
		if err := json.Unmarshal(appIDs, &s.ApplicationIDs); err != nil {
			return nil, fmt.Errorf("parse schedule application_ids: %w", err)
		}
	}
	if len(emails) > 0 {
		if err := json.Unmarshal(emails, &s.Emails); err != nil {
			return nil, fmt.Errorf("parse schedule emails: %w", err)
		}
	}
	return &s, nil
}

// CreateSchedule 创建定时计划（先校验；next_run_at 立即计算）。
func (s *Store) CreateSchedule(ctx context.Context, sch *ReportSchedule, createdBy uuid.UUID) error {
	if err := sch.Validate(); err != nil {
		return err
	}
	appIDs, _ := json.Marshal(sch.ApplicationIDs)
	if sch.ApplicationIDs == nil {
		appIDs = []byte("[]")
	}
	emails, _ := json.Marshal(sch.Emails)
	if sch.Emails == nil {
		emails = []byte("[]")
	}
	next := NextRunAt(sch.ReportType, sch.TimeOfDay, sch.DayOfWeek, sch.DayOfMonth, time.Now())
	return s.db.QueryRow(ctx, `
INSERT INTO report_schedules (name, report_type, content_scope, application_ids, template_id, file_format,
	include_api_assets, page_orientation, time_of_day, day_of_week, day_of_month, send_email, emails, enabled, next_run_at, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
RETURNING id, created_at, updated_at`,
		sch.Name, sch.ReportType, sch.ContentScope, appIDs, sch.TemplateID, sch.FileFormat,
		sch.IncludeAPIAssets, sch.PageOrientation, sch.TimeOfDay, sch.DayOfWeek, sch.DayOfMonth, sch.SendEmail, emails, sch.Enabled, next, createdBy).
		Scan(&sch.ID, &sch.CreatedAt, &sch.UpdatedAt)
}

// UpdateSchedule 更新定时计划（重算 next_run_at；updated_at 触发器不存在，显式更新）。
func (s *Store) UpdateSchedule(ctx context.Context, sch *ReportSchedule) error {
	if err := sch.Validate(); err != nil {
		return err
	}
	appIDs, _ := json.Marshal(sch.ApplicationIDs)
	if sch.ApplicationIDs == nil {
		appIDs = []byte("[]")
	}
	emails, _ := json.Marshal(sch.Emails)
	if sch.Emails == nil {
		emails = []byte("[]")
	}
	next := NextRunAt(sch.ReportType, sch.TimeOfDay, sch.DayOfWeek, sch.DayOfMonth, time.Now())
	res, err := s.db.Exec(ctx, `
UPDATE report_schedules SET name=$2, report_type=$3, content_scope=$4, application_ids=$5, template_id=$6,
	file_format=$7, include_api_assets=$8, page_orientation=$9, time_of_day=$10, day_of_week=$11, day_of_month=$12, send_email=$13, emails=$14,
	enabled=$15, next_run_at=$16, updated_at=now()
WHERE id=$1`,
		sch.ID, sch.Name, sch.ReportType, sch.ContentScope, appIDs, sch.TemplateID, sch.FileFormat,
		sch.IncludeAPIAssets, sch.PageOrientation, sch.TimeOfDay, sch.DayOfWeek, sch.DayOfMonth, sch.SendEmail, emails, sch.Enabled, next)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetSchedule 计划详情。
func (s *Store) GetSchedule(ctx context.Context, id uuid.UUID) (*ReportSchedule, error) {
	sch, err := scanSchedule(s.db.QueryRow(ctx,
		`SELECT `+scheduleColumns+` FROM report_schedules WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return sch, nil
}

// ListSchedules 计划列表（按创建时间倒序）。
func (s *Store) ListSchedules(ctx context.Context, page, pageSize int) ([]*ReportSchedule, int64, error) {
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM report_schedules`).Scan(&total); err != nil {
		return nil, 0, err
	}
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(ctx,
		`SELECT `+scheduleColumns+` FROM report_schedules ORDER BY created_at DESC LIMIT $1 OFFSET $2`, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*ReportSchedule
	for rows.Next() {
		sch, err := scanSchedule(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, sch)
	}
	return out, total, rows.Err()
}

// DeleteSchedule 删除计划。
func (s *Store) DeleteSchedule(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.Exec(ctx, `DELETE FROM report_schedules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkScheduleDueNow 立即到期（run-now：交调度器下一轮拾取）。
func (s *Store) MarkScheduleDueNow(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.Exec(ctx,
		`UPDATE report_schedules SET next_run_at = now(), updated_at = now() WHERE id = $1 AND enabled`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrInvalidState
	}
	return nil
}

// ClaimDueSchedules 原子认领一个到期计划（推进 next_run_at 后返回计划本体；无到期返回 nil, nil）。
func (s *Store) ClaimDueSchedules(ctx context.Context, now time.Time) (*ReportSchedule, error) {
	return s.claimDue(ctx, now)
}

func (s *Store) claimDue(ctx context.Context, now time.Time) (*ReportSchedule, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	sch, err := scanSchedule(tx.QueryRow(ctx, `
SELECT `+scheduleColumns+` FROM report_schedules
WHERE enabled AND next_run_at IS NOT NULL AND next_run_at <= $1
ORDER BY next_run_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED`, now))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	next := NextRunAt(sch.ReportType, sch.TimeOfDay, sch.DayOfWeek, sch.DayOfMonth, now)
	if _, err := tx.Exec(ctx,
		`UPDATE report_schedules SET next_run_at = $2, last_run_at = $3, updated_at = now() WHERE id = $1`,
		sch.ID, next, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return sch, nil
}

// RecordScheduleJob 回写计划最近产物任务。
func (s *Store) RecordScheduleJob(ctx context.Context, id, jobID uuid.UUID) error {
	_, err := s.db.Exec(ctx,
		`UPDATE report_schedules SET last_job_id = $2, updated_at = now() WHERE id = $1`, id, jobID)
	return err
}

// RecordEmailResult 回写邮件发送结果（SENT 清空错误，FAILED 记录原因并截断）。
func (s *Store) RecordEmailResult(ctx context.Context, id uuid.UUID, status string, sendErr error) error {
	errText := ""
	if sendErr != nil {
		errText = sendErr.Error()
		if len([]rune(errText)) > 500 {
			errText = string([]rune(errText)[:500])
		}
	}
	_, err := s.db.Exec(ctx,
		`UPDATE report_schedules SET last_email_status = $2, last_email_error = $3, updated_at = now() WHERE id = $1`,
		id, status, errText)
	return err
}
