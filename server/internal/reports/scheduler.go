package reports

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
)

// 定时报告调度器：周期认领到期计划，按计划的类型/范围/模板/格式创建报告任务。
// 认领经 FOR UPDATE SKIP LOCKED（多实例/重复执行安全）；进程重启后到期计划
// 在下一轮自然被拾取，无需额外僵尸恢复。

// Scheduler 定时报告调度器。
type Scheduler struct {
	store    *Store
	interval time.Duration
	now      func() time.Time
	audits   *audits.Service
}

// NewScheduler 创建调度器。
func NewScheduler(store *Store, auditSvc *audits.Service) *Scheduler {
	return &Scheduler{store: store, interval: 30 * time.Second, now: func() time.Time { return time.Now().UTC() }, audits: auditSvc}
}

// Run 后台循环（main.go 以 goroutine 启动）。
func (s *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	slog.Info("report scheduler started", "interval", s.interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.fireDue(ctx)
		}
	}
}

// fireDue 认领并触发一个到期计划（每轮最多一个，防突发积压阻塞）。
func (s *Scheduler) fireDue(ctx context.Context) {
	sch, err := s.store.ClaimDueSchedules(ctx, s.now())
	if err != nil {
		slog.Error("claim due report schedule failed", "error", err)
		return
	}
	if sch == nil {
		return
	}
	job := &Job{
		ReportType:       sch.ReportType,
		ContentScope:     sch.ContentScope,
		IncludeAPIAssets: sch.IncludeAPIAssets,
		PageOrientation:  sch.PageOrientation,
		ApplicationIDs:   sch.ApplicationIDs,
		TemplateID:       sch.TemplateID,
		ScheduleID:       &sch.ID,
		Status:           StatusPending,
		FileFormat:       sch.FileFormat,
		RequestedBy:      sch.CreatedBy,
	}
	// 时间范围与手工创建同口径（DAILY=昨天 / WEEKLY=上周 / MONTHLY=上月）
	start, end, err := ComputeTimeRange(sch.ReportType, nil, nil, s.now())
	if err != nil {
		slog.Error("compute schedule time range failed", "schedule_id", sch.ID, "error", err)
		return
	}
	job.Start, job.End = start, end
	if err := s.store.CreateJob(ctx, job); err != nil {
		slog.Error("create scheduled report job failed", "schedule_id", sch.ID, "error", err)
		return
	}
	if err := s.store.RecordScheduleJob(ctx, sch.ID, job.ID); err != nil {
		slog.Error("record schedule job failed", "schedule_id", sch.ID, "job_id", job.ID, "error", err)
	}
	slog.Info("scheduled report job created",
		"schedule_id", sch.ID, "schedule", sch.Name, "job_id", job.ID, "report_type", job.ReportType)
	s.auditFire(ctx, sch)
}

// auditFire 计划触发后台审计。
func (s *Scheduler) auditFire(ctx context.Context, sch *ReportSchedule) {
	if s.audits == nil {
		return
	}
	if err := s.audits.Record(ctx, audits.RecordInput{
		UserID:     sch.CreatedBy,
		Module:     "reports",
		Action:     "schedule_fire",
		ObjectType: "report_schedule",
		ObjectID:   sch.ID.String(),
		ObjectName: sch.Name,
		Result:     audits.ResultSuccess,
		RiskLevel:  audits.RiskLow,
	}); err != nil {
		slog.Error("record schedule fire audit failed", "schedule_id", sch.ID, "error", err)
	}
}

// jobSchedule 加载任务来源计划（无来源返回 nil, nil；计划已删除返回 nil, nil）。
func (g *Generator) jobSchedule(ctx context.Context, job *Job) (*ReportSchedule, error) {
	if job.ScheduleID == nil {
		return nil, nil
	}
	sch, err := g.store.GetSchedule(ctx, *job.ScheduleID)
	if err != nil {
		if err == ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	return sch, nil
}

// scheduleEmails 计划收件人（未开启或为空返回 nil）。
func scheduleEmails(sch *ReportSchedule) []string {
	if sch == nil || !sch.SendEmail || len(sch.Emails) == 0 {
		return nil
	}
	return sch.Emails
}

// uuidOrNil 文本化任务 ID（邮件主题用）。
func uuidOrNil(id uuid.UUID) string { return id.String() }
