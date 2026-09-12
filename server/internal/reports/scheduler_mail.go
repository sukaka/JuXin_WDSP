package reports

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/notify"
)

// 定时计划邮件发送：报告任务成功写入产物后触发。
// 语义：失败只记录到计划 last_email_status/error 并审计，不回滚报告任务。

// sendScheduledMail 定时计划邮件发送入口（仅计划任务且开启邮件时生效）。
func (g *Generator) sendScheduledMail(ctx context.Context, job *Job, fileName, reportNo string) {
	if job.ScheduleID == nil {
		return
	}
	sch, err := g.jobSchedule(ctx, job)
	if err != nil {
		slog.Error("load report schedule for mail failed", "job_id", job.ID, "error", err)
		return
	}
	emails := scheduleEmails(sch)
	if emails == nil {
		return
	}
	sendErr := g.sendReportMail(ctx, sch, job, fileName, reportNo, emails)
	status := EmailStatusSent
	if sendErr != nil {
		status = EmailStatusFailed
		slog.Error("send scheduled report mail failed", "schedule_id", sch.ID, "job_id", job.ID, "error", sendErr)
	}
	if err := g.store.RecordEmailResult(ctx, sch.ID, status, sendErr); err != nil {
		slog.Error("record email result failed", "schedule_id", sch.ID, "error", err)
	}
	g.auditSchedule(ctx, sch, "email_send", status)
}

// sendReportMail 读取产物并发送邮件（SMTP 配置来自通知渠道）。
func (g *Generator) sendReportMail(ctx context.Context, sch *ReportSchedule, job *Job, fileName, reportNo string, emails []string) error {
	if g.notifyStore == nil {
		return fmt.Errorf("通知存储未注入")
	}
	cfg, err := g.smtpConfig(ctx)
	if err != nil {
		return err
	}
	content, err := readReportFile(g.dataDir, fileName)
	if err != nil {
		return fmt.Errorf("读取报告文件失败: %w", err)
	}
	subject := fmt.Sprintf("安全报告 %s（%s）", reportNo,
		job.Start.UTC().Format("2006-01-02")+" 至 "+job.End.UTC().Format("2006-01-02"))
	body := fmt.Sprintf(
		"计划「%s」的定时报告已生成，详见附件。\n\n"+
			"报告编号：%s\n报告类型：%s\n统计周期：%s 至 %s（UTC）\n内容范围：%s\n文件格式：%s（%s）\n生成时间：%s（UTC）\n\n"+
			"本邮件由九章安全系统自动发送，请勿直接回复。",
		sch.Name, reportNo, ReportTypeName(job.ReportType),
		job.Start.UTC().Format("2006-01-02"), job.End.UTC().Format("2006-01-02"),
		ContentScopeName(job.ContentScope), fileName, formatSize(int64(len(content))),
		time.Now().UTC().Format("2006-01-02 15:04"))
	return notify.SendMail(*cfg, emails, subject, body, fileName, content)
}

// smtpConfig 读取首个启用的 SMTP 通知渠道配置（未配置返回明确错误）。
func (g *Generator) smtpConfig(ctx context.Context) (*notify.SMTPConfig, error) {
	channels, err := g.notifyStore.ListDecrypted(ctx)
	if err != nil {
		return nil, fmt.Errorf("读取通知渠道失败: %w", err)
	}
	for _, ch := range channels {
		if ch.Type == notify.TypeSMTP && ch.Enabled {
			cfg, err := notify.ParseSMTPConfig(ch.Config)
			if err != nil {
				return nil, fmt.Errorf("SMTP 渠道配置无效: %w", err)
			}
			return &cfg, nil
		}
	}
	return nil, fmt.Errorf("未配置启用的 SMTP 邮件渠道（请在 系统告警→通知渠道 中配置）")
}

// formatSize 人类可读文件大小（邮件正文用）。
func formatSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// auditSchedule 计划相关后台审计（schedule_fire / email_send）。
func (g *Generator) auditSchedule(ctx context.Context, sch *ReportSchedule, action, result string) {
	if g.audits == nil {
		return
	}
	risk := audits.RiskLow
	if result == EmailStatusFailed {
		risk = audits.RiskMedium
	}
	if err := g.audits.Record(ctx, audits.RecordInput{
		UserID:     sch.CreatedBy,
		Username:   "",
		Module:     "reports",
		Action:     action,
		ObjectType: "report_schedule",
		ObjectID:   sch.ID.String(),
		ObjectName: sch.Name,
		Result:     result,
		RiskLevel:  risk,
	}); err != nil {
		slog.Error("record schedule audit failed", "action", action, "schedule_id", sch.ID, "error", err)
	}
}
