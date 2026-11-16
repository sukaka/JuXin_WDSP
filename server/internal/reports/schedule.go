package reports

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 定时报告计划：按 每天/每周/每月 固定时刻（UTC）自动创建报告任务，
// 生成成功后可选发送到 1~N 个邮箱（SMTP 配置复用系统告警通知邮件渠道）。

// ReportSchedule 定时报告计划。
type ReportSchedule struct {
	ID               uuid.UUID   `json:"id"`
	Name             string      `json:"name"`
	ReportType       string      `json:"report_type"` // DAILY / WEEKLY / MONTHLY
	APIReportType    string      `json:"api_report_type"`
	ContentScope     string      `json:"content_scope"` // WAF / API / WAF_API
	ApplicationIDs   []uuid.UUID `json:"application_ids"`
	TemplateID       *uuid.UUID  `json:"template_id"`
	FileFormat       string      `json:"file_format"`
	IncludeAPIAssets bool        `json:"include_api_assets"` // 是否包含全量 API 资产清单
	PageOrientation  string      `json:"page_orientation"`   // P 竖向 / L 横向（PDF/Word）
	TimeOfDay        string      `json:"time_of_day"`        // HH:MM（UTC）
	DayOfWeek        int         `json:"day_of_week"`        // WEEKLY 用，1=周一..7=周日
	DayOfMonth       int         `json:"day_of_month"`
	SendEmail        bool        `json:"send_email"`
	Emails           []string    `json:"emails"`
	Enabled          bool        `json:"enabled"`
	NextRunAt        *time.Time  `json:"next_run_at"`
	LastRunAt        *time.Time  `json:"last_run_at"`
	LastJobID        *uuid.UUID  `json:"last_job_id"`
	LastEmailStatus  string      `json:"last_email_status"`
	LastEmailError   string      `json:"last_email_error"`
	CreatedBy        *uuid.UUID  `json:"created_by"`
	CreatedAt        time.Time   `json:"created_at"`
	UpdatedAt        time.Time   `json:"updated_at"`
}

// 邮件发送结果状态。
const (
	EmailStatusSent   = "SENT"
	EmailStatusFailed = "FAILED"
)

// 限制。
const (
	maxScheduleName  = 64
	maxScheduleMails = 10
)

var (
	timeOfDayRe = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)
	emailRe     = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
)

// Validate 校验计划字段（返回首个错误；创建/更新共用）。
func (s *ReportSchedule) Validate() error {
	name := strings.TrimSpace(s.Name)
	if name == "" || len([]rune(name)) > maxScheduleName {
		return fmt.Errorf("%w: 计划名称必填且不超过 %d 字符", ErrInvalidInput, maxScheduleName)
	}
	s.Name = name
	switch s.ReportType {
	case TypeDaily, TypeWeekly, TypeMonthly:
	default:
		return fmt.Errorf("%w: 定时计划仅支持 DAILY/WEEKLY/MONTHLY", ErrInvalidInput)
	}
	if !validContentScope(s.ContentScope) {
		return fmt.Errorf("%w: 无效的内容范围（WAF/API/WAF_API）", ErrInvalidInput)
	}
	s.ContentScope = NormalizeContentScope(s.ContentScope)
	if s.APIReportType != "" {
		if !IsAPIReportType(s.APIReportType) {
			return fmt.Errorf("%w: 无效的 API 专项报告类型", ErrInvalidInput)
		}
		if s.ContentScope != ScopeAPI {
			return fmt.Errorf("%w: API 专项报告的内容范围必须为 API", ErrInvalidInput)
		}
	}
	if !validFormat(s.FileFormat) {
		return fmt.Errorf("%w: 无效的导出格式（html/pdf/docx）", ErrInvalidInput)
	}
	if !validPageOrientation(s.PageOrientation) {
		return fmt.Errorf("%w: 无效的纸张方向（P 竖向 / L 横向）", ErrInvalidInput)
	}
	s.PageOrientation = NormalizePageOrientation(s.PageOrientation)
	if !timeOfDayRe.MatchString(s.TimeOfDay) {
		return fmt.Errorf("%w: 执行时刻须为 HH:MM（UTC，00:00-23:59）", ErrInvalidInput)
	}
	if s.ReportType == TypeWeekly && (s.DayOfWeek < 1 || s.DayOfWeek > 7) {
		return fmt.Errorf("%w: 每周执行的星期须为 1-7（1=周一）", ErrInvalidInput)
	}
	if s.ReportType == TypeMonthly && (s.DayOfMonth < 1 || s.DayOfMonth > 28) {
		return fmt.Errorf("%w: 每月执行的日期须为 1-28", ErrInvalidInput)
	}
	if s.SendEmail {
		if len(s.Emails) == 0 {
			return fmt.Errorf("%w: 开启邮件发送时至少填写一个收件邮箱", ErrInvalidInput)
		}
		if len(s.Emails) > maxScheduleMails {
			return fmt.Errorf("%w: 收件邮箱最多 %d 个", ErrInvalidInput, maxScheduleMails)
		}
		for _, e := range s.Emails {
			e = strings.TrimSpace(e)
			if !emailRe.MatchString(e) {
				return fmt.Errorf("%w: 邮箱格式无效：%s", ErrInvalidInput, e)
			}
		}
	}
	return nil
}

// JobReportType 返回调度实际创建的报告任务类型；空专项类型保持普通周期报告。
func (s *ReportSchedule) JobReportType() string {
	if s.APIReportType != "" {
		return s.APIReportType
	}
	return s.ReportType
}

// NextRunAt 计算 after 之后的下一次执行时刻（UTC，确定性纯函数）。
// kind 取 TypeDaily/TypeWeekly/TypeMonthly；timeOfDay 已校验 HH:MM。
func NextRunAt(kind, timeOfDay string, dayOfWeek, dayOfMonth int, after time.Time) time.Time {
	after = after.UTC()
	var hour, min int
	_, _ = fmt.Sscanf(timeOfDay, "%d:%d", &hour, &min)
	at := func(t time.Time) time.Time {
		return time.Date(t.Year(), t.Month(), t.Day(), hour, min, 0, 0, time.UTC)
	}
	switch kind {
	case TypeWeekly:
		// Go Weekday：Sunday=0..Saturday=6；计划词表 1=周一..7=周日
		want := dayOfWeek % 7 // 1..6→1..6，7（周日）→0
		for i := 0; i < 8; i++ {
			cand := at(after.AddDate(0, 0, i))
			if int(cand.Weekday()) == want && cand.After(after) {
				return cand
			}
		}
	case TypeMonthly:
		for i := 0; i < 2; i++ {
			y, m, _ := after.AddDate(0, i, 0).Date()
			cand := time.Date(y, m, dayOfMonth, hour, min, 0, 0, time.UTC)
			if cand.After(after) {
				return cand
			}
		}
	default: // TypeDaily
		cand := at(after)
		if cand.After(after) {
			return cand
		}
		return cand.AddDate(0, 0, 1)
	}
	return time.Time{}
}

// ScheduleDescription 周期中文描述（界面/报告展示用）。
func (s *ReportSchedule) ScheduleDescription() string {
	weekNames := []string{"", "一", "二", "三", "四", "五", "六", "日"}
	switch s.ReportType {
	case TypeDaily:
		return fmt.Sprintf("每天 %s UTC", s.TimeOfDay)
	case TypeWeekly:
		d := s.DayOfWeek
		if d < 1 || d > 7 {
			d = 1
		}
		return fmt.Sprintf("每周%s %s UTC", weekNames[d], s.TimeOfDay)
	case TypeMonthly:
		return fmt.Sprintf("每月%d号 %s UTC", s.DayOfMonth, s.TimeOfDay)
	}
	return s.ReportType
}
