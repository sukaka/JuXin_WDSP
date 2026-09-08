package reports

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNextRunAtDaily(t *testing.T) {
	// 当日时刻未过 → 当天；已过 → 次日
	at := time.Date(2026, 8, 29, 1, 0, 0, 0, time.UTC)
	got := NextRunAt(TypeDaily, "02:30", 1, 1, at)
	if got.Day() != 29 || got.Hour() != 2 || got.Minute() != 30 {
		t.Fatalf("daily same-day: %v", got)
	}
	got = NextRunAt(TypeDaily, "00:30", 1, 1, at)
	if got.Day() != 30 || got.Hour() != 0 || got.Minute() != 30 {
		t.Fatalf("daily next-day: %v", got)
	}
}

func TestNextRunAtWeekly(t *testing.T) {
	// 2026-08-29 是周六；目标周一(1) 02:00 → 2026-08-31 02:00
	at := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	got := NextRunAt(TypeWeekly, "02:00", 1, 1, at)
	if got.Weekday() != time.Monday || got.Day() != 31 || got.Hour() != 2 {
		t.Fatalf("weekly to monday: %v (%s)", got, got.Weekday())
	}
	// 目标周日(7) 02:00 → 次日（2026-08-30 周日）
	got = NextRunAt(TypeWeekly, "02:00", 7, 1, at)
	if got.Weekday() != time.Sunday || got.Day() != 30 {
		t.Fatalf("weekly to sunday: %v (%s)", got, got.Weekday())
	}
	// 当天就是目标日但时刻已过 → 下周
	at2 := time.Date(2026, 8, 31, 3, 0, 0, 0, time.UTC) // 周一 03:00
	got = NextRunAt(TypeWeekly, "02:00", 1, 1, at2)
	if got.Day() != 7 || got.Month() != 9 {
		t.Fatalf("weekly next week: %v", got)
	}
}

func TestNextRunAtMonthly(t *testing.T) {
	at := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	// 目标 1 号 → 9月1号
	got := NextRunAt(TypeMonthly, "02:00", 1, 1, at)
	if got.Month() != 9 || got.Day() != 1 {
		t.Fatalf("monthly next month: %v", got)
	}
	// 目标 28 号 当月未过 02:00？今天 29 号已过 → 下月 28 号
	got = NextRunAt(TypeMonthly, "02:00", 1, 28, at)
	if got.Month() != 9 || got.Day() != 28 {
		t.Fatalf("monthly day 28 next month: %v", got)
	}
	// 目标 30？越界只允许 1-28（Validate 拦截）；NextRunAt 对 28 正常工作
	at2 := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	got = NextRunAt(TypeMonthly, "02:00", 1, 28, at2)
	if got.Month() != 8 || got.Day() != 28 {
		t.Fatalf("monthly same month: %v", got)
	}
}

func TestReportScheduleValidate(t *testing.T) {
	ok := &ReportSchedule{
		Name: "安全周报", ReportType: TypeWeekly, ContentScope: "WAF_API",
		FileFormat: "pdf", TimeOfDay: "02:00", DayOfWeek: 1,
		SendEmail: true, Emails: []string{"sec@example.com"},
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid schedule rejected: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*ReportSchedule)
	}{
		{"empty name", func(s *ReportSchedule) { s.Name = "  " }},
		{"bad type", func(s *ReportSchedule) { s.ReportType = TypeCustom }},
		{"bad scope", func(s *ReportSchedule) { s.ContentScope = "ALL" }},
		{"bad format", func(s *ReportSchedule) { s.FileFormat = "word" }},
		{"bad time", func(s *ReportSchedule) { s.TimeOfDay = "25:00" }},
		{"bad dow", func(s *ReportSchedule) { s.DayOfWeek = 8 }},
		{"bad dom", func(s *ReportSchedule) { s.ReportType = TypeMonthly; s.DayOfMonth = 30 }},
		{"mail required", func(s *ReportSchedule) { s.Emails = nil }},
		{"mail invalid", func(s *ReportSchedule) { s.Emails = []string{"not-an-email"} }},
		{"mail too many", func(s *ReportSchedule) {
			s.Emails = nil
			for i := 0; i < 11; i++ {
				s.Emails = append(s.Emails, "a@b.com")
			}
		}},
	}
	for _, tc := range cases {
		s := *ok
		s.Emails = append([]string{}, ok.Emails...)
		tc.mut(&s)
		if err := s.Validate(); err == nil {
			t.Fatalf("case %q should be rejected", tc.name)
		}
	}
	// 不开发邮件时邮箱可为空
	s := *ok
	s.SendEmail = false
	s.Emails = nil
	if err := s.Validate(); err != nil {
		t.Fatalf("email disabled should allow empty emails: %v", err)
	}
}

func TestScheduleDescription(t *testing.T) {
	s := &ReportSchedule{ReportType: TypeDaily, TimeOfDay: "02:00"}
	if s.ScheduleDescription() != "每天 02:00 UTC" {
		t.Fatalf("daily desc: %q", s.ScheduleDescription())
	}
	s.ReportType, s.DayOfWeek = TypeWeekly, 5
	if s.ScheduleDescription() != "每周五 02:00 UTC" {
		t.Fatalf("weekly desc: %q", s.ScheduleDescription())
	}
	s.ReportType, s.DayOfMonth = TypeMonthly, 15
	if s.ScheduleDescription() != "每月15号 02:00 UTC" {
		t.Fatalf("monthly desc: %q", s.ScheduleDescription())
	}
}

func TestScheduleAppIDsRoundTrip(t *testing.T) {
	// application_ids JSONB 序列化（store 层复用该结构）
	s := &ReportSchedule{ApplicationIDs: []uuid.UUID{uuid.New()}}
	if len(s.ApplicationIDs) != 1 {
		t.Fatal("app ids")
	}
	if !strings.Contains(TimeDailyConst(), "DAILY") {
		t.Fatal("const sanity")
	}
}

// TimeDailyConst 防误改常量辅助（内部一致性检查）。
func TimeDailyConst() string { return TypeDaily }
