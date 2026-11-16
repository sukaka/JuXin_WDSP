package reports

import "testing"

func TestAPIReportScheduleValidationAndJobType(t *testing.T) {
	base := &ReportSchedule{
		Name: "API 专项周报", ReportType: TypeWeekly, ContentScope: ScopeAPI,
		FileFormat: "pdf", PageOrientation: "P", TimeOfDay: "02:00", DayOfWeek: 1,
	}
	for _, kind := range []string{TypeAPIAsset, TypeAPIRisk, TypeAPIWeak, TypeAPISens} {
		sch := *base
		sch.APIReportType = kind
		if err := sch.Validate(); err != nil {
			t.Fatalf("kind=%s: %v", kind, err)
		}
		if sch.JobReportType() != kind {
			t.Fatalf("job type=%s want %s", sch.JobReportType(), kind)
		}
		if sch.ReportType != TypeWeekly {
			t.Fatal("schedule period must remain independent from report content type")
		}
	}

	for _, scope := range []string{ScopeWAF, ScopeWAFAPI} {
		sch := *base
		sch.APIReportType = TypeAPIRisk
		sch.ContentScope = scope
		if err := sch.Validate(); err == nil {
			t.Fatalf("scope=%s must reject API-only report", scope)
		}
	}
	invalid := *base
	invalid.APIReportType = "UNKNOWN"
	if err := invalid.Validate(); err == nil {
		t.Fatal("unknown API report type must be rejected")
	}

	ordinary := *base
	if ordinary.JobReportType() != TypeWeekly {
		t.Fatalf("ordinary job type=%s", ordinary.JobReportType())
	}
}

func TestScheduleRequestPreservesAPIReportType(t *testing.T) {
	req := scheduleRequest{ReportType: TypeWeekly, APIReportType: TypeAPIWeak, ContentScope: ScopeAPI}
	sch := req.toSchedule()
	if sch.APIReportType != TypeAPIWeak || !sch.Enabled {
		t.Fatalf("schedule=%+v", sch)
	}
}
