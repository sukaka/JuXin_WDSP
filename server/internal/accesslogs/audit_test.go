package accesslogs

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBuildListWhereAuditFilters(t *testing.T) {
	applicationID := uuid.New()
	filter := ListFilter{
		ApplicationID:       &applicationID,
		TraceID:             strings.Repeat("a", 32),
		IdentityFingerprint: "identity-hmac-1",
		RuleID:              `sensitive.field",{"x":"y`,
	}
	where, args := buildListWhere(filter)
	for _, wanted := range []string{
		"application_id = $1",
		"trace_id = $2",
		"audit_event.identity_fingerprint = $3",
		"audit_event.details_json @> jsonb_build_array(jsonb_build_object('rule_id', $4::text))",
		"audit_event.request_id = access_logs.request_id",
	} {
		if !strings.Contains(where, wanted) {
			t.Errorf("where missing %q: %s", wanted, where)
		}
	}
	if len(args) != 4 || args[0] != applicationID || args[1] != filter.TraceID || args[2] != filter.IdentityFingerprint {
		t.Fatalf("unexpected filter args: %#v", args)
	}
	if got := args[3]; got != filter.RuleID {
		t.Fatalf("rule filter must remain a SQL argument, got %#v", got)
	}
	if strings.Contains(where, filter.RuleID) {
		t.Fatalf("rule input was concatenated into SQL: %s", where)
	}
}

func TestBuildTrendQuery(t *testing.T) {
	filter := ListFilter{Domain: "example.internal", WAFAction: "BLOCK"}
	query, args := buildTrendQuery(filter, 300)
	if len(args) != 3 || args[0] != "%example.internal%" || args[1] != "BLOCK" || args[2] != 300 {
		t.Fatalf("unexpected trend args: %#v", args)
	}
	for _, wanted := range []string{
		"count(*) AS total",
		"FILTER (WHERE waf_action = 'BLOCK')",
		"FILTER (WHERE response_status >= 500)",
		"GROUP BY bucket",
		"ORDER BY bucket",
	} {
		if !strings.Contains(query, wanted) {
			t.Errorf("trend query missing %q: %s", wanted, query)
		}
	}
}

func TestTrendBucketSeconds(t *testing.T) {
	start := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		duration  time.Duration
		requested string
		want      int
		wantError bool
	}{
		{name: "one hour automatic", duration: time.Hour, want: 60},
		{name: "six hours automatic", duration: 6 * time.Hour, want: 300},
		{name: "one day automatic", duration: 24 * time.Hour, want: 900},
		{name: "one week automatic", duration: 7 * 24 * time.Hour, want: 3600},
		{name: "month automatic", duration: 31 * 24 * time.Hour, want: 86400},
		{name: "explicit", duration: time.Hour, requested: "900", want: 900},
		{name: "invalid", duration: time.Hour, requested: "1", wantError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := trendBucketSeconds(start, start.Add(tc.duration), tc.requested)
			if tc.wantError {
				if err == nil {
					t.Fatal("expected invalid bucket error")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("bucket=%d err=%v want=%d", got, err, tc.want)
			}
		})
	}
}

func TestFilterFromQueryAuditFields(t *testing.T) {
	applicationID := uuid.New()
	traceID := strings.Repeat("a", 32)
	req := httptest.NewRequest("GET", "/api/v1/access-logs?application_id="+applicationID.String()+
		"&trace_id="+traceID+"&identity_fingerprint=identity-hmac-1&rule_id=sensitive.field"+
		"&start_time=2026-11-17T00%3A00%3A00Z&end_time=2026-11-17T01%3A00%3A00Z&status=200", nil)
	filter, err := filterFromQuery(req)
	if err != nil {
		t.Fatal(err)
	}
	if filter.ApplicationID == nil || *filter.ApplicationID != applicationID || filter.TraceID != traceID ||
		filter.IdentityFingerprint != "identity-hmac-1" || filter.RuleID != "sensitive.field" {
		t.Fatalf("audit filters were not parsed: %+v", filter)
	}
}

func TestFilterFromQueryRejectsInvalidAuditFields(t *testing.T) {
	cases := []string{
		"application_id=bad",
		"trace_id=bad",
		"trace_id=00000000000000000000000000000000",
		"status=99",
		"start_time=bad",
		"start_time=2026-11-17T01%3A00%3A00Z&end_time=2026-11-17T00%3A00%3A00Z",
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/access-logs?"+query, nil)
			if _, err := filterFromQuery(req); err == nil {
				t.Fatal("expected query validation error")
			}
		})
	}
}
