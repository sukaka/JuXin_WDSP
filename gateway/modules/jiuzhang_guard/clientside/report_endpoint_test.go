package clientside

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestServeReportRequest_AllFormatsSanitizationLimitsAndRateLimit(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	eng, err := NewEngine(&Policy{
		SchemaVersion: 1,
		Mode:          ModeProtect,
		CSPMode:       CSPModeEnforce,
	}, EngineOptions{
		Now:                func() time.Time { return now },
		ReportRateLimitRPM: 30,
		ReportRateMaxIPs:   4,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// 1. Non-POST -> 405.
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://shop.example.com/_wdsp/csp/v1/report", nil)
		out := eng.ServeReportRequest(rec, req, "203.0.113.1")
		if out.Status != http.StatusMethodNotAllowed || rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET expected 405, got %d", rec.Code)
		}
		if rec.Header().Get("Allow") != http.MethodPost {
			t.Fatalf("Allow header = %q, want POST", rec.Header().Get("Allow"))
		}
	}

	// 2. Standard CSP report with credentials, query string, fragment -> stripped + 204.
	{
		body := `{"csp-report":{"document-uri":"https://alice:pw@shop.example.com/checkout?session=topsecret#step2","violated-directive":"script-src 'self'","effective-directive":"script-src","blocked-uri":"https://user:pass@evil.example/skim.js?card=4111&cvv=999#frag","disposition":"enforce"}}`
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "https://shop.example.com/_wdsp/csp/v1/report", strings.NewReader(body))
		out := eng.ServeReportRequest(rec, req, "203.0.113.2")
		if out.Status != http.StatusNoContent || rec.Code != http.StatusNoContent {
			t.Fatalf("CSP report expected 204, got %d", rec.Code)
		}
		if len(out.Events) != 1 {
			t.Fatalf("expected 1 event, got %d", len(out.Events))
		}
		ev := out.Events[0]
		if ev.ViolationType != ViolationCSPViolation || ev.ActionTaken != ActionCSPEnforced {
			t.Fatalf("unexpected violation/action: %+v", ev)
		}
		if ev.PagePath != "/checkout" {
			t.Fatalf("page_path = %q, want /checkout (no query/creds)", ev.PagePath)
		}
		if ev.BlockedURI != "https://evil.example/skim.js" {
			t.Fatalf("blocked_uri = %q, want sanitized URL", ev.BlockedURI)
		}
		if ev.ViolatedDirective != "script-src" || ev.ScriptOrigin != "https://evil.example" {
			t.Fatalf("unexpected directive/origin: %+v", ev)
		}
	}

	// 3. Reporting API v1 array format -> 204, parses csp-violation, ignores unknown types, caps at 16.
	{
		var items []string
		for i := 0; i < 20; i++ {
			items = append(items, fmt.Sprintf(`{"type":"csp-violation","url":"https://shop.example.com/pay?tok=abc","body":{"documentURL":"https://shop.example.com/pay?tok=abc","effectiveDirective":"connect-src","blockedURL":"https://exfil.example/c/%d?cc=4111","disposition":"report"}}`, i))
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "https://shop.example.com/_wdsp/csp/v1/report", strings.NewReader("["+strings.Join(items, ",")+"]"))
		out := eng.ServeReportRequest(rec, req, "203.0.113.3")
		if rec.Code != http.StatusNoContent {
			t.Fatalf("Reporting API expected 204, got %d", rec.Code)
		}
		if len(out.Events) != MaxReportsPerBatch {
			t.Fatalf("expected batch capped at %d, got %d", MaxReportsPerBatch, len(out.Events))
		}
		if out.Events[0].BlockedURI != "https://exfil.example/c/0" || out.Events[0].ActionTaken != ActionReported || out.Events[0].PagePath != "/pay" {
			t.Fatalf("unexpected Reporting API event: %+v", out.Events[0])
		}
	}

	// 4. Probe alert format -> 204, PROBE_ALERT, sanitized URL & page.
	{
		body := `{"type":"probe-alert","kind":"cross_origin_fetch","target":"https://u:p@steal.example/drop?data=secret#x","page":"https://shop.example.com/login?next=/admin"}`
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "https://shop.example.com/_wdsp/csp/v1/report", strings.NewReader(body))
		out := eng.ServeReportRequest(rec, req, "203.0.113.4")
		if rec.Code != http.StatusNoContent || len(out.Events) != 1 {
			t.Fatalf("probe alert expected 204 + 1 event, got code=%d events=%d", rec.Code, len(out.Events))
		}
		ev := out.Events[0]
		if ev.ViolationType != ViolationProbeAlert || ev.Reason != "cross_origin_fetch" ||
			ev.BlockedURI != "https://steal.example/drop" || ev.PagePath != "/login" || ev.ActionTaken != ActionReported {
			t.Fatalf("unexpected probe alert event: %+v", ev)
		}
	}

	// 5. Oversized >16KiB -> 413.
	{
		huge := `{"type":"probe-alert","kind":"` + strings.Repeat("a", MaxReportBodyBytes+10) + `"}`
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "https://shop.example.com/_wdsp/csp/v1/report", strings.NewReader(huge))
		out := eng.ServeReportRequest(rec, req, "203.0.113.5")
		if out.Status != http.StatusRequestEntityTooLarge || rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized report expected 413, got %d", rec.Code)
		}
		if len(out.Events) != 0 {
			t.Fatal("oversized report must not emit events")
		}
	}

	// 6. Per-IP rate limit: 30/min allowed, 31st -> 429, resets after 60s.
	{
		floodIP := "198.51.100.77"
		payload := `{"type":"probe-alert","kind":"dynamic_script","target":"https://evil.example/a.js","page":"/pay"}`
		for i := 1; i <= 30; i++ {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "https://shop.example.com/_wdsp/csp/v1/report", strings.NewReader(payload))
			eng.ServeReportRequest(rec, req, floodIP)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("req %d expected 204, got %d", i, rec.Code)
			}
		}
		rec31 := httptest.NewRecorder()
		req31 := httptest.NewRequest(http.MethodPost, "https://shop.example.com/_wdsp/csp/v1/report", strings.NewReader(payload))
		out31 := eng.ServeReportRequest(rec31, req31, floodIP)
		if out31.Status != http.StatusTooManyRequests || rec31.Code != http.StatusTooManyRequests {
			t.Fatalf("req 31 expected 429, got %d", rec31.Code)
		}
		if rec31.Header().Get("Retry-After") == "" {
			t.Fatal("429 must include Retry-After")
		}

		// Bounded IP map never exceeds maxIPs=4.
		if eng.reportLimiter.Len() > 4 {
			t.Fatalf("rate limiter IP map exceeded bound 4: got %d", eng.reportLimiter.Len())
		}

		// Advance clock past 1 minute -> allowed again.
		now = now.Add(61 * time.Second)
		recAfter := httptest.NewRecorder()
		reqAfter := httptest.NewRequest(http.MethodPost, "https://shop.example.com/_wdsp/csp/v1/report", strings.NewReader(payload))
		eng.ServeReportRequest(recAfter, reqAfter, floodIP)
		if recAfter.Code != http.StatusNoContent {
			t.Fatalf("expected 204 after rate limit window reset, got %d", recAfter.Code)
		}
	}

	// 7. Concurrent rate limiter safety under -race.
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				eng.reportLimiter.Allow(fmt.Sprintf("198.51.100.%d", id), now)
			}
		}(g)
	}
	wg.Wait()
}

func TestSanitizeReportURL_EdgeCases(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://user:secret@evil.com:443/a.js?token=123#frag", "https://evil.com/a.js"},
		{"http://evil.com:80/x.js?k=v", "http://evil.com/x.js"},
		{"/static/app.js?v=2#hash", "/static/app.js"},
		{"data:text/javascript;base64,YWxlcnQoMSk=", "data:"},
		{"javascript:alert(document.cookie)", "javascript:"},
		{"blob:https://evil.com/uuid?secret=1", "blob:https://evil.com/uuid"},
		{"inline", "inline"},
		{"eval", "eval"},
	}
	for _, tc := range cases {
		if got := SanitizeReportURL(tc.in); got != tc.want {
			t.Errorf("SanitizeReportURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
