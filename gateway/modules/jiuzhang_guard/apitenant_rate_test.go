package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
)

func TestGuardConfigTenantRatePerMinuteJSON(t *testing.T) {
	var g Guard
	if err := json.Unmarshal([]byte(`{
		"app_id":"app-1",
		"events_log":"/tmp/events.log",
		"api_dynamic_protection":true,
		"tenant_rate_per_minute":2
	}`), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if g.TenantRatePerMinute != 2 {
		t.Fatalf("tenant_rate_per_minute = %d, want 2", g.TenantRatePerMinute)
	}

	var legacy Guard
	if err := json.Unmarshal([]byte(`{"app_id":"app-1","events_log":"/tmp/events.log"}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	if legacy.TenantRatePerMinute != 0 {
		t.Fatalf("legacy tenant rate = %d, want disabled zero value", legacy.TenantRatePerMinute)
	}

	for _, value := range []string{`"not-a-number"`, `"1"`, `1.5`} {
		var invalid Guard
		raw := `{"events_log":"/tmp/events.log","tenant_rate_per_minute":` + value + `}`
		if err := json.Unmarshal([]byte(raw), &invalid); err == nil {
			t.Fatalf("non-integer tenant_rate_per_minute %s must be rejected", value)
		}
	}
}

func TestGuardRejectsNegativeTenantRatePerMinute(t *testing.T) {
	g := &Guard{
		EventsLog:           filepath.Join(t.TempDir(), "events.log"),
		TenantRatePerMinute: -1,
	}
	if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "tenant_rate_per_minute") {
		t.Fatalf("negative tenant rate must fail Validate, got %v", err)
	}
	if err := g.Provision(caddy.Context{Context: context.Background()}); err == nil || !strings.Contains(err.Error(), "tenant_rate_per_minute") {
		t.Fatalf("negative tenant rate must fail Provision, got %v", err)
	}
}

func newTenantRateRequest(id string, jwt *jwtverify.VerificationResult) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/tenant-rate", strings.NewReader(`{"id":1}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("X-Request-Id", id)
	r.RemoteAddr = "203.0.113.91:1001"
	if jwt != nil {
		*r = *r.WithContext(context.WithValue(r.Context(), jwtResultKey{}, *jwt))
	}
	return r
}

func assertNoTenantRateDetail(t *testing.T, rec apievents.Record) {
	t.Helper()
	for _, detail := range rec.Details {
		if detail.RuleID == "ratelimit.tenant_rate" {
			t.Fatalf("unexpected tenant rate detail: %+v", detail)
		}
	}
}

func assertTenantRateDetail(t *testing.T, rec apievents.Record, tenant, salt string) {
	t.Helper()
	for _, detail := range rec.Details {
		if detail.RuleID != "ratelimit.tenant_rate" {
			continue
		}
		if detail.Detector != "api_ratelimit" || detail.Category != "RATE_LIMIT" || detail.Severity != "HIGH" {
			t.Fatalf("bad tenant rate detail attributes: %+v", detail)
		}
		wantEvidence := map[string]string{"window_count": "2", "limit": "1", "window": "1m"}
		if !reflect.DeepEqual(detail.Evidence, wantEvidence) {
			t.Fatalf("tenant evidence must contain only frozen fields: got %+v, want %+v", detail.Evidence, wantEvidence)
		}
		fingerprint := detectors.Fingerprint(salt, "jwt-tenant:"+tenant)
		for _, value := range detail.Evidence {
			if value == tenant || value == fingerprint {
				t.Fatalf("tenant plaintext or fingerprint leaked into evidence: %+v", detail.Evidence)
			}
		}
		encoded, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		if strings.Contains(string(encoded), tenant) {
			t.Fatal("tenant plaintext must not appear in api runtime event")
		}
		return
	}
	t.Fatalf("ratelimit.tenant_rate detail missing: %+v", rec.Details)
}

func TestServeNextTenantRatePerMinute(t *testing.T) {
	const tenant = "guard-tenant-rate-secret"
	for _, mode := range []string{"OBSERVE", "PROTECT"} {
		t.Run(mode, func(t *testing.T) {
			g, logPath := newAPITestGuard(t, mode, nil)
			g.IdentitySalt = "guard-tenant-rate-" + mode
			g.TenantRatePerMinute = 1
			jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedTenantID: tenant}
			nextCalls := 0
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				nextCalls++
				w.WriteHeader(http.StatusOK)
				return nil
			})

			if err := g.serveNext(httptest.NewRecorder(), newTenantRateRequest("first", jwt), next); err != nil {
				t.Fatalf("first serveNext: %v", err)
			}
			err := g.serveNext(httptest.NewRecorder(), newTenantRateRequest("second", jwt), next)
			if mode == "PROTECT" {
				var handlerErr caddyhttp.HandlerError
				if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusTooManyRequests {
					t.Fatalf("second request error = %v, want 429 HandlerError", err)
				}
			} else if err != nil {
				t.Fatalf("OBSERVE second serveNext must pass: %v", err)
			}
			wantNextCalls := 2
			if mode == "PROTECT" {
				wantNextCalls = 1
			}
			if nextCalls != wantNextCalls {
				t.Fatalf("next calls = %d, want %d", nextCalls, wantNextCalls)
			}

			recs := readAPIRecords(t, logPath)
			if len(recs) != 2 {
				t.Fatalf("want 2 api events, got %d: %+v", len(recs), recs)
			}
			assertNoTenantRateDetail(t, recs[0])
			assertTenantRateDetail(t, recs[1], tenant, g.IdentitySalt)
			wantAction := "OBSERVE"
			if mode == "PROTECT" {
				wantAction = "RATE_LIMIT"
				if recs[1].ResponseStatus != http.StatusTooManyRequests {
					t.Fatalf("blocked event response status = %d, want 429", recs[1].ResponseStatus)
				}
			}
			if recs[1].FinalAction != wantAction {
				t.Fatalf("second final_action = %q, want %q", recs[1].FinalAction, wantAction)
			}
		})
	}
}

func TestServeNextTenantRateSkipsUntrustedMissingTenantAndDisabled(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		jwt   *jwtverify.VerificationResult
	}{
		{name: "no verification result", limit: 1},
		{name: "unverified", limit: 1, jwt: &jwtverify.VerificationResult{Status: jwtverify.StatusUnverified, VerifiedTenantID: "guard-untrusted-tenant"}},
		{name: "verified without tenant", limit: 1, jwt: &jwtverify.VerificationResult{Status: jwtverify.StatusVerified}},
		{name: "zero disabled", limit: 0, jwt: &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedTenantID: "guard-disabled-tenant"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, logPath := newAPITestGuard(t, "PROTECT", nil)
			g.IdentitySalt = "guard-tenant-rate-skip-" + tc.name
			g.TenantRatePerMinute = tc.limit
			nextCalls := 0
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				nextCalls++
				return nil
			})
			for hit := 0; hit < 2; hit++ {
				if err := g.serveNext(httptest.NewRecorder(), newTenantRateRequest("request", tc.jwt), next); err != nil {
					t.Fatalf("serveNext %d: %v", hit+1, err)
				}
			}
			if nextCalls != 2 {
				t.Fatalf("next calls = %d, want 2", nextCalls)
			}
			recs := readAPIRecords(t, logPath)
			if len(recs) != 2 {
				t.Fatalf("want 2 api events, got %d: %+v", len(recs), recs)
			}
			for _, rec := range recs {
				assertNoTenantRateDetail(t, rec)
			}
		})
	}
}

func TestServeNextTenantRateIsolatesTenants(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.IdentitySalt = "guard-tenant-rate-isolation"
	g.TenantRatePerMinute = 1
	nextCalls := 0
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalls++
		return nil
	})
	for _, tenant := range []string{"guard-tenant-a", "guard-tenant-b"} {
		jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedTenantID: tenant}
		if err := g.serveNext(httptest.NewRecorder(), newTenantRateRequest("request", jwt), next); err != nil {
			t.Fatalf("serveNext for %s: %v", tenant, err)
		}
	}
	if nextCalls != 2 {
		t.Fatalf("next calls = %d, want 2", nextCalls)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("want 2 api events, got %d: %+v", len(recs), recs)
	}
	for _, rec := range recs {
		assertNoTenantRateDetail(t, rec)
	}
}
