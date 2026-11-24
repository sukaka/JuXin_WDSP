package applications

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/validation"
)

func TestDefaultMode(t *testing.T) {
	for _, m := range []string{ModeOff, ModeObserve, ModeProtect, ModeBypass} {
		if got := defaultMode(m); got != m {
			t.Errorf("defaultMode(%s) = %s, want %s", m, got, m)
		}
	}
	for _, m := range []string{"", "INVALID", "bypass"} {
		if got := defaultMode(m); got != ModeObserve {
			t.Errorf("defaultMode(%q) = %s, want %s", m, got, ModeObserve)
		}
	}
}

// 创建接口对非法 api_admission_mode 明确 400（冻结契约；校验先于配额与 store，
// nil store 即可驱动——与 quota_test 同一纪律）
func TestCreateRejectsInvalidAdmissionModeHTTP(t *testing.T) {
	h := NewHandler(nil, deadAudits(t), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/applications",
		strings.NewReader(`{"code":"shop-x","name":"测试应用","api_admission_mode":"STRICT"}`))
	req.Header.Set("Content-Type", "application/json")
	p := &authz.Principal{UserID: uuid.New(), Username: "tester"}
	req = req.WithContext(authz.WithPrincipal(req.Context(), p))
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 api_admission_mode 应 400，got %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应非 JSON: %v", err)
	}
	if body.Code != "INVALID_ARGUMENT" {
		t.Fatalf("业务码应为 INVALID_ARGUMENT，got %s", body.Code)
	}
}

func TestGenerateAppCodeFormat(t *testing.T) {
	seen := make(map[string]struct{}, 64)
	for i := 0; i < 64; i++ {
		code, err := generateAppCode()
		if err != nil {
			t.Fatalf("generateAppCode: %v", err)
		}
		if !strings.HasPrefix(code, "app-") || len(code) != 4+autoAppCodeSuffixLen {
			t.Fatalf("unexpected generated code %q", code)
		}
		if err := validation.ValidateAppCode(code); err != nil {
			t.Fatalf("generated code %q failed ValidateAppCode: %v", code, err)
		}
		seen[code] = struct{}{}
	}
	if len(seen) < 60 {
		t.Fatalf("expected high entropy generated codes, only got %d unique out of 64", len(seen))
	}
}

func makeAuthReq(t *testing.T, body string) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/applications", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	p := &authz.Principal{UserID: uuid.New(), Username: "tester"}
	req = req.WithContext(authz.WithPrincipal(req.Context(), p))
	return req, httptest.NewRecorder()
}

func TestCreateAutoGeneratesCodeWhenOmittedOrEmpty(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "omitted", body: `{"name":"官网"}`},
		{name: "empty", body: `{"code":"","name":"官网"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHandler(nil, deadAudits(t), nil)
			var persisted *Application
			h.createApp = func(_ context.Context, a *Application) error {
				a.ID = uuid.New()
				persisted = a
				return nil
			}
			req, rec := makeAuthReq(t, tc.body)
			h.Create(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
			}
			if persisted == nil || !strings.HasPrefix(persisted.Code, "app-") {
				t.Fatalf("expected auto-generated app-* code, got %+v", persisted)
			}
			if err := validation.ValidateAppCode(persisted.Code); err != nil {
				t.Fatalf("auto-generated code invalid: %v", err)
			}
			var resp struct {
				Code string `json:"code"`
				Data struct {
					Code          string `json:"code"`
					Name          string `json:"name"`
					PrimaryDomain string `json:"primary_domain"`
				} `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp.Code != "SUCCESS" || resp.Data.Code != persisted.Code || resp.Data.Name != "官网" || resp.Data.PrimaryDomain != "" {
				t.Fatalf("unexpected response: %+v", resp)
			}
		})
	}
}

func TestCreateAutoCodeRetriesOnCollision(t *testing.T) {
	h := NewHandler(nil, deadAudits(t), nil)
	seq := []string{"app-dup00001", "app-dup00002", "app-ok000003"}
	idx := 0
	h.generateCode = func() (string, error) {
		c := seq[idx]
		idx++
		return c, nil
	}
	var attempts []string
	h.createApp = func(_ context.Context, a *Application) error {
		attempts = append(attempts, a.Code)
		if a.Code != "app-ok000003" {
			return ErrCodeExists
		}
		a.ID = uuid.New()
		return nil
	}
	req, rec := makeAuthReq(t, `{"name":"官网"}`)
	h.Create(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected retry to succeed with 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(attempts) != 3 || attempts[2] != "app-ok000003" {
		t.Fatalf("unexpected attempts: %v", attempts)
	}
}

func TestCreateAutoCodeExhaustedRetriesReturns500(t *testing.T) {
	h := NewHandler(nil, deadAudits(t), nil)
	calls := 0
	h.generateCode = func() (string, error) { return "app-same0001", nil }
	h.createApp = func(_ context.Context, _ *Application) error {
		calls++
		return ErrCodeExists
	}
	req, rec := makeAuthReq(t, `{"name":"官网"}`)
	h.Create(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when auto-code retries exhausted, got %d body=%s", rec.Code, rec.Body.String())
	}
	if calls != maxAutoAppCodeRetries {
		t.Fatalf("expected %d attempts, got %d", maxAutoAppCodeRetries, calls)
	}
}

func TestCreateExplicitCodeConflictDoesNotRetry(t *testing.T) {
	h := NewHandler(nil, deadAudits(t), nil)
	calls := 0
	h.createApp = func(_ context.Context, a *Application) error {
		calls++
		if a.Code != "portal-web" {
			t.Fatalf("expected explicit code portal-web, got %q", a.Code)
		}
		return ErrCodeExists
	}
	req, rec := makeAuthReq(t, `{"code":"portal-web","name":"门户"}`)
	h.Create(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 on explicit code conflict, got %d body=%s", rec.Code, rec.Body.String())
	}
	if calls != 1 {
		t.Fatalf("explicit code should not retry, got %d calls", calls)
	}
}

func TestCreateRejectsInvalidExplicitCodeOrEmptyName(t *testing.T) {
	h := NewHandler(nil, deadAudits(t), nil)
	h.createApp = func(_ context.Context, _ *Application) error {
		return errors.New("should not reach createApp")
	}
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "invalid_code", body: `{"code":"BAD--CODE","name":"测试"}`},
		{name: "whitespace_code", body: `{"code":"   ","name":"测试"}`},
		{name: "empty_name_with_auto_code", body: `{"name":""}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, rec := makeAuthReq(t, tc.body)
			h.Create(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: expected 400, got %d body=%s", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPrimaryActiveDomain(t *testing.T) {
	if got := primaryActiveDomain(nil); got != "" {
		t.Fatalf("nil domains -> %q, want empty", got)
	}
	domains := []Domain{
		{Hostname: "old.example.com", NormalizedHostname: "old.example.com", Status: "DISABLED", IsPrimary: true},
		{Hostname: "WWW.Example.COM", NormalizedHostname: "www.example.com", Status: "ACTIVE", IsPrimary: true},
		{Hostname: "api.example.com", NormalizedHostname: "api.example.com", Status: "ACTIVE", IsPrimary: false},
	}
	if got := primaryActiveDomain(domains); got != "www.example.com" {
		t.Fatalf("primaryActiveDomain = %q, want www.example.com", got)
	}
	fallback := []Domain{{Hostname: "fallback.example.com", Status: "ACTIVE"}}
	if got := primaryActiveDomain(fallback); got != "fallback.example.com" {
		t.Fatalf("fallback hostname = %q, want fallback.example.com", got)
	}
}

func TestPrimaryDomainsByAppIDsEmptySlice(t *testing.T) {
	s := &Store{}
	got, err := s.PrimaryDomainsByAppIDs(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("expected empty non-nil map, got %#v", got)
	}
}

func TestUpstreamHealthJSONAndNotifyCallback(t *testing.T) {
	status := 200
	ms := 15
	u := Upstream{
		ID:                   uuid.New(),
		Name:                 "origin-1",
		HealthStatus:         UpstreamHealthHealthy,
		LastResponseStatus:   &status,
		LastResponseTimeMs:   &ms,
		LastHealthErrorCode:  "",
		LastHealthError:      "",
		ConsecutiveSuccesses: 4,
		ConsecutiveFailures:  0,
	}
	raw, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("marshal upstream: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal upstream: %v", err)
	}
	if m["health_status"] != UpstreamHealthHealthy || m["last_response_status"] != float64(200) || m["last_response_time_ms"] != float64(15) || m["consecutive_successes"] != float64(4) {
		t.Fatalf("unexpected upstream health JSON: %s", string(raw))
	}

	called := 0
	h := NewHandler(nil, deadAudits(t), nil)
	h.notifyUpstreamChanged() // nil 安全不 panic
	h.SetOnUpstreamChanged(func() { called++ })
	h.notifyUpstreamChanged()
	if called != 1 {
		t.Fatalf("onUpstreamChanged called %d times, want 1", called)
	}
}
