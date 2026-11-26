package semanticguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func TestValidatePolicyAndBounds(t *testing.T) {
	appID := uuid.New()
	p := DefaultPolicy(appID)
	p.Mode = " protect "
	p.FailPolicy = " fail_closed "
	p.SocketPath = " /run/jiuzhang/semantic.sock "
	p.TimeoutMs = 50
	p.MaxConcurrency = 64
	p.MaxInputRunes = 2048
	p.ObserveThreshold = 0.55
	p.BlockThreshold = 0.85
	p.CircuitFailureThreshold = 10
	p.CircuitOpenSeconds = 60

	NormalizePolicy(p)
	if p.Mode != ModeProtect {
		t.Fatalf("normalize mode = %q, want PROTECT", p.Mode)
	}
	if p.FailPolicy != FailPolicyClosed {
		t.Fatalf("normalize fail_policy = %q, want FAIL_CLOSED", p.FailPolicy)
	}
	if p.SocketPath != "/run/jiuzhang/semantic.sock" {
		t.Fatalf("normalize socket_path = %q", p.SocketPath)
	}
	if errs := ValidatePolicy(p); len(errs) > 0 {
		t.Fatalf("valid policy rejected: %+v", errs)
	}

	// Boundary equality: observe_threshold == block_threshold must pass
	eq := *p
	eq.ObserveThreshold = 0.75
	eq.BlockThreshold = 0.75
	if errs := ValidatePolicy(&eq); len(errs) > 0 {
		t.Fatalf("observe_threshold == block_threshold should be valid: %+v", errs)
	}

	fieldSet := func(errs []FieldError) map[string]bool {
		m := map[string]bool{}
		for _, e := range errs {
			m[e.Field] = true
		}
		return m
	}

	cases := []struct {
		name   string
		mutate func(*Policy)
		field  string
	}{
		{"invalid mode", func(x *Policy) { x.Mode = "BLOCK" }, "mode"},
		{"empty socket", func(x *Policy) { x.SocketPath = "" }, "socket_path"},
		{"socket http ssrf", func(x *Policy) { x.SocketPath = "http://127.0.0.1:8080/healthz" }, "socket_path"},
		{"socket tcp ssrf", func(x *Policy) { x.SocketPath = "tcp://127.0.0.1:9000" }, "socket_path"},
		{"socket outside dir", func(x *Policy) { x.SocketPath = "/tmp/semantic.sock" }, "socket_path"},
		{"socket traversal", func(x *Policy) { x.SocketPath = "/var/run/caddy/sidecars/../docker.sock" }, "socket_path"},
		{"socket double dot in name", func(x *Policy) { x.SocketPath = "/run/jiuzhang/a..b.sock" }, "socket_path"},
		{"socket trailing slash", func(x *Policy) { x.SocketPath = "/var/run/caddy/sidecars/" }, "socket_path"},
		{"socket double slash", func(x *Policy) { x.SocketPath = "/run/jiuzhang//semantic.sock" }, "socket_path"},
		{"socket dot segment", func(x *Policy) { x.SocketPath = "/run/jiuzhang/./semantic.sock" }, "socket_path"},
		{"socket control char", func(x *Policy) { x.SocketPath = "/run/jiuzhang/sem\n.sock" }, "socket_path"},
		{"socket space", func(x *Policy) { x.SocketPath = "/run/jiuzhang/sem antic.sock" }, "socket_path"},
		{"socket too long", func(x *Policy) { x.SocketPath = "/run/jiuzhang/" + strings.Repeat("a", MaxSocketPathLen) }, "socket_path"},
		{"timeout below min", func(x *Policy) { x.TimeoutMs = 4 }, "timeout_ms"},
		{"timeout above max", func(x *Policy) { x.TimeoutMs = 201 }, "timeout_ms"},
		{"concurrency below min", func(x *Policy) { x.MaxConcurrency = 0 }, "max_concurrency"},
		{"concurrency above max", func(x *Policy) { x.MaxConcurrency = 257 }, "max_concurrency"},
		{"input runes below min", func(x *Policy) { x.MaxInputRunes = 255 }, "max_input_runes"},
		{"input runes above max", func(x *Policy) { x.MaxInputRunes = 8193 }, "max_input_runes"},
		{"observe below min", func(x *Policy) { x.ObserveThreshold = 0.09 }, "observe_threshold"},
		{"observe above max", func(x *Policy) { x.ObserveThreshold = 1.0 }, "observe_threshold"},
		{"observe NaN", func(x *Policy) { x.ObserveThreshold = math.NaN() }, "observe_threshold"},
		{"block below min", func(x *Policy) { x.BlockThreshold = 0.49 }, "block_threshold"},
		{"block above max", func(x *Policy) { x.BlockThreshold = 1.0 }, "block_threshold"},
		{"block Inf", func(x *Policy) { x.BlockThreshold = math.Inf(1) }, "block_threshold"},
		{"observe > block", func(x *Policy) { x.ObserveThreshold = 0.90; x.BlockThreshold = 0.80 }, "observe_threshold"},
		{"invalid fail_policy", func(x *Policy) { x.FailPolicy = "BLOCK" }, "fail_policy"},
		{"circuit fail below min", func(x *Policy) { x.CircuitFailureThreshold = 0 }, "circuit_failure_threshold"},
		{"circuit fail above max", func(x *Policy) { x.CircuitFailureThreshold = 101 }, "circuit_failure_threshold"},
		{"circuit open below min", func(x *Policy) { x.CircuitOpenSeconds = 4 }, "circuit_open_seconds"},
		{"circuit open above max", func(x *Policy) { x.CircuitOpenSeconds = 301 }, "circuit_open_seconds"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := *p
			tc.mutate(&cp)
			errs := ValidatePolicy(&cp)
			if !fieldSet(errs)[tc.field] {
				t.Fatalf("expected error on %q, got %+v", tc.field, errs)
			}
		})
	}
}

func TestToGuardPolicyFrozenContract(t *testing.T) {
	appID := uuid.MustParse("8b1a2c3d-0000-4000-8000-000000000077")
	p := DefaultPolicy(appID)
	p.Mode = ModeProtect
	p.Version = 3
	p.FailPolicy = FailPolicyClosed

	gp := toGuardPolicy(p)
	raw, err := json.Marshal(gp)
	if err != nil {
		t.Fatalf("marshal guard policy: %v", err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal guard policy: %v", err)
	}
	wantKeys := []string{
		"schema_version", "application_id", "mode", "version",
		"socket_path", "timeout_ms", "max_concurrency", "max_input_runes",
		"block_threshold", "observe_threshold", "fail_policy",
		"inspect_llm_prompts", "inspect_mcp_content", "inspect_web_grayzone",
		"circuit_failure_threshold", "circuit_open_seconds",
	}
	if len(obj) != len(wantKeys) {
		t.Fatalf("frozen contract expects exactly %d keys, got %d: %s", len(wantKeys), len(obj), raw)
	}
	for _, k := range wantKeys {
		if _, ok := obj[k]; !ok {
			t.Errorf("frozen guard JSON missing key %q: %s", k, raw)
		}
	}
	if obj["schema_version"] != float64(1) {
		t.Errorf("schema_version = %v, want 1", obj["schema_version"])
	}
}

func startTestUnixHealthServer(t *testing.T, handler http.Handler) (string, string) {
	t.Helper()
	// Keep temp dir short so macOS Unix socket sun_path (<=104 bytes) never overflows.
	dir, err := os.MkdirTemp("/tmp", "sgtest-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sock := filepath.Join(dir, "semantic.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("net.Listen unix: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	})
	return dir + "/", sock
}

func TestUnixHealthProberRealSocketAndHonestOffline(t *testing.T) {
	// 1. Missing socket under allowed prefix -> honestly returns available=false
	prodProber := NewUnixHealthProber(500 * time.Millisecond)
	missingPath := "/var/run/caddy/sidecars/definitely-missing-semantic-test.sock"
	stMissing := prodProber.Probe(context.Background(), missingPath)
	if stMissing.Available || stMissing.Status != "unavailable" || stMissing.SocketPath != missingPath || stMissing.Error == "" {
		t.Fatalf("missing socket must honestly report unavailable: %+v", stMissing)
	}

	// 2. Real Unix socket sidecar returning healthy JSON
	prefix, sock := startTestUnixHealthServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Errorf("healthz probe must never send auth or cookie headers")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":       "ok",
			"model_id":     "jiuzhang-slm-prompt-int8-v1",
			"model_sha256": "deadbeef0123456789abcdef",
			"backend":      "onnxruntime",
		})
	}))
	prober := &UnixHealthProber{timeout: time.Second, testAllowedPrefix: prefix}
	stOK := prober.Probe(context.Background(), sock)
	if !stOK.Available || stOK.Status != "ok" || stOK.ModelID != "jiuzhang-slm-prompt-int8-v1" ||
		stOK.ModelSHA256 != "deadbeef0123456789abcdef" || stOK.Backend != "onnxruntime" {
		t.Fatalf("healthy socket status mismatch: %+v", stOK)
	}

	// 3. Symlink inside allowed dir must be rejected
	linkPath := filepath.Join(strings.TrimSuffix(prefix, "/"), "escape.sock")
	if err := os.Symlink(sock, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	stLink := prober.Probe(context.Background(), linkPath)
	if stLink.Available || !strings.Contains(stLink.Error, "符号链接") {
		t.Fatalf("symlink socket must be rejected: %+v", stLink)
	}

	// 4. Sidecar returning HTTP 503 -> available=false
	prefix503, sock503 := startTestUnixHealthServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "model sha256 mismatch",
		})
	}))
	prober503 := &UnixHealthProber{timeout: time.Second, testAllowedPrefix: prefix503}
	st503 := prober503.Probe(context.Background(), sock503)
	if st503.Available || st503.Status != "error" || !strings.Contains(st503.Error, "model sha256 mismatch") {
		t.Fatalf("503 sidecar must report unavailable: %+v", st503)
	}

	// 5. Production prober rejects temp dir socket (testAllowedPrefix never set in prod)
	stProdReject := prodProber.Probe(context.Background(), sock)
	if stProdReject.Available || stProdReject.Status != "invalid_socket_path" {
		t.Fatalf("production prober must reject /tmp socket: %+v", stProdReject)
	}
}

type fakeRepo struct {
	policies  map[uuid.UUID]*Policy
	published map[string]int
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		policies:  map[uuid.UUID]*Policy{},
		published: map[string]int{},
	}
}

func (f *fakeRepo) GetPolicyByApp(_ context.Context, appID uuid.UUID) (*Policy, error) {
	p, ok := f.policies[appID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *p
	return &cp, nil
}

func (f *fakeRepo) SavePolicyDraft(_ context.Context, p *Policy, expectedVersion int, reason, updatedBy string) error {
	cur := f.policies[p.ApplicationID]
	if expectedVersion == 0 {
		if cur != nil {
			return ErrConflict
		}
		cp := *p
		cp.ID = uuid.New()
		cp.Version = 1
		cp.UpdatedBy = updatedBy
		cp.CreatedAt = time.Now().UTC()
		cp.UpdatedAt = cp.CreatedAt
		f.policies[p.ApplicationID] = &cp
		p.ID = cp.ID
		p.Version = cp.Version
		p.UpdatedBy = updatedBy
		return nil
	}
	if cur == nil || cur.Version != expectedVersion {
		return ErrConflict
	}
	cp := *p
	cp.ID = cur.ID
	cp.Version = cur.Version + 1
	cp.UpdatedBy = updatedBy
	cp.CreatedAt = cur.CreatedAt
	cp.UpdatedAt = time.Now().UTC()
	f.policies[p.ApplicationID] = &cp
	p.ID = cp.ID
	p.Version = cp.Version
	p.UpdatedBy = updatedBy
	return nil
}

func (f *fakeRepo) PublishedVersion(_ context.Context, appCode string) (int, error) {
	return f.published[appCode], nil
}

type fakeAppGetter struct {
	apps map[uuid.UUID]*applications.Application
}

func (f *fakeAppGetter) GetByID(_ context.Context, id uuid.UUID) (*applications.Application, error) {
	app, ok := f.apps[id]
	if !ok {
		return nil, applications.ErrNotFound
	}
	return app, nil
}

type spyAudit struct {
	records []audits.RecordInput
}

func (s *spyAudit) Record(_ context.Context, in audits.RecordInput) error {
	s.records = append(s.records, in)
	return nil
}

func withPrincipal(req *http.Request) *http.Request {
	p := &authz.Principal{UserID: uuid.New(), Username: "secadmin"}
	return req.WithContext(authz.WithPrincipal(req.Context(), p))
}

func TestHandlerStatusAndPolicyLifecycle(t *testing.T) {
	appID := uuid.New()
	repo := newFakeRepo()
	apps := &fakeAppGetter{apps: map[uuid.UUID]*applications.Application{
		appID: {ID: appID, Code: "llm-app", Name: "LLM App"},
	}}
	auditSpy := &spyAudit{}
	h := NewHandler(repo, apps, nil)
	h.audits = auditSpy

	// 1. GET /api/v1/semantic-guard/status rejects disallowed socket_path with 400
	reqBadSock := httptest.NewRequest(http.MethodGet, "/api/v1/semantic-guard/status?socket_path="+url.QueryEscape("http://127.0.0.1:8080"), nil)
	recBadSock := httptest.NewRecorder()
	h.GetStatus(recBadSock, reqBadSock)
	if recBadSock.Code != http.StatusBadRequest {
		t.Fatalf("disallowed socket_path must return 400, got %d: %s", recBadSock.Code, recBadSock.Body.String())
	}

	// 2. GET /api/v1/semantic-guard/status with live local Unix socket
	prefix, sock := startTestUnixHealthServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":       "ok",
			"model_id":     "heuristic-v1",
			"model_sha256": "",
			"backend":      "heuristic_fallback",
		})
	}))
	h.SetProber(&UnixHealthProber{timeout: time.Second, testAllowedPrefix: prefix})
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/v1/semantic-guard/status?socket_path="+url.QueryEscape(sock), nil)
	recStatus := httptest.NewRecorder()
	h.GetStatus(recStatus, reqStatus)
	if recStatus.Code != http.StatusOK {
		t.Fatalf("status endpoint returned %d: %s", recStatus.Code, recStatus.Body.String())
	}
	var envStatus struct {
		Data SidecarStatus `json:"data"`
	}
	if err := json.Unmarshal(recStatus.Body.Bytes(), &envStatus); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if !envStatus.Data.Available || envStatus.Data.Backend != "heuristic_fallback" || envStatus.Data.ModelID != "heuristic-v1" {
		t.Fatalf("unexpected status data: %+v", envStatus.Data)
	}

	// 3. GET policy before save -> default OFF policy, NOT_CONFIGURED
	reqGet := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/applications/%s/semantic-guard-policy", appID), nil)
	reqGet.SetPathValue("id", appID.String())
	recGet := httptest.NewRecorder()
	h.GetPolicy(recGet, reqGet)
	if recGet.Code != http.StatusOK {
		t.Fatalf("GET default policy = %d: %s", recGet.Code, recGet.Body.String())
	}
	var envGet struct {
		Data struct {
			Policy  Policy        `json:"policy"`
			Summary StatusSummary `json:"summary"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recGet.Body.Bytes(), &envGet); err != nil {
		t.Fatalf("decode get policy: %v", err)
	}
	if envGet.Data.Policy.Mode != ModeOff || envGet.Data.Policy.Version != 0 || envGet.Data.Summary.State != StateNotConfigured {
		t.Fatalf("unexpected default policy/summary: %+v", envGet.Data)
	}

	// 4. PUT policy valid first save (expected_version=0) -> 200 + version=1 + audit recorded
	body1 := `{
		"mode": "PROTECT",
		"expected_version": 0,
		"socket_path": "/var/run/caddy/sidecars/semantic.sock",
		"timeout_ms": 20,
		"max_concurrency": 16,
		"max_input_runes": 4096,
		"observe_threshold": 0.50,
		"block_threshold": 0.85,
		"fail_policy": "FAIL_CLOSED",
		"inspect_llm_prompts": true,
		"inspect_mcp_content": true,
		"inspect_web_grayzone": false,
		"circuit_failure_threshold": 5,
		"circuit_open_seconds": 30,
		"reason": "启用本地语义防火墙保护 LLM 网关"
	}`
	reqPut := withPrincipal(httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/applications/%s/semantic-guard-policy", appID), bytes.NewBufferString(body1)))
	reqPut.SetPathValue("id", appID.String())
	recPut := httptest.NewRecorder()
	h.PutPolicy(recPut, reqPut)
	if recPut.Code != http.StatusOK {
		t.Fatalf("PUT policy = %d: %s", recPut.Code, recPut.Body.String())
	}
	var envPut struct {
		Data struct {
			Policy Policy `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recPut.Body.Bytes(), &envPut); err != nil {
		t.Fatalf("decode put response: %v", err)
	}
	if envPut.Data.Policy.Version != 1 || envPut.Data.Policy.Mode != ModeProtect || envPut.Data.Policy.FailPolicy != FailPolicyClosed || envPut.Data.Policy.InspectWebGrayzone {
		t.Fatalf("unexpected saved policy: %+v", envPut.Data.Policy)
	}
	if len(auditSpy.records) != 1 || auditSpy.records[0].ObjectType != "semantic_guard_policy" || auditSpy.records[0].RiskLevel != audits.RiskHigh {
		t.Fatalf("expected high-risk audit record, got %+v", auditSpy.records)
	}

	// 5. PUT with stale expected_version=0 -> 409 Conflict
	reqConflict := withPrincipal(httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/applications/%s/semantic-guard-policy", appID), bytes.NewBufferString(body1)))
	reqConflict.SetPathValue("id", appID.String())
	recConflict := httptest.NewRecorder()
	h.PutPolicy(recConflict, reqConflict)
	if recConflict.Code != http.StatusConflict {
		t.Fatalf("stale expected_version must return 409, got %d: %s", recConflict.Code, recConflict.Body.String())
	}

	// 6. PUT with observe_threshold > block_threshold -> 400
	badBody := `{"mode":"OBSERVE","expected_version":1,"observe_threshold":0.9,"block_threshold":0.8,"reason":"test"}`
	reqBad := withPrincipal(httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/applications/%s/semantic-guard-policy", appID), bytes.NewBufferString(badBody)))
	reqBad.SetPathValue("id", appID.String())
	recBad := httptest.NewRecorder()
	h.PutPolicy(recBad, reqBad)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("cross-field invalid thresholds must return 400, got %d: %s", recBad.Code, recBad.Body.String())
	}

	// 7. GET after save: DRAFT_PENDING; once published matches version -> PUBLISHED
	recGet2 := httptest.NewRecorder()
	h.GetPolicy(recGet2, reqGet)
	_ = json.Unmarshal(recGet2.Body.Bytes(), &envGet)
	if envGet.Data.Summary.State != StateDraftPending || envGet.Data.Summary.DraftVersion != 1 || envGet.Data.Summary.PublishedVersion != 0 {
		t.Fatalf("expected DRAFT_PENDING, got %+v", envGet.Data.Summary)
	}

	repo.published["llm-app"] = 1
	recGet3 := httptest.NewRecorder()
	h.GetPolicy(recGet3, reqGet)
	_ = json.Unmarshal(recGet3.Body.Bytes(), &envGet)
	if envGet.Data.Summary.State != StatePublished || envGet.Data.Summary.PublishedVersion != 1 {
		t.Fatalf("expected PUBLISHED, got %+v", envGet.Data.Summary)
	}
}
