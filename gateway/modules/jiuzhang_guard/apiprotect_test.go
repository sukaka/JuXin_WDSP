package jiuzhang_guard

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"go.uber.org/zap"
)

type nextFunc func(http.ResponseWriter, *http.Request) error

func (f nextFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error { return f(w, r) }

// newAPITestGuard 构造仅启用 API 动态防护所需字段的 Guard（不经过 Provision）。
func newAPITestGuard(t *testing.T, mode string, schemas map[string]map[string]string) (*Guard, string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "api-runtime-events.log")
	al, err := apievents.NewLogger(logPath, "test-node")
	if err != nil {
		t.Fatalf("new api events logger: %v", err)
	}
	t.Cleanup(func() { _ = al.Close() })
	g := &Guard{
		AppID:                "app-1",
		AppCode:              "shop",
		APIDynamicProtection: true,
		APIProtectionMode:    mode,
		APIFormalSchemas:     schemas,
		apiEvents:            al,
		logger:               zap.NewNop(),
	}
	return g, logPath
}

func readAPIRecords(t *testing.T, path string) []apievents.Record {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read api events log: %v", err)
	}
	var out []apievents.Record
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var rec apievents.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad json line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// 关闭时：零行为变化，不产事件、不进管线。
func TestServeNext_DisabledPassthrough(t *testing.T) {
	g := &Guard{APIDynamicProtection: false, logger: zap.NewNop()}
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called {
		t.Fatal("next handler not called when API protection disabled")
	}
	if RequestContextFrom(req) != nil {
		t.Fatal("request context should not carry RequestContext when disabled")
	}
}

// OBSERVE 模式 + 模型偏离：放行、上下文注入、事件落盘且含 type_mismatch 明细。
func TestServeNext_ObserveModeRecordsDeviation(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"id": "number"}}
	g, logPath := newAPITestGuard(t, "OBSERVE", schemas)

	var gotBody string
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-observe-1")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if gotBody != `{"id":"abc"}` {
		t.Fatalf("downstream body corrupted: %q", gotBody)
	}
	rc := RequestContextFrom(req)
	if rc == nil {
		t.Fatal("RequestContext not injected into request context")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	rec := recs[0]
	if rec.RequestID != "req-observe-1" || rec.EndpointKey != "POST /v1/orders" {
		t.Fatalf("bad record identity: %+v", rec)
	}
	if !rec.IsAPI || rec.Method != "POST" || rec.PathTemplate != "/v1/orders" {
		t.Fatalf("bad discovery fields: %+v", rec)
	}
	found := false
	for _, d := range rec.Details {
		if d.RuleID == "schema.type_mismatch" && d.Category == "BLOCK" {
			found = true
		}
	}
	if !found {
		t.Fatalf("type_mismatch detail missing: %+v", rec.Details)
	}
	if rec.FinalAction == "BLOCK" {
		t.Fatal("OBSERVE mode must not finalize BLOCK")
	}
}

// PROTECT 模式 + 类型偏离：403 拦截且事件落盘。
func TestServeNext_ProtectModeBlocks(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"id": "number"}}
	g, logPath := newAPITestGuard(t, "PROTECT", schemas)

	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-protect-1")
	err := g.serveNext(httptest.NewRecorder(), req, next)
	if err == nil {
		t.Fatal("expect block error")
	}
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 HandlerError, got %v", err)
	}
	if called {
		t.Fatal("next handler must not run when blocked")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 || recs[0].FinalAction != "BLOCK" {
		t.Fatalf("want 1 BLOCK event, got %+v", recs)
	}
}

// 无冻结模型 + 正常请求：放行且不阻断（缺失字段不抬升至 BLOCK）。
func TestServeNext_NoSchemaPassthrough(t *testing.T) {
	g, _ := newAPITestGuard(t, "PROTECT", nil)
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called {
		t.Fatal("next handler not called")
	}
}

// 非 API 的 GET 请求：放行且不产事件（由访问日志/WAF 事件覆盖）。
func TestServeNext_NonAPIGETNoEvent(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if recs := readAPIRecords(t, logPath); len(recs) != 0 {
		t.Fatalf("want no events for plain GET, got %+v", recs)
	}
}

// 生命周期检测：端点不在发布下发的已知基线中 → NEW_ENDPOINT（OBSERVE 放行，事件含明细）。
func TestServeNext_LifecycleNewEndpoint(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.APIKnownEndpoints = map[string]string{"GET /v1/known": "CONFIRMED"}
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/new-thing", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-lifecycle-1")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called {
		t.Fatal("NEW_ENDPOINT is OBSERVE class: next handler must be called")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	found := false
	for _, d := range recs[0].Details {
		if d.RuleID == "lifecycle.new_endpoint" && d.Category == "OBSERVE" && d.Severity == "LOW" {
			found = true
		}
	}
	if !found {
		t.Fatalf("lifecycle.new_endpoint detail missing: %+v", recs[0].Details)
	}
}

// preserveRequestBody：Content-Length 超限不读入内存、跳过管线；限内完整可读可还原，
// 体样本与原文一致（webshell C2 请求相位观测样本由此供给）。
func TestPreserveRequestBodyCap(t *testing.T) {
	// 超限 Content-Length：不读 body，返回 nil（跳过管线）
	over := httptest.NewRequest(http.MethodPost, "/v1/x", strings.NewReader("payload"))
	over.ContentLength = maxBodyPreserveBytes + 1
	if restore, _ := preserveRequestBody(over); restore != nil {
		t.Fatal("oversized Content-Length must skip preserve")
	}
	// 限内：可读且 restore 可还原，体样本与原文一致
	body := `{"id":1}`
	okReq := httptest.NewRequest(http.MethodPost, "/v1/x", strings.NewReader(body))
	restore, sample := preserveRequestBody(okReq)
	if restore == nil {
		t.Fatal("in-limit body must be preserved")
	}
	if string(sample) != body {
		t.Fatalf("body sample = %q, want %q", sample, body)
	}
	got, err := io.ReadAll(okReq.Body)
	if err != nil || string(got) != body {
		t.Fatalf("first read = %q err=%v", got, err)
	}
	restore()
	got, err = io.ReadAll(okReq.Body)
	if err != nil || string(got) != body {
		t.Fatalf("restored read = %q err=%v", got, err)
	}
}

// 事件携带响应状态码与来源/身份指纹：阻断按决策映射 403（阻断时输出）；
// API 放行流量在响应完成后输出，携带真实状态码（空响应归一 200）与 client_ip/raw_path。
// 身份指纹语义（新）：仅凭据派生（auth:/key:/sess: 前缀），匿名请求置空；IP 只属于来源指纹。
func TestServeNext_EventStatusAndFingerprints(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"id": "number"}}
	g, logPath := newAPITestGuard(t, "PROTECT", schemas)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	// 阻断请求：类型偏离 → BLOCK/403
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer token-abc")
	req.RemoteAddr = "203.0.113.7:4321"
	if err := g.serveNext(httptest.NewRecorder(), req, next); err == nil {
		t.Fatal("expect block")
	}
	// 放行请求：符合模型 → ALLOW，状态码未采集置 0（无凭据：匿名）
	req2 := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":1}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.RemoteAddr = "203.0.113.8:4321"
	if err := g.serveNext(httptest.NewRecorder(), req2, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}

	recs := readAPIRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("want 2 api events, got %d: %+v", len(recs), recs)
	}
	blocked, allow := recs[0], recs[1]
	if blocked.FinalAction != "BLOCK" || blocked.ResponseStatus != http.StatusForbidden {
		t.Fatalf("blocked event status: %+v", blocked)
	}
	// 测试 Guard 未配置 identity_salt → 指纹走固定域分隔前缀（salt=""）
	if blocked.SourceFingerprint != detectors.Fingerprint("", "203.0.113.7") {
		t.Fatalf("source fingerprint mismatch: %q", blocked.SourceFingerprint)
	}
	if !strings.HasPrefix(blocked.IdentityFingerprint, "auth:") {
		t.Fatalf("identity fingerprint should be credential-derived (auth:), got %q", blocked.IdentityFingerprint)
	}
	if strings.Contains(blocked.IdentityFingerprint, "token-abc") {
		t.Fatal("identity fingerprint must not contain raw credential")
	}
	if blocked.AuthType != "bearer_or_basic" {
		t.Fatalf("auth_type = %q, want bearer_or_basic", blocked.AuthType)
	}
	if allow.FinalAction != "ALLOW" && allow.FinalAction != "OBSERVE" {
		t.Fatalf("request should pass, got final_action=%q", allow.FinalAction)
	}
	// 事件时机修正：API 流量事件在响应完成后输出，携带真实状态码（下游空响应归一为 200）
	if allow.ResponseStatus != http.StatusOK {
		t.Fatalf("pass-through event should carry real response_status=200: %+v", allow)
	}
	// 新增事件字段：真实客户端 IP 与归一化前路径
	if allow.ClientIP != "203.0.113.8" {
		t.Fatalf("client_ip = %q", allow.ClientIP)
	}
	if allow.RawPath != "/v1/orders" {
		t.Fatalf("raw_path = %q", allow.RawPath)
	}
	if allow.SourceFingerprint != detectors.Fingerprint("", "203.0.113.8") {
		t.Fatalf("source fingerprint mismatch: %q", allow.SourceFingerprint)
	}
	// 匿名事件：身份指纹为空（IP 不得冒充身份），auth_type 为空
	if allow.IdentityFingerprint != "" {
		t.Fatalf("anonymous event must not carry identity fingerprint, got %q", allow.IdentityFingerprint)
	}
	if allow.AuthType != "" {
		t.Fatalf("anonymous event auth_type must be empty, got %q", allow.AuthType)
	}
}

// cookie 会话身份：sess: 指纹进事件且 auth_type=cookie_session；Cookie 明文不出事件。
func TestServeNext_CookieSessionIdentity(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"id": "number"}}
	g, logPath := newAPITestGuard(t, "PROTECT", schemas)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "sid=secret-session-cookie")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err == nil {
		t.Fatal("expect block")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	rec := recs[0]
	if !strings.HasPrefix(rec.IdentityFingerprint, "sess:") {
		t.Fatalf("want sess: identity fingerprint, got %q", rec.IdentityFingerprint)
	}
	if strings.Contains(rec.IdentityFingerprint, "secret-session-cookie") {
		t.Fatal("cookie plaintext must not appear in identity fingerprint")
	}
	if rec.AuthType != "cookie_session" {
		t.Fatalf("auth_type = %q, want cookie_session", rec.AuthType)
	}
}

// 同凭据跨 IP 跳变接线：credential_ip_spread_limit 透传管线，同凭据第二来源 IP 命中 OBSERVE 信号。
func TestServeNext_CredentialIPSpread(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	g.CredentialIPSpreadLimit = 2

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	mk := func(remoteAddr string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":1}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer env-spread-token")
		req.RemoteAddr = remoteAddr
		return req
	}
	// 第一个来源 IP：distinct 1，不报
	if err := g.serveNext(httptest.NewRecorder(), mk("203.0.113.50:1001"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	// 第二个来源 IP：distinct 2 达阈值 → auth.credential_ip_spread（OBSERVE 放行）
	if err := g.serveNext(httptest.NewRecorder(), mk("203.0.113.51:1002"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("want 2 api events, got %d: %+v", len(recs), recs)
	}
	for _, d := range recs[0].Details {
		if d.RuleID == "auth.credential_ip_spread" {
			t.Fatalf("first request below threshold must not match: %+v", recs[0].Details)
		}
	}
	found := false
	for _, d := range recs[1].Details {
		if d.RuleID == "auth.credential_ip_spread" {
			found = true
			if d.Category != "OBSERVE" || d.Severity != "MEDIUM" {
				t.Fatalf("bad spread detail attrs: %+v", d)
			}
			for _, v := range d.Evidence {
				if strings.Contains(v, "203.0.113.") {
					t.Fatalf("ip leaked into evidence: %+v", d.Evidence)
				}
			}
		}
	}
	if !found {
		t.Fatalf("credential_ip_spread detail missing: %+v", recs[1].Details)
	}
	// 事件身份指纹不含凭据明文
	if strings.Contains(recs[1].IdentityFingerprint, "env-spread-token") {
		t.Fatal("identity fingerprint must not contain raw credential")
	}
}

// 同凭据并发度接线：credential_concurrency_limit 透传管线；serveNext 入口并发记账生效
// （手动预占一个 in-flight 名额模拟另一在途请求，第二个同凭据请求命中 OBSERVE 信号）。
func TestServeNext_CredentialConcurrency(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	g.CredentialConcurrencyLimit = 2

	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer env-concurrency-token")
	req.RemoteAddr = "203.0.113.60:1001"
	// 模拟另一在途同凭据请求（serveNext 外已有一个 in-flight）
	_, release := detectors.AcquireCredentialInFlight(detectors.CredentialKey(req, g.IdentitySalt))
	defer release()

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d: %+v", len(recs), recs)
	}
	found := false
	for _, d := range recs[0].Details {
		if d.RuleID == "auth.credential_concurrency" {
			found = true
			if d.Category != "OBSERVE" || d.Severity != "LOW" {
				t.Fatalf("bad concurrency detail attrs: %+v", d)
			}
		}
	}
	if !found {
		t.Fatalf("credential_concurrency detail missing: %+v", recs[0].Details)
	}
	// serveNext 出口已释放自身记账：仅剩手动预占的 1
	if n, rel := detectors.AcquireCredentialInFlight(detectors.CredentialKey(req, g.IdentitySalt)); n != 2 {
		rel()
		t.Fatalf("serveNext must release its in-flight slot, acquired count=%d (want 2 = manual + this probe)", n)
	} else {
		rel()
	}
}
