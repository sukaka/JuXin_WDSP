package jiuzhang_guard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"go.uber.org/zap"
)

// newAdmissionTestGuard 构造启用 API 动态防护 + 准入策略的 Guard（不经过 Provision，
// 运行时字段直接注入；compile 路径由 TestCompileAPIAdmissionPolicies 覆盖）。
func newAdmissionTestGuard(t *testing.T, globalMode string, policies map[string]detectors.AdmissionPolicy) (*Guard, string) {
	t.Helper()
	g, logPath := newAPITestGuard(t, globalMode, nil)
	g.apiAdmission = policies
	return g, logPath
}

// ---------- 配置编译（fail-safe 归一） ----------

func TestCompileAPIAdmissionPolicies(t *testing.T) {
	g := &Guard{logger: zap.NewNop()}
	if got := g.compileAPIAdmissionPolicies(); got != nil {
		t.Fatalf("nil section must compile to nil, got %+v", got)
	}
	g.APIAdmissionPolicies = &apiAdmissionSectionJSON{}
	if got := g.compileAPIAdmissionPolicies(); got != nil {
		t.Fatalf("empty policies must compile to nil, got %+v", got)
	}
	g.APIAdmissionPolicies = &apiAdmissionSectionJSON{Policies: map[string]apiAdmissionPolicyJSON{
		"app-observe": {Mode: "observe", ConfirmedEndpoints: []string{"GET /v1/a", "GET /v1/a", " ", ""}},
		"app-protect": {Mode: "PROTECT", ConfirmedEndpoints: []string{"POST /v1/login"}},
		"app-off":     {Mode: "OFF", ConfirmedEndpoints: []string{"GET /v1/x"}},
		"app-bad":     {Mode: "BLOCK_ALL", ConfirmedEndpoints: []string{"GET /v1/x"}},
		"app-empty":   {Mode: "", ConfirmedEndpoints: []string{"GET /v1/x"}},
		" ":           {Mode: "PROTECT"},
	}}
	got := g.compileAPIAdmissionPolicies()
	if len(got) != 2 {
		t.Fatalf("only OBSERVE/PROTECT policies must survive (OFF/非法 fail-safe 不启用), got %+v", got)
	}
	ob, ok := got["app-observe"]
	if !ok || ob.Mode != detectors.AdmissionModeObserve {
		t.Fatalf("lowercase observe must normalize to OBSERVE, got %+v", got)
	}
	if len(ob.Confirmed) != 1 {
		t.Fatalf("confirmed endpoints must be trimmed/deduped/empties-dropped, got %+v", ob.Confirmed)
	}
	if _, ok := ob.Confirmed["GET /v1/a"]; !ok {
		t.Fatalf("confirmed set content wrong: %+v", ob.Confirmed)
	}
	pr, ok := got["app-protect"]
	if !ok || pr.Mode != detectors.AdmissionModeProtect || len(pr.Confirmed) != 1 {
		t.Fatalf("protect policy wrong: %+v", got)
	}
	for _, dropped := range []string{"app-off", "app-bad", "app-empty", " "} {
		if _, ok := got[dropped]; ok {
			t.Fatalf("policy %q must be dropped (fail-safe OFF), got %+v", dropped, got)
		}
	}
	// 全部策略均 fail-safe 丢弃时返回 nil（而非空 map，与「无策略」同构）
	g.APIAdmissionPolicies = &apiAdmissionSectionJSON{Policies: map[string]apiAdmissionPolicyJSON{
		"app-bad": {Mode: "NOPE"},
	}}
	if got := g.compileAPIAdmissionPolicies(); got != nil {
		t.Fatalf("all-invalid section must compile to nil, got %+v", got)
	}
}

// ---------- 请求→应用策略解析 ----------

func TestAPIAdmissionPolicyForApp(t *testing.T) {
	g := &Guard{logger: zap.NewNop()}
	if p := g.apiAdmissionPolicyForApp(); p != nil {
		t.Fatalf("no policies must resolve nil, got %+v", p)
	}
	g.AppID = "app-1"
	if p := g.apiAdmissionPolicyForApp(); p != nil {
		t.Fatalf("empty policy map must resolve nil, got %+v", p)
	}
	g.apiAdmission = map[string]detectors.AdmissionPolicy{
		"app-1": {Mode: detectors.AdmissionModeProtect, Confirmed: map[string]struct{}{"GET /v1/a": {}}},
	}
	p := g.apiAdmissionPolicyForApp()
	if p == nil || p.Mode != detectors.AdmissionModeProtect {
		t.Fatalf("own app policy must resolve, got %+v", p)
	}
	if _, ok := p.Confirmed["GET /v1/a"]; !ok {
		t.Fatalf("confirmed set wrong: %+v", p.Confirmed)
	}
	g.AppID = "app-other"
	if p := g.apiAdmissionPolicyForApp(); p != nil {
		t.Fatalf("other app must resolve nil (解析不到应用无策略不判定), got %+v", p)
	}
	g.AppID = ""
	if p := g.apiAdmissionPolicyForApp(); p != nil {
		t.Fatalf("empty AppID (应用未识别) must resolve nil, got %+v", p)
	}
}

// ---------- 端到端：PROTECT 实断 403 统一响应 ----------

func TestServeNext_AdmissionProtectDeniesWithUniformJSON(t *testing.T) {
	g, logPath := newAdmissionTestGuard(t, "PROTECT", map[string]detectors.AdmissionPolicy{
		"app-1": {Mode: detectors.AdmissionModeProtect, Confirmed: map[string]struct{}{"POST /v1/orders": {}}},
	})
	g.APIKnownEndpoints = map[string]string{"POST /v1/discovered": "DISCOVERED"}

	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/discovered", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-adm-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("admission-denied response is written directly, err must be nil, got %v", err)
	}
	if called {
		t.Fatal("next handler must not run when admission-denied")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	// 统一响应体精确匹配（unknown/unconfirmed 不区分；键序字典序由 encoding/json 保证）
	wantBody := `{"code":"API_ADMISSION_DENIED","message":"该接口未开放访问","request_id":"req-adm-1"}`
	if got := rec.Body.String(); got != wantBody {
		t.Fatalf("body = %q, want %q", got, wantBody)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}
	if rid := rec.Header().Get("X-Jiuzhang-Request-ID"); rid != "req-adm-1" {
		t.Fatalf("X-Jiuzhang-Request-ID = %q", rid)
	}
	// 事件照常落盘：BLOCK + 403 + admission 明细（内部记录真实原因 unconfirmed）
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %+v", recs)
	}
	if recs[0].FinalAction != "BLOCK" || recs[0].ResponseStatus != http.StatusForbidden {
		t.Fatalf("event = %+v", recs[0])
	}
	var found bool
	for _, m := range recs[0].Details {
		if m.Detector == "admission" && m.RuleID == "admission.unconfirmed_endpoint" && m.Category == "BLOCK" {
			found = true
		}
	}
	if !found {
		t.Fatalf("event must carry admission.unconfirmed_endpoint BLOCK detail: %+v", recs[0].Details)
	}
}

// 未知端点（基线无）与未确认端点响应体完全一致（防资产探测）；内部 finding 区分。
func TestServeNext_AdmissionProtectUnknownSameBody(t *testing.T) {
	g, logPath := newAdmissionTestGuard(t, "PROTECT", map[string]detectors.AdmissionPolicy{
		"app-1": {Mode: detectors.AdmissionModeProtect, Confirmed: map[string]struct{}{"POST /v1/orders": {}}},
	})
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	req := httptest.NewRequest(http.MethodPost, "/v1/never-seen", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-adm-2")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	wantBody := `{"code":"API_ADMISSION_DENIED","message":"该接口未开放访问","request_id":"req-adm-2"}`
	if got := rec.Body.String(); got != wantBody {
		t.Fatalf("body = %q, want %q", got, wantBody)
	}
	recs := readAPIRecords(t, logPath)
	var found bool
	for _, m := range recs[0].Details {
		if m.RuleID == "admission.unknown_endpoint" {
			found = true
		}
	}
	if !found {
		t.Fatalf("internal detail must record true reason unknown: %+v", recs[0].Details)
	}
}

// 已确认端点：放行进入下游，无 admission 明细。
func TestServeNext_AdmissionConfirmedPasses(t *testing.T) {
	g, _ := newAdmissionTestGuard(t, "PROTECT", map[string]detectors.AdmissionPolicy{
		"app-1": {Mode: detectors.AdmissionModeProtect, Confirmed: map[string]struct{}{"POST /v1/orders": {}}},
	})
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
		t.Fatal("confirmed endpoint must pass to downstream")
	}
}

// OBSERVE 模式：放行 + 观测 finding 入事件流；lifecycle.new_endpoint 被覆盖不重复。
func TestServeNext_AdmissionObservePassesAndRecords(t *testing.T) {
	g, logPath := newAdmissionTestGuard(t, "OBSERVE", map[string]detectors.AdmissionPolicy{
		"app-1": {Mode: detectors.AdmissionModeObserve, Confirmed: map[string]struct{}{"POST /v1/orders": {}}},
	})
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/never-seen", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called {
		t.Fatal("OBSERVE admission must pass through")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %+v", recs)
	}
	var admissionFound, lifecycleFound bool
	for _, m := range recs[0].Details {
		if m.RuleID == "admission.unknown_endpoint" && m.Category == "OBSERVE" && m.Severity == "LOW" {
			admissionFound = true
		}
		if m.RuleID == "lifecycle.new_endpoint" {
			lifecycleFound = true
		}
	}
	if !admissionFound {
		t.Fatalf("OBSERVE admission finding must enter event stream: %+v", recs[0].Details)
	}
	if lifecycleFound {
		t.Fatal("lifecycle.new_endpoint must be deduped when admission covered unknown")
	}
}

// 非法 mode fail-safe：装配后策略不存在 → 放行且不产 admission 明细（不拦截优于误拦截）。
func TestServeNext_AdmissionInvalidModeFailsSafe(t *testing.T) {
	g := &Guard{
		AppID:                "app-1",
		APIDynamicProtection: true,
		APIProtectionMode:    "PROTECT",
		logger:               zap.NewNop(),
	}
	g.APIAdmissionPolicies = &apiAdmissionSectionJSON{Policies: map[string]apiAdmissionPolicyJSON{
		"app-1": {Mode: "BLOCK_ALL", ConfirmedEndpoints: []string{"POST /v1/orders"}},
	}}
	g.apiAdmission = g.compileAPIAdmissionPolicies()
	if g.apiAdmission != nil {
		t.Fatalf("invalid mode must compile away, got %+v", g.apiAdmission)
	}
	g2, _ := newAdmissionTestGuard(t, "PROTECT", g.apiAdmission)
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/never-seen", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	if err := g2.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called {
		t.Fatal("invalid mode must fail-safe to no judgment (pass through)")
	}
}

// 全局管线模式 OBSERVE + 准入 PROTECT：统一决策按全局模式降级为 OBSERVE（不拦截），
// BLOCK 类 admission finding 照常入事件（全局模式是 API 管线统一实断阀门）。
func TestServeNext_AdmissionProtectDowngradedByGlobalObserve(t *testing.T) {
	g, logPath := newAdmissionTestGuard(t, "OBSERVE", map[string]detectors.AdmissionPolicy{
		"app-1": {Mode: detectors.AdmissionModeProtect, Confirmed: map[string]struct{}{"POST /v1/orders": {}}},
	})
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/never-seen", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called || rec.Code == http.StatusForbidden {
		t.Fatal("global OBSERVE must downgrade admission block (pass through)")
	}
	recs := readAPIRecords(t, logPath)
	var found bool
	for _, m := range recs[0].Details {
		if m.RuleID == "admission.unknown_endpoint" && m.Category == "BLOCK" {
			found = true
		}
	}
	if !found {
		t.Fatalf("BLOCK-category admission finding must be recorded as would-block: %+v", recs[0].Details)
	}
}

// 其他 BLOCK 来源（模型偏离）维持既有响应路径与格式（caddyhttp.Error → 错误链），
// 不被准入响应路径污染。
func TestServeNext_NonAdmissionBlockUnchanged(t *testing.T) {
	g, _ := newAdmissionTestGuard(t, "PROTECT", map[string]detectors.AdmissionPolicy{
		"app-1": {Mode: detectors.AdmissionModeProtect, Confirmed: map[string]struct{}{"POST /v1/orders": {}}},
	})
	g.APIFormalSchemas = map[string]map[string]string{"POST /v1/orders": {"id": "number"}}
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	err := g.serveNext(httptest.NewRecorder(), req, next)
	if err == nil {
		t.Fatal("schema block must keep caddyhttp.Error path")
	}
	if !strings.Contains(err.Error(), "request blocked by api protection") {
		t.Fatalf("non-admission block error changed: %v", err)
	}
}

// 热加载竞态：旧实例（旧基线）与新实例（新基线含新确认端点）并发服务——Caddy 整体
// 替换模型下策略结构 Provision 后只读，新旧并存不竞态、各自按本实例基线判定（go test -race）。
func TestServeNext_AdmissionHotReloadRace(t *testing.T) {
	oldG, _ := newAdmissionTestGuard(t, "PROTECT", map[string]detectors.AdmissionPolicy{
		"app-1": {Mode: detectors.AdmissionModeProtect, Confirmed: map[string]struct{}{"POST /v1/orders": {}}},
	})
	// 新实例：/v1/new 已确认（模拟确认 → 发布 → 新配置生效）
	newG, _ := newAdmissionTestGuard(t, "PROTECT", map[string]detectors.AdmissionPolicy{
		"app-1": {Mode: detectors.AdmissionModeProtect, Confirmed: map[string]struct{}{
			"POST /v1/orders": {}, "POST /v1/new": {},
		}},
	})
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() { // 旧实例：/v1/new 未确认 → 403
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/v1/new", strings.NewReader(`{"id":1}`))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			if err := oldG.serveNext(rec, req, next); err != nil {
				t.Errorf("old instance serveNext: %v", err)
			}
			if rec.Code != http.StatusForbidden {
				t.Errorf("old baseline must deny /v1/new, got %d", rec.Code)
			}
		}()
		go func() { // 新实例：/v1/new 已确认 → 放行
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/v1/new", strings.NewReader(`{"id":1}`))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			if err := newG.serveNext(rec, req, next); err != nil {
				t.Errorf("new instance serveNext: %v", err)
			}
			if rec.Code == http.StatusForbidden {
				t.Errorf("new baseline must pass /v1/new, got %d", rec.Code)
			}
		}()
	}
	wg.Wait()
}
