// debug_cccounter_test.go 调试回显端点（阶段5 §十七 CC 精确计数探针）单测：
// 开关、来源门禁、键不存在、方法/子路径、引擎故障与探针自污染防控。
package jiuzhang_guard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func debugTestGuard(t *testing.T) *Guard {
	t.Helper()
	return newTestGuard(t, Guard{
		AppID: "app1", AppCode: "shop",
		DebugCCCounter: true,
		RateLimits: []policyJSON{{
			ID: "p1", Name: "cc", Dimension: "CLIENT_IP", Algorithm: "SLIDING_WINDOW",
			RequestsLimit: 5, WindowSeconds: 60, Action: "REJECT", Priority: 1,
		}},
	})
}

func debugReq(method, target, remoteAddr string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = remoteAddr
	r.Header.Set("X-Request-Id", "11111111-2222-3333-4444-555555555555")
	return r
}

func ccCounterURL(policyID, ip string) string {
	return fmt.Sprintf("http://waf-test.local%s?policy_id=%s&ip=%s", debugCCCounterPath, policyID, ip)
}

func readDebugJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("response not JSON: %v body=%q", err, rec.Body.String())
	}
	return m
}

// 开关关闭：命名空间不抢占业务路径，请求照常进入下游（零行为变化）。
func TestDebugCCCounterDisabled(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", AppCode: "shop"})
	called := false
	rec := httptest.NewRecorder()
	r := debugReq(http.MethodGet, ccCounterURL("p1", "127.0.0.1"), "127.0.0.1:9000")
	if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
		t.Fatal(err)
	}
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("disabled endpoint must fall through to next: called=%v code=%d", called, rec.Code)
	}
}

// 非本机/内网连接源：404 墓碑（不暴露端点存在性），不进入下游。
func TestDebugCCCounterExternalSourceDenied(t *testing.T) {
	g := debugTestGuard(t)
	called := false
	rec := httptest.NewRecorder()
	r := debugReq(http.MethodGet, ccCounterURL("p1", "10.8.0.1"), "203.0.113.5:9000")
	if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("debug namespace must never reach upstream")
	}
	if rec.Code != http.StatusNotFound || rec.Body.String() != "404 not found" {
		t.Fatalf("external source: code=%d body=%q, want 404 tombstone", rec.Code, rec.Body.String())
	}
}

// 回显：业务流量计数后经端点读回（计数与 Allow 同口径）。
func TestDebugCCCounterEcho(t *testing.T) {
	g := debugTestGuard(t)
	called := false
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		if err := g.ServeHTTP(rec, req("10.8.0.1:1234", nil), nextHandler{&called}); err != nil {
			t.Fatal(err)
		}
	}
	rec := httptest.NewRecorder()
	r := debugReq(http.MethodGet, ccCounterURL("p1", "10.8.0.1"), "127.0.0.1:9000")
	if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("echo code=%d body=%q", rec.Code, rec.Body.String())
	}
	m := readDebugJSON(t, rec)
	if m["policy_id"] != "p1" || m["found"] != true || m["count"].(float64) != 2 {
		t.Fatalf("echo = %v, want policy p1 found count 2", m)
	}
	if m["limit"].(float64) != 5 || m["window_seconds"].(float64) != 60 {
		t.Fatalf("echo limit/window = %v", m)
	}
	// 响应不回显客户端 IP（只含计数与窗口）
	if _, ok := m["ip"]; ok {
		t.Fatalf("echo must not reflect client ip: %v", m)
	}
}

// 键不存在（该来源尚无计数）：found=false、count=0，不报错不建键。
func TestDebugCCCounterKeyNotFound(t *testing.T) {
	g := debugTestGuard(t)
	rec := httptest.NewRecorder()
	r := debugReq(http.MethodGet, ccCounterURL("p1", "10.9.9.9"), "127.0.0.1:9000")
	if err := g.ServeHTTP(rec, r, nextHandler{new(bool)}); err != nil {
		t.Fatal(err)
	}
	m := readDebugJSON(t, rec)
	if rec.Code != http.StatusOK || m["found"] != false || m["count"].(float64) != 0 {
		t.Fatalf("missing key echo: code=%d body=%v", rec.Code, m)
	}
}

// 探针自污染防控：回显请求本身不进入 CC 计数（先于 CC 步骤挂接）。
func TestDebugCCCounterNoSelfPollution(t *testing.T) {
	g := debugTestGuard(t)
	for i := 0; i < 6; i++ { // 超过策略阈值 5：若计数必触发 429
		rec := httptest.NewRecorder()
		r := debugReq(http.MethodGet, ccCounterURL("p1", "127.0.0.1"), "127.0.0.1:9000")
		if err := g.ServeHTTP(rec, r, nextHandler{new(bool)}); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("debug request %d counted (code=%d) — 端点请求不得进入 CC 计数", i+1, rec.Code)
		}
		m := readDebugJSON(t, rec)
		if m["found"] != false || m["count"].(float64) != 0 {
			t.Fatalf("endpoint self-pollution: echo=%v", m)
		}
	}
}

// 方法限制：POST 一律 405（Allow: GET）。
func TestDebugCCCounterMethodNotAllowed(t *testing.T) {
	g := debugTestGuard(t)
	rec := httptest.NewRecorder()
	r := debugReq(http.MethodPost, ccCounterURL("p1", "10.8.0.1"), "127.0.0.1:9000")
	if err := g.ServeHTTP(rec, r, nextHandler{new(bool)}); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST: code=%d allow=%q", rec.Code, rec.Header().Get("Allow"))
	}
}

// 未知子路径：本地 404 墓碑，不反向代理。
func TestDebugCCCounterUnknownSubpath(t *testing.T) {
	g := debugTestGuard(t)
	called := false
	rec := httptest.NewRecorder()
	r := debugReq(http.MethodGet, "http://waf-test.local/_wdsp/debug/v1/nope", "127.0.0.1:9000")
	if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
		t.Fatal(err)
	}
	if called || rec.Code != http.StatusNotFound {
		t.Fatalf("unknown subpath: called=%v code=%d", called, rec.Code)
	}
}

// 策略不存在 / 参数非法：如实 404/400 JSON 错误。
func TestDebugCCCounterBadParams(t *testing.T) {
	g := debugTestGuard(t)
	rec := httptest.NewRecorder()
	r := debugReq(http.MethodGet, ccCounterURL("nope", "10.8.0.1"), "127.0.0.1:9000")
	if err := g.ServeHTTP(rec, r, nextHandler{new(bool)}); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusNotFound || readDebugJSON(t, rec)["error"] != "POLICY_NOT_FOUND" {
		t.Fatalf("unknown policy: code=%d body=%q", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	r = debugReq(http.MethodGet, "http://waf-test.local"+debugCCCounterPath+"?policy_id=p1", "127.0.0.1:9000")
	if err := g.ServeHTTP(rec, r, nextHandler{new(bool)}); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest || readDebugJSON(t, rec)["error"] != "INVALID_IP" {
		t.Fatalf("missing ip: code=%d body=%q", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	r = debugReq(http.MethodGet, "http://waf-test.local"+debugCCCounterPath+"?ip=10.8.0.1", "127.0.0.1:9000")
	if err := g.ServeHTTP(rec, r, nextHandler{new(bool)}); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest || readDebugJSON(t, rec)["error"] != "MISSING_POLICY_ID" {
		t.Fatalf("missing policy_id: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

// 计数引擎故障：如实 503，不伪装计数。
func TestDebugCCCounterEngineError(t *testing.T) {
	g := debugTestGuard(t)
	g.engine.limiter = &errLimiter{}
	rec := httptest.NewRecorder()
	r := debugReq(http.MethodGet, ccCounterURL("p1", "10.8.0.1"), "127.0.0.1:9000")
	if err := g.ServeHTTP(rec, r, nextHandler{new(bool)}); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusServiceUnavailable || readDebugJSON(t, rec)["error"] != "ENGINE_UNAVAILABLE" {
		t.Fatalf("engine error: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

// 来源门禁边界：内网（RFC1918/ULA）放行，公网拒绝。
func TestDebugConnIPAllowed(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":   true,
		"::1":         true,
		"10.0.0.8":    true,
		"192.168.1.2": true,
		"172.16.3.4":  true,
		"fd00::1":     true,
		"203.0.113.5": false,
		"8.8.8.8":     false,
	}
	for s, want := range cases {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatal(err)
		}
		if got := debugConnIPAllowed(ip); got != want {
			t.Fatalf("debugConnIPAllowed(%s) = %v, want %v", s, got, want)
		}
	}
}
