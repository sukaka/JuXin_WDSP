package jiuzhang_guard

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/wasmplugin"
	"go.uber.org/zap"
)

// ---------- Guard 集成测试用最小 Wasm 二进制辅助 ----------

func guardTestWasmULEB(v uint32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			return out
		}
	}
}

func guardTestWasmSLEB(v int32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		done := (v == 0 && (b&0x40) == 0) || (v == -1 && (b&0x40) != 0)
		if !done {
			b |= 0x80
		}
		out = append(out, b)
		if done {
			return out
		}
	}
}

func guardTestWasmSec(id byte, payload []byte) []byte {
	out := []byte{id}
	out = append(out, guardTestWasmULEB(uint32(len(payload)))...)
	return append(out, payload...)
}

func guardTestWasmStr(s string) []byte {
	return append(guardTestWasmULEB(uint32(len(s))), []byte(s)...)
}

// buildGuardTestStaticWasm 生成调用 wdsp_env.set_result(action, score, rule, reason) 的最小 Wasm 二进制。
func buildGuardTestStaticWasm(action, score int32, rule, reason string) []byte {
	const (
		rulePtr   int32 = 0x100
		reasonPtr int32 = 0x200
	)
	bin := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

	// Type section: type 0 = (i32 x6)->(), type 1 = ()->()
	typePayload := []byte{0x02, 0x60, 0x06, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x00, 0x60, 0x00, 0x00}
	bin = append(bin, guardTestWasmSec(1, typePayload)...)

	// Import section: wdsp_env.set_result (func 0, type 0)
	var imp []byte
	imp = append(imp, 0x01)
	imp = append(imp, guardTestWasmStr("wdsp_env")...)
	imp = append(imp, guardTestWasmStr("set_result")...)
	imp = append(imp, 0x00, 0x00)
	bin = append(bin, guardTestWasmSec(2, imp)...)

	// Function section: func 1 -> type 1
	bin = append(bin, guardTestWasmSec(3, []byte{0x01, 0x01})...)

	// Memory section: 1 page
	bin = append(bin, guardTestWasmSec(5, []byte{0x01, 0x00, 0x01})...)

	// Export section: memory (mem 0), wdsp_on_request (func 1)
	var exp []byte
	exp = append(exp, 0x02)
	exp = append(exp, guardTestWasmStr("memory")...)
	exp = append(exp, 0x02, 0x00)
	exp = append(exp, guardTestWasmStr("wdsp_on_request")...)
	exp = append(exp, 0x00, 0x01)
	bin = append(bin, guardTestWasmSec(7, exp)...)

	// Code section
	var body []byte
	body = append(body, 0x00) // 0 locals
	for _, v := range []int32{action, score, rulePtr, int32(len(rule)), reasonPtr, int32(len(reason))} {
		body = append(body, 0x41)
		body = append(body, guardTestWasmSLEB(v)...)
	}
	body = append(body, 0x10, 0x00, 0x0b) // call 0, end
	var codeSec []byte
	codeSec = append(codeSec, 0x01)
	codeSec = append(codeSec, guardTestWasmULEB(uint32(len(body)))...)
	codeSec = append(codeSec, body...)
	bin = append(bin, guardTestWasmSec(10, codeSec)...)

	// Data section
	var dataSec []byte
	dataSec = append(dataSec, 0x02)
	for _, seg := range []struct {
		off int32
		val string
	}{{rulePtr, rule}, {reasonPtr, reason}} {
		dataSec = append(dataSec, 0x00, 0x41)
		dataSec = append(dataSec, guardTestWasmSLEB(seg.off)...)
		dataSec = append(dataSec, 0x0b)
		dataSec = append(dataSec, guardTestWasmStr(seg.val)...)
	}
	bin = append(bin, guardTestWasmSec(11, dataSec)...)
	return bin
}

// buildGuardTestLoopWasm 生成死循环 Wasm 二进制用于超时测试。
func buildGuardTestLoopWasm() []byte {
	bin := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	bin = append(bin, guardTestWasmSec(1, []byte{0x01, 0x60, 0x00, 0x00})...)
	bin = append(bin, guardTestWasmSec(3, []byte{0x01, 0x00})...)
	bin = append(bin, guardTestWasmSec(5, []byte{0x01, 0x00, 0x01})...)
	var exp []byte
	exp = append(exp, 0x02)
	exp = append(exp, guardTestWasmStr("memory")...)
	exp = append(exp, 0x02, 0x00)
	exp = append(exp, guardTestWasmStr("wdsp_on_request")...)
	exp = append(exp, 0x00, 0x00)
	bin = append(bin, guardTestWasmSec(7, exp)...)
	// body: 0 locals, loop (void) br 0 end, end
	body := []byte{0x00, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b}
	codeSec := append([]byte{0x01}, guardTestWasmULEB(uint32(len(body)))...)
	codeSec = append(codeSec, body...)
	bin = append(bin, guardTestWasmSec(10, codeSec)...)
	return bin
}

func guardWasmPluginConfigJSON(t *testing.T, plugins []map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"application_id": "app-wasm-1",
		"plugins":        plugins,
	})
	if err != nil {
		t.Fatalf("marshal wasm_plugins: %v", err)
	}
	return raw
}

func guardWasmPluginMap(id, name, mode, failPolicy string, bin []byte, extra map[string]any) map[string]any {
	sum := sha256.Sum256(bin)
	m := map[string]any{
		"id":             id,
		"name":           name,
		"version":        1,
		"abi_version":    wasmplugin.ABIVersionV1,
		"mode":           mode,
		"sha256":         hex.EncodeToString(sum[:]),
		"wasm_base64":    base64.StdEncoding.EncodeToString(bin),
		"priority":       100,
		"timeout_ms":     50,
		"max_memory_kb":  4096,
		"max_body_bytes": 16,
		"fail_policy":    failPolicy,
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func newWasmTestGuard(t *testing.T, cfgJSON json.RawMessage) (*Guard, string) {
	t.Helper()
	dir := t.TempDir()
	evLog := filepath.Join(dir, "events.log")
	el, err := events.NewLogger(evLog, "gw-wasm-test")
	if err != nil {
		t.Fatalf("events.NewLogger: %v", err)
	}
	g := &Guard{
		AppID:       "app-wasm-1",
		AppCode:     "wasm-app",
		EventsLog:   evLog,
		GatewayNode: "gw-wasm-test",
		WasmPlugins: cfgJSON,
		logger:      zap.NewNop(),
		events:      el,
	}
	if err := g.Validate(); err != nil {
		_ = el.Close()
		t.Fatalf("Guard.Validate: %v", err)
	}
	if err := g.assembleWasmPlugins(); err != nil {
		_ = el.Close()
		t.Fatalf("Guard.assembleWasmPlugins: %v", err)
	}
	t.Cleanup(func() {
		_ = g.Cleanup()
	})
	return g, evLog
}

func TestWasmGuardValidateAssembleAndCleanup(t *testing.T) {
	bin := buildGuardTestStaticWasm(wasmplugin.ActionAllow, 0, "ok", "ok")

	// 1. 未知字段 fail-closed
	gBad := &Guard{
		EventsLog:   filepath.Join(t.TempDir(), "events.log"),
		WasmPlugins: json.RawMessage(`{"schema_version":1,"unknown":1,"plugins":[]}`),
		logger:      zap.NewNop(),
	}
	if err := gBad.Validate(); err == nil {
		t.Fatal("Validate must reject unknown field in wasm_plugins")
	}

	// 2. 全部插件 OFF 时 g.wasmPlugins == nil（零开销直通）
	offCfg := guardWasmPluginConfigJSON(t, []map[string]any{
		guardWasmPluginMap("p-off", "off_plg", wasmplugin.ModeOff, wasmplugin.FailOpen, bin, nil),
	})
	gOff, _ := newWasmTestGuard(t, offCfg)
	if gOff.wasmPlugins != nil {
		t.Fatal("OFF-only plugins must leave g.wasmPlugins == nil")
	}

	// 3. Cleanup 幂等释放运行期资源
	actCfg := guardWasmPluginConfigJSON(t, []map[string]any{
		guardWasmPluginMap("p-act", "act_plg", wasmplugin.ModeProtect, wasmplugin.FailOpen, bin, nil),
	})
	gAct, _ := newWasmTestGuard(t, actCfg)
	if gAct.wasmPlugins == nil {
		t.Fatal("expected active wasmPlugins engine")
	}
	if err := gAct.Cleanup(); err != nil {
		t.Fatalf("Cleanup 1: %v", err)
	}
	if err := gAct.Cleanup(); err != nil {
		t.Fatalf("Cleanup 2 (idempotent): %v", err)
	}
}

func TestWasmGuardServeNextOutcomesAndBodyPreservation(t *testing.T) {
	// 1. ALLOW 绝不绕过下游，且超出 max_body_bytes(16) 的请求体必须完整无损透传给下游
	allowBin := buildGuardTestStaticWasm(wasmplugin.ActionAllow, 0, "allow.rule", "ok")
	gAllow, _ := newWasmTestGuard(t, guardWasmPluginConfigJSON(t, []map[string]any{
		guardWasmPluginMap("p-allow", "allow_plg", wasmplugin.ModeProtect, wasmplugin.FailOpen, allowBin, map[string]any{
			"max_body_bytes": 16,
		}),
	}))

	fullBody := "0123456789abcdefghijklmnopqrstuvwxyz-COMPLETE-PAYLOAD"
	downstreamCalled := false
	var downstreamBody string
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		downstreamCalled = true
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		downstreamBody = string(b)
		w.WriteHeader(http.StatusOK)
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "https://example.com/api/v1/submit", strings.NewReader(fullBody))
	req.Header.Set("X-Request-Id", "req-wasm-allow")
	ctx, _ := WithDisposition(req.Context(), "gw-wasm-test")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	if err := gAllow.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext allow: %v", err)
	}
	if !downstreamCalled || rec.Code != http.StatusOK {
		t.Fatalf("ALLOW must invoke downstream (WAF/API/proxy), called=%v code=%d", downstreamCalled, rec.Code)
	}
	if downstreamBody != fullBody {
		t.Fatalf("request body corrupted after wasm peek: got %q want %q", downstreamBody, fullBody)
	}

	// 2. PROTECT BLOCK -> 403 + WASM_PLUGIN_BLOCK 事件 + final_decision，不进下游
	blockBin := buildGuardTestStaticWasm(wasmplugin.ActionBlock, 85, "custom.sqli", "union_select")
	gBlock, evBlockLog := newWasmTestGuard(t, guardWasmPluginConfigJSON(t, []map[string]any{
		guardWasmPluginMap("p-blk", "sqli_wasm", wasmplugin.ModeProtect, wasmplugin.FailOpen, blockBin, nil),
	}))
	downstreamCalled = false
	reqBlk := httptest.NewRequest(http.MethodGet, "https://example.com/api/v1/search?q=1", nil)
	reqBlk.Header.Set("X-Request-Id", "req-wasm-blk")
	ctxBlk, dispoBlk := WithDisposition(reqBlk.Context(), "gw-wasm-test")
	reqBlk = reqBlk.WithContext(ctxBlk)
	recBlk := httptest.NewRecorder()
	if err := gBlock.serveNext(recBlk, reqBlk, next); err != nil {
		t.Fatalf("serveNext block: %v", err)
	}
	if downstreamCalled {
		t.Fatal("PROTECT BLOCK must not reach downstream")
	}
	if recBlk.Code != http.StatusForbidden || !strings.Contains(recBlk.Body.String(), "wasm_plugin_blocked") {
		t.Fatalf("want 403 wasm_plugin_blocked, got %d body=%s", recBlk.Code, recBlk.Body.String())
	}
	if !dispoBlk.Terminated() {
		t.Fatal("expected disposition terminated on BLOCK")
	}
	evsBlk := readAccessControlEvents(t, evBlockLog)
	if len(evsBlk) != 1 || evsBlk[0].EventType != events.WasmPluginBlock || evsBlk[0].WasmPlugin == nil ||
		evsBlk[0].WasmPlugin.RuleID != "custom.sqli" || len(evsBlk[0].FinalDecision) == 0 {
		t.Fatalf("unexpected BLOCK event: %+v", evsBlk)
	}

	// 3. PROTECT RATE_LIMIT -> 429 + Retry-After + WASM_PLUGIN_RATE_LIMIT 事件
	rlBin := buildGuardTestStaticWasm(wasmplugin.ActionRateLimit, 60, "custom.burst", "rate_exceeded")
	gRL, evRLLog := newWasmTestGuard(t, guardWasmPluginConfigJSON(t, []map[string]any{
		guardWasmPluginMap("p-rl", "rl_wasm", wasmplugin.ModeProtect, wasmplugin.FailOpen, rlBin, nil),
	}))
	downstreamCalled = false
	reqRL := httptest.NewRequest(http.MethodGet, "https://example.com/api/v1/login", nil)
	reqRL.Header.Set("X-Request-Id", "req-wasm-rl")
	ctxRL, _ := WithDisposition(reqRL.Context(), "gw-wasm-test")
	reqRL = reqRL.WithContext(ctxRL)
	recRL := httptest.NewRecorder()
	if err := gRL.serveNext(recRL, reqRL, next); err != nil {
		t.Fatalf("serveNext rl: %v", err)
	}
	if downstreamCalled || recRL.Code != http.StatusTooManyRequests || recRL.Header().Get("Retry-After") == "" {
		t.Fatalf("want 429 with Retry-After and no downstream, code=%d retry=%q called=%v",
			recRL.Code, recRL.Header().Get("Retry-After"), downstreamCalled)
	}
	evsRL := readAccessControlEvents(t, evRLLog)
	if len(evsRL) != 1 || evsRL[0].EventType != events.WasmPluginRateLimit || evsRL[0].WasmPlugin == nil {
		t.Fatalf("unexpected RATE_LIMIT event: %+v", evsRL)
	}

	// 4. OBSERVE 模式命中 BLOCK 动作 -> 放行下游 + WASM_PLUGIN_OBSERVED 事件
	gObs, evObsLog := newWasmTestGuard(t, guardWasmPluginConfigJSON(t, []map[string]any{
		guardWasmPluginMap("p-obs", "obs_wasm", wasmplugin.ModeObserve, wasmplugin.FailOpen, blockBin, nil),
	}))
	downstreamCalled = false
	reqObs := httptest.NewRequest(http.MethodGet, "https://example.com/api/v1/search", nil)
	reqObs.Header.Set("X-Request-Id", "req-wasm-obs")
	ctxObs, _ := WithDisposition(reqObs.Context(), "gw-wasm-test")
	reqObs = reqObs.WithContext(ctxObs)
	recObs := httptest.NewRecorder()
	if err := gObs.serveNext(recObs, reqObs, next); err != nil {
		t.Fatalf("serveNext obs: %v", err)
	}
	if !downstreamCalled || recObs.Code != http.StatusOK {
		t.Fatalf("OBSERVE must pass downstream, called=%v code=%d", downstreamCalled, recObs.Code)
	}
	evsObs := readAccessControlEvents(t, evObsLog)
	if len(evsObs) != 1 || evsObs[0].EventType != events.WasmPluginObserved || evsObs[0].WasmPlugin == nil ||
		evsObs[0].WasmPlugin.ActionTaken != "would_block" {
		t.Fatalf("unexpected OBSERVE event: %+v", evsObs)
	}

	// 5. 死循环超时 + FAIL_CLOSED -> 503 wasm_plugin_unavailable + WASM_PLUGIN_ERROR 事件
	loopBin := buildGuardTestLoopWasm()
	gFC, evFCLog := newWasmTestGuard(t, guardWasmPluginConfigJSON(t, []map[string]any{
		guardWasmPluginMap("p-fc", "loop_fc", wasmplugin.ModeProtect, wasmplugin.FailClosed, loopBin, map[string]any{
			"timeout_ms": 10,
		}),
	}))
	downstreamCalled = false
	reqFC := httptest.NewRequest(http.MethodGet, "https://example.com/api/v1/heavy", nil)
	reqFC.Header.Set("X-Request-Id", "req-wasm-fc")
	ctxFC, _ := WithDisposition(reqFC.Context(), "gw-wasm-test")
	reqFC = reqFC.WithContext(ctxFC)
	recFC := httptest.NewRecorder()
	if err := gFC.serveNext(recFC, reqFC, next); err != nil {
		t.Fatalf("serveNext fail-closed: %v", err)
	}
	if downstreamCalled || recFC.Code != http.StatusServiceUnavailable || !strings.Contains(recFC.Body.String(), "wasm_plugin_unavailable") {
		t.Fatalf("FAIL_CLOSED timeout must return 503 wasm_plugin_unavailable, code=%d body=%s called=%v",
			recFC.Code, recFC.Body.String(), downstreamCalled)
	}
	evsFC := readAccessControlEvents(t, evFCLog)
	if len(evsFC) != 1 || evsFC[0].EventType != events.WasmPluginError || evsFC[0].ResponseStatus != http.StatusServiceUnavailable ||
		len(evsFC[0].FinalDecision) == 0 {
		t.Fatalf("unexpected FAIL_CLOSED error event: %+v", evsFC)
	}

	// 6. 死循环超时 + FAIL_OPEN -> 放行下游 + WASM_PLUGIN_ERROR (OBSERVE) 事件
	gFO, evFOLog := newWasmTestGuard(t, guardWasmPluginConfigJSON(t, []map[string]any{
		guardWasmPluginMap("p-fo", "loop_fo", wasmplugin.ModeProtect, wasmplugin.FailOpen, loopBin, map[string]any{
			"timeout_ms": 10,
		}),
	}))
	downstreamCalled = false
	reqFO := httptest.NewRequest(http.MethodGet, "https://example.com/api/v1/heavy", nil)
	reqFO.Header.Set("X-Request-Id", "req-wasm-fo")
	ctxFO, _ := WithDisposition(reqFO.Context(), "gw-wasm-test")
	reqFO = reqFO.WithContext(ctxFO)
	recFO := httptest.NewRecorder()
	if err := gFO.serveNext(recFO, reqFO, next); err != nil {
		t.Fatalf("serveNext fail-open: %v", err)
	}
	if !downstreamCalled || recFO.Code != http.StatusOK {
		t.Fatalf("FAIL_OPEN timeout must pass downstream, called=%v code=%d", downstreamCalled, recFO.Code)
	}
	evsFO := readAccessControlEvents(t, evFOLog)
	if len(evsFO) != 1 || evsFO[0].EventType != events.WasmPluginError || evsFO[0].Action != "OBSERVE" {
		t.Fatalf("unexpected FAIL_OPEN error event: %+v", evsFO)
	}
}

func TestWasmGuardOrderingAndAllowlistNoBypass(t *testing.T) {
	t.Setenv(capDisabledEnv, "1")
	rsaKey := jwtTestRSA(t)
	jwks := jwtTestJWKS(t, &rsaKey.PublicKey, "k-wasm-order")
	jwtRaw, err := json.Marshal(jwtStaticSection("PROTECT", true, jwks))
	if err != nil {
		t.Fatalf("marshal jwt_trust: %v", err)
	}

	blockBin := buildGuardTestStaticWasm(wasmplugin.ActionBlock, 90, "wasm.after_jwt", "blocked_after_jwt")
	dir := t.TempDir()
	evLog := filepath.Join(dir, "events.log")
	g := &Guard{
		AppID:          "app-wasm-order",
		AppCode:        "wasm-order",
		EventsLog:      evLog,
		GatewayNode:    "gw-wasm-order",
		CounterBackend: "memory",
		IdentitySalt:   jwtTestSalt,
		GlobalAllow:    []ruleJSON{{ID: "allow-1", Address: "198.51.100.10", Priority: 1}},
		JWTTrust:       jwtRaw,
		WasmPlugins: guardWasmPluginConfigJSON(t, []map[string]any{
			guardWasmPluginMap("p-order", "order_blk", wasmplugin.ModeProtect, wasmplugin.FailOpen, blockBin, map[string]any{
				"path_prefixes": []string{"/api"},
			}),
		}),
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := g.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer func() { _ = g.Cleanup() }()

	downstreamCalled := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		downstreamCalled = true
		w.WriteHeader(http.StatusOK)
		return nil
	})

	// 1. 命中 IP 白名单但无 JWT Bearer：JWT PROTECT 在 Wasm 之前执行 -> 401
	reqNoJWT := httptest.NewRequest(http.MethodGet, "https://example.com/api/orders", nil)
	reqNoJWT.RemoteAddr = "198.51.100.10:12345"
	reqNoJWT.Header.Set("X-Request-Id", "req-order-1")
	rec1 := httptest.NewRecorder()
	if err := g.ServeHTTP(rec1, reqNoJWT, next); err != nil {
		t.Fatalf("ServeHTTP no jwt: %v", err)
	}
	if downstreamCalled || rec1.Code != http.StatusUnauthorized {
		t.Fatalf("JWT PROTECT must reject 401 before Wasm runs, code=%d called=%v", rec1.Code, downstreamCalled)
	}

	// 2. 命中 IP 白名单且携带合法 JWT：JWT 放行后，IP 白名单不得绕过 Wasm PROTECT -> 403 wasm_plugin_blocked
	token := jwtSignRS256(t, rsaKey, "k-wasm-order", jwtValidClaims())
	reqWithJWT := httptest.NewRequest(http.MethodGet, "https://example.com/api/orders", nil)
	reqWithJWT.RemoteAddr = "198.51.100.10:12345"
	reqWithJWT.Header.Set("X-Request-Id", "req-order-2")
	reqWithJWT.Header.Set("Authorization", "Bearer "+token)
	rec2 := httptest.NewRecorder()
	if err := g.ServeHTTP(rec2, reqWithJWT, next); err != nil {
		t.Fatalf("ServeHTTP with jwt: %v", err)
	}
	if downstreamCalled || rec2.Code != http.StatusForbidden || !strings.Contains(rec2.Body.String(), "wasm_plugin_blocked") {
		t.Fatalf("IP allowlist must NOT bypass Wasm PROTECT BLOCK, code=%d body=%s called=%v",
			rec2.Code, rec2.Body.String(), downstreamCalled)
	}
}
