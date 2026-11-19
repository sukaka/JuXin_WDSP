package jiuzhang_guard

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/pipeline"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
)

// riskServe 发送一个请求经完整 ServeHTTP 链路（自定义状态码处理器可选）。
func riskServe(t *testing.T, g *Guard, remoteAddr, target, ua string, status int) (rec *httptest.ResponseRecorder, called bool, err error) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = remoteAddr
	r.Header.Set("X-Request-Id", "risk-test-event-1")
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	rec = httptest.NewRecorder()
	h := ibHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(status)
		return nil
	})
	err = g.ServeHTTP(rec, r, h)
	return rec, called, err
}

// riskKey 计算与请求同形的 identity_key（风险累加器种子用）；accept 非空时按携带
// Accept 头的请求口径计算（匿名 UA 身份的浏览器指纹纳入 Accept，见 ResolveIdentity）。
func riskKey(t *testing.T, salt, ip, ua string, accept ...string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "http://waf-test.local/", nil)
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	for _, a := range accept {
		r.Header.Set("Accept", a)
	}
	return identitybehavior.ResolveIdentity(r, salt, ip).Key
}

// riskEvents 读取 events.log 中 RISK_POLICY_* 事件。
func riskEvents(t *testing.T, path string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, m := range readIBEvents(t, path) {
		if m["event_type"] == "RISK_POLICY_BLOCK" || m["event_type"] == "RISK_POLICY_CHALLENGE" || m["event_type"] == "RISK_POLICY_RATE_LIMIT" {
			out = append(out, m)
		}
	}
	return out
}

// 配置缺省 = 零行为变化：nil / enabled=false 不装配引擎，请求照常且无风险事件。
func TestRiskPolicyDefaultZeroChange(t *testing.T) {
	dir := t.TempDir()
	g := provisionIBHTestGuard(t, Guard{AppID: "app1", EventsLog: filepath.Join(dir, "events.log")})
	if g.risk != nil {
		t.Fatal("nil risk_policy must not provision engine")
	}
	_, called, err := riskServe(t, g, "203.0.113.10:1", "http://waf-test.local/", "sqlmap/1.7", 200)
	if err != nil || !called {
		t.Fatalf("zero-change pass: %v %v", err, called)
	}
	g2 := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: filepath.Join(dir, "events2.log"),
		RiskPolicy: &riskPolicyJSON{Enabled: false},
	})
	if g2.risk != nil {
		t.Fatal("disabled risk_policy must not provision engine")
	}
}

// OBSERVE 永不实断：80 分达 block 阈值请求照常放行，事件记录"假设会处置"（字段完整、
// signals 明细可解释 80 分构成）。
func TestRiskPolicyObserveWouldBlock(t *testing.T) {
	dir := t.TempDir()
	evPath := filepath.Join(dir, "events.log")
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: evPath, IdentitySalt: "test-salt",
		RiskPolicy: &riskPolicyJSON{Enabled: true, Version: 1},
	})
	key := riskKey(t, "test-salt", "203.0.113.10", "sqlmap/1.7")
	g.risk.AddSignal(key, "SENSITIVE_PATH_PROBE", 15, "seeded recon")
	g.risk.AddSignal(key, "AUTH_FAIL_PROBE", 15, "seeded auth fail")
	g.risk.AddSignal(key, "WAF", 50, "seeded sqli")
	rec, called, err := riskServe(t, g, "203.0.113.10:1", "http://waf-test.local/", "sqlmap/1.7", 200)
	if err != nil || !called || rec.Code != 200 {
		t.Fatalf("OBSERVE must never block: err=%v called=%v code=%d", err, called, rec.Code)
	}
	evs := riskEvents(t, evPath)
	if len(evs) != 1 || evs[0]["event_type"] != "RISK_POLICY_BLOCK" || evs[0]["action"] != "would_block" {
		t.Fatalf("would_block event: %v", evs)
	}
	risk := evs[0]["risk"].(map[string]any)
	if risk["identity_key"] != key || risk["score"].(float64) != 80 ||
		risk["risk_level"] != "CRITICAL" || risk["threshold"].(float64) != 80 ||
		risk["mode"] != "OBSERVE" || risk["policy_version"].(float64) != 1 ||
		risk["reason"] != "identity_risk_policy" || risk["action_taken"] != "would_block" {
		t.Fatalf("risk detail fields: %v", risk)
	}
	sigs := risk["signals"].([]any)
	if len(sigs) != 3 {
		t.Fatalf("signals must explain the 80: %v", sigs)
	}
	sum := 0
	for i, s := range sigs {
		e := s.(map[string]any)
		sum += int(e["score"].(float64))
		if e["type"] == "" || e["at"] == "" || e["reason"] == "" {
			t.Fatalf("signal[%d] detail incomplete: %v", i, e)
		}
	}
	if sum != 80 {
		t.Fatalf("signals must sum to score 80: %d", sum)
	}
}

// PROTECT 实断：80 分 → 403、上游不到达，事件 action_taken=blocked、reason=identity_risk_policy。
func TestRiskPolicyProtectBlocks(t *testing.T) {
	dir := t.TempDir()
	evPath := filepath.Join(dir, "events.log")
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: evPath, IdentitySalt: "test-salt",
		RiskPolicy: &riskPolicyJSON{Enabled: true, Mode: "PROTECT", Version: 2},
	})
	key := riskKey(t, "test-salt", "203.0.113.10", "sqlmap/1.7")
	g.risk.AddSignal(key, "WAF", 80, "seeded")
	rec, called, err := riskServe(t, g, "203.0.113.10:1", "http://waf-test.local/", "sqlmap/1.7", 200)
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != 403 || called {
		t.Fatalf("PROTECT must 403 before upstream: err=%v called=%v", err, called)
	}
	if got := rec.Header().Get("X-Jiuzhang-Risk-Reason"); got != "identity_risk_policy" {
		t.Fatalf("403 risk reason = %q, want identity_risk_policy", got)
	}
	if got := rec.Header().Get("X-Jiuzhang-Policy-Version"); got != "2" {
		t.Fatalf("403 policy version = %q, want 2", got)
	}
	if got := rec.Header().Get("X-Jiuzhang-Risk-Event-ID"); got == "" {
		t.Fatal("403 must identify the associated risk event")
	}
	evs := riskEvents(t, evPath)
	if len(evs) != 1 || evs[0]["action"] != "blocked" {
		t.Fatalf("blocked event: %v", evs)
	}
	risk := evs[0]["risk"].(map[string]any)
	if risk["action_taken"] != "blocked" || risk["reason"] != "identity_risk_policy" ||
		risk["mode"] != "PROTECT" || risk["policy_version"].(float64) != 2 ||
		evs[0]["response_status"].(float64) != 403 {
		t.Fatalf("blocked event fields: %v", evs[0])
	}
}

// PROTECT 限速：40 分入 RATE_LIMIT 档，rps=1 → 首请求放行、次请求 429（Retry-After），
// 事件 action_taken=rate_limited。
func TestRiskPolicyProtectRateLimit(t *testing.T) {
	dir := t.TempDir()
	evPath := filepath.Join(dir, "events.log")
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: evPath, IdentitySalt: "test-salt",
		RiskPolicy: &riskPolicyJSON{Enabled: true, Mode: "PROTECT", Version: 1, RateLimitRPS: 1},
	})
	key := riskKey(t, "test-salt", "203.0.113.10", "sqlmap/1.7", "application/json")
	g.risk.AddSignal(key, "AUTH_FAIL_PROBE", 40, "seeded")
	// 本测试两请求与种子键必须同口径携带 Accept: application/json：
	//   - 匿名 UA 身份的浏览器指纹纳入 Accept 头（identitybehavior.ResolveIdentity），
	//      Accept 有无会产生不同 identity_key（不同限速桶与风险累加键）；
	//   - 429 响应体按 Accept 内容协商（writeTooMany 既有设计：仅声明 JSON 时返回
	//     JSON 元数据体，否则返回 HTML 错误页），下方 JSON 断言以声明为前提。
	// riskServe 不带 Accept，故内联构造请求
	serve := func() (rec *httptest.ResponseRecorder, called bool, err error) {
		r := httptest.NewRequest(http.MethodGet, "http://waf-test.local/", nil)
		r.RemoteAddr = "203.0.113.10:1"
		r.Header.Set("X-Request-Id", "risk-test-event-1")
		r.Header.Set("User-Agent", "sqlmap/1.7")
		r.Header.Set("Accept", "application/json")
		rec = httptest.NewRecorder()
		err = g.ServeHTTP(rec, r, ibHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			called = true
			w.WriteHeader(200)
			return nil
		}))
		return rec, called, err
	}
	_, called, err := serve()
	if err != nil || !called {
		t.Fatalf("first request within rps must pass: %v %v", err, called)
	}
	rec, called, err := serve()
	if err != nil || called || rec.Code != 429 {
		t.Fatalf("second request must be 429: err=%v called=%v code=%d", err, called, rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
	if got := rec.Header().Get("X-Jiuzhang-Risk-Reason"); got != "identity_risk_policy" {
		t.Fatalf("429 risk reason = %q, want identity_risk_policy", got)
	}
	if got := rec.Header().Get("X-Jiuzhang-Policy-Version"); got != "1" {
		t.Fatalf("429 policy version = %q, want 1", got)
	}
	if got := rec.Header().Get("X-Jiuzhang-Risk-Event-ID"); got == "" {
		t.Fatal("429 must identify the associated risk event")
	}
	var response map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("429 response must be JSON: %v", err)
	}
	if response["reason_code"] != "identity_risk_policy" || response["policy_version"] != "1" || response["event_id"] == "" {
		t.Fatalf("429 risk metadata: %+v", response)
	}
	evs := riskEvents(t, evPath)
	if len(evs) != 1 || evs[0]["event_type"] != "RISK_POLICY_RATE_LIMIT" || evs[0]["action"] != "rate_limited" {
		t.Fatalf("rate_limited event: %v", evs)
	}
	risk := evs[0]["risk"].(map[string]any)
	if risk["score"].(float64) != 40 || risk["threshold"].(float64) != 40 ||
		risk["risk_level"] != "HIGH" || risk["action_taken"] != "rate_limited" {
		t.Fatalf("rate limit event fields: %v", risk)
	}
}

// 白名单优先：身份行为白名单命中跳过处置与累积；IP 白名单命中提前放行不评估。
func TestRiskPolicyWhitelistSkips(t *testing.T) {
	dir := t.TempDir()
	// 身份行为白名单（identitybehavior whitelist）
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: filepath.Join(dir, "events.log"), IdentitySalt: "test-salt",
		IdentityBehavior: &identityBehaviorJSON{Enabled: true, WhitelistIPs: []string{"203.0.113.0/24"}},
		RiskPolicy:       &riskPolicyJSON{Enabled: true, Mode: "PROTECT"},
	})
	key := riskKey(t, "test-salt", "203.0.113.10", "sqlmap/1.7")
	g.risk.AddSignal(key, "WAF", 100, "seeded")
	_, called, err := riskServe(t, g, "203.0.113.10:1", "http://waf-test.local/", "sqlmap/1.7", 200)
	if err != nil || !called {
		t.Fatalf("identity-behavior whitelisted must skip enforcement: %v %v", err, called)
	}
	if evs := riskEvents(t, filepath.Join(dir, "events.log")); len(evs) != 0 {
		t.Fatalf("whitelisted must emit no risk events: %v", evs)
	}
	// IP 白名单（全局 allow 命中提前放行，执行点不可达）
	g2 := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: filepath.Join(dir, "events2.log"), IdentitySalt: "test-salt",
		GlobalAllow: []ruleJSON{{ID: "a1", Address: "203.0.113.0/24", Priority: 1}},
		RiskPolicy:  &riskPolicyJSON{Enabled: true, Mode: "PROTECT"},
	})
	key2 := riskKey(t, "test-salt", "203.0.113.10", "sqlmap/1.7")
	g2.risk.AddSignal(key2, "WAF", 100, "seeded")
	_, called, err = riskServe(t, g2, "203.0.113.10:1", "http://waf-test.local/", "sqlmap/1.7", 200)
	if err != nil || !called {
		t.Fatalf("IP allow must pass before risk enforcement: %v %v", err, called)
	}
}

// 阶段3 验收语义（组合）：Recon15 + AuthFail15 + SQLi50 = 80 达阈后后续请求被 BLOCK，
// 事件 signals 解释 80 分构成——三条信号分别经三个真实入口入账。
func TestRiskPolicyAcceptanceCombo(t *testing.T) {
	dir := t.TempDir()
	evPath := filepath.Join(dir, "events.log")
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: evPath, IdentitySalt: "test-salt",
		IdentityBehavior: &identityBehaviorJSON{Enabled: true},
		RiskPolicy:       &riskPolicyJSON{Enabled: true, Mode: "PROTECT", Version: 1},
	})
	ua := "sqlmap/1.7"
	// 入口1（identitybehavior recon → End sink）：敏感路径探测 +15
	_, called, err := riskServe(t, g, "203.0.113.10:1", "http://waf-test.local/.git/config", ua, 200)
	if err != nil || !called {
		t.Fatalf("probe must pass pre-threshold: %v %v", err, called)
	}
	// 入口1（AUTH-FAIL-001）：10 次 401 → +15
	for i := 0; i < 10; i++ {
		if _, _, err := riskServe(t, g, "203.0.113.10:1", "http://waf-test.local/api/login", ua, 401); err != nil {
			t.Fatalf("401 request %d: %v", i, err)
		}
	}
	// 入口2（apiprotect 统一管线 DetectorMatch → emitAPIEvent）：waf SQLi +50
	syn := httptest.NewRequest(http.MethodGet, "http://waf-test.local/api/users", nil)
	syn.RemoteAddr = "203.0.113.10:0" // 与 serveGuard 改写后同形
	syn.Header.Set("User-Agent", ua)
	res := &pipeline.Result{Context: dsctx.New("req-syn", dsctx.DefaultParseLimits())}
	res.Context.AddMatch(dsctx.DetectorMatch{
		Detector: "waf", RuleID: "waf.downstream_intercept", Category: "BLOCK",
		Severity: "HIGH", ScoreDelta: 50, Message: "request blocked by downstream WAF (coraza interruption)",
	})
	g.emitAPIEvent(syn, res, nil)
	// 累计 15+15+50 = 80 达阈 → 后续请求被 BLOCK
	_, called, err = riskServe(t, g, "203.0.113.10:1", "http://waf-test.local/api/users", ua, 200)
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != 403 || called {
		t.Fatalf("80 must BLOCK: err=%v called=%v", err, called)
	}
	// 事件必须解释 80 分构成
	evs := riskEvents(t, evPath)
	if len(evs) != 1 {
		t.Fatalf("blocked event: %v", evs)
	}
	risk := evs[0]["risk"].(map[string]any)
	if risk["score"].(float64) != 80 || risk["reason"] != "identity_risk_policy" ||
		risk["action_taken"] != "blocked" {
		t.Fatalf("combo event: %v", risk)
	}
	sigs := risk["signals"].([]any)
	byType := map[string]int{}
	for _, s := range sigs {
		e := s.(map[string]any)
		byType[e["type"].(string)] += int(e["score"].(float64))
	}
	want := map[string]int{"SENSITIVE_PATH_PROBE": 15, "AUTH_FAIL_PROBE": 15, "WAF": 50}
	if len(sigs) != 3 || byType["SENSITIVE_PATH_PROBE"] != 15 || byType["AUTH_FAIL_PROBE"] != 15 || byType["WAF"] != 50 {
		t.Fatalf("event must explain 80 = %v: %v", want, byType)
	}
}

// 阶段3 验收语义（单一）：Headless +10 单独不能 Block（也不入 RATE_LIMIT 档）。
func TestRiskPolicyHeadlessAloneNoBlock(t *testing.T) {
	dir := t.TempDir()
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: filepath.Join(dir, "events.log"), IdentitySalt: "test-salt",
		IdentityBehavior: &identityBehaviorJSON{Enabled: true},
		RiskPolicy:       &riskPolicyJSON{Enabled: true, Mode: "PROTECT"},
	})
	ua := "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0 Safari/537.36"
	for i := 0; i < 3; i++ {
		_, called, err := riskServe(t, g, "203.0.113.10:1", "http://waf-test.local/", ua, 200)
		if err != nil || !called {
			t.Fatalf("headless +10 alone must not block (req %d): %v %v", i, err, called)
		}
	}
	// 入口3（HEADLESS-001）已入账 10 分（60s 节流 → 仅首请求计分）
	key := riskKey(t, "test-salt", "203.0.113.10", ua)
	dec, err := g.risk.Evaluate(key)
	if err != nil || dec.Score != 10 || dec.Action != "PASS" ||
		len(dec.Signals) != 1 || dec.Signals[0].Type != "HEADLESS" {
		t.Fatalf("headless accumulation: %+v %v", dec, err)
	}
}

// policy.scores 覆盖端到端：SENSITIVE_PATH_PROBE 覆盖为 65（自带 15 被覆盖）。
func TestRiskPolicyScoreOverrideEndToEnd(t *testing.T) {
	dir := t.TempDir()
	evPath := filepath.Join(dir, "events.log")
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: evPath, IdentitySalt: "test-salt",
		IdentityBehavior: &identityBehaviorJSON{Enabled: true},
		RiskPolicy: &riskPolicyJSON{Enabled: true, Mode: "OBSERVE",
			Scores: map[string]int{"SENSITIVE_PATH_PROBE": 65}},
	})
	ua := "sqlmap/1.7"
	if _, _, err := riskServe(t, g, "203.0.113.10:1", "http://waf-test.local/.git/config", ua, 200); err != nil {
		t.Fatal(err)
	}
	// 65 入 RATE_LIMIT 档 → OBSERVE 记录 would_rate_limit，明细分为覆盖值 65
	if _, _, err := riskServe(t, g, "203.0.113.10:1", "http://waf-test.local/", ua, 200); err != nil {
		t.Fatal(err)
	}
	evs := riskEvents(t, evPath)
	if len(evs) != 1 || evs[0]["action"] != "would_rate_limit" {
		t.Fatalf("would_rate_limit event: %v", evs)
	}
	risk := evs[0]["risk"].(map[string]any)
	sigs := risk["signals"].([]any)
	if risk["score"].(float64) != 65 || len(sigs) != 1 ||
		sigs[0].(map[string]any)["score"].(float64) != 65 {
		t.Fatalf("override must apply (65 not 15): %v", risk)
	}
}

// 事件节流：60s / identity+action —— 连续阻断仅 1 条事件。
func TestRiskPolicyEventThrottle(t *testing.T) {
	dir := t.TempDir()
	evPath := filepath.Join(dir, "events.log")
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: evPath, IdentitySalt: "test-salt",
		RiskPolicy: &riskPolicyJSON{Enabled: true, Mode: "PROTECT"},
	})
	key := riskKey(t, "test-salt", "203.0.113.10", "sqlmap/1.7")
	g.risk.AddSignal(key, "WAF", 100, "seeded")
	for i := 0; i < 3; i++ {
		if _, _, err := riskServe(t, g, "203.0.113.10:1", "http://waf-test.local/", "sqlmap/1.7", 200); err == nil {
			t.Fatalf("req %d must block", i)
		}
	}
	if evs := riskEvents(t, evPath); len(evs) != 1 {
		t.Fatalf("events must throttle to 1/60s/identity+action: %v", evs)
	}
}

// 配置非法 fail-open 按 OBSERVE：非法 mode 消毒为 OBSERVE（Warn），达阈也不实断。
func TestRiskPolicyInvalidModeFailOpen(t *testing.T) {
	dir := t.TempDir()
	evPath := filepath.Join(dir, "events.log")
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: evPath, IdentitySalt: "test-salt",
		RiskPolicy: &riskPolicyJSON{Enabled: true, Mode: "BLOCK_ALL", BlockThreshold: -1},
	})
	if g.risk == nil {
		t.Fatal("invalid config must still provision in OBSERVE (fail-open)")
	}
	if g.risk.Config().Mode != "OBSERVE" || g.risk.Config().BlockThreshold != 80 {
		t.Fatalf("sanitize: %+v", g.risk.Config())
	}
	key := riskKey(t, "test-salt", "203.0.113.10", "sqlmap/1.7")
	g.risk.AddSignal(key, "WAF", 100, "seeded")
	_, called, err := riskServe(t, g, "203.0.113.10:1", "http://waf-test.local/", "sqlmap/1.7", 200)
	if err != nil || !called {
		t.Fatalf("invalid config must fail-open OBSERVE (no block): %v %v", err, called)
	}
	if evs := riskEvents(t, evPath); len(evs) != 1 || evs[0]["action"] != "would_block" {
		t.Fatalf("would_block on invalid config: %v", evs)
	}
}

// apiprotect 信号入口专项：ScoreDelta>0 的 DetectorMatch 入账（detector 名大写蛇形），
// ≤0 不入账；身份行为白名单命中不累积。
func TestRiskPolicyAPIDetectorIntake(t *testing.T) {
	dir := t.TempDir()
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: filepath.Join(dir, "events.log"), IdentitySalt: "test-salt",
		RiskPolicy: &riskPolicyJSON{Enabled: true},
	})
	ua := "sqlmap/1.7"
	mk := func() *pipeline.Result {
		res := &pipeline.Result{Context: dsctx.New("req-x", dsctx.DefaultParseLimits())}
		res.Context.AddMatch(dsctx.DetectorMatch{Detector: "waf", ScoreDelta: 50, Message: "sqli"})
		res.Context.AddMatch(dsctx.DetectorMatch{Detector: "api_schema", ScoreDelta: 15, RuleID: "schema.type_mismatch"})
		res.Context.AddMatch(dsctx.DetectorMatch{Detector: "api_parser", ScoreDelta: 0})
		return res
	}
	syn := httptest.NewRequest(http.MethodGet, "http://waf-test.local/api", nil)
	syn.RemoteAddr = "203.0.113.10:0"
	syn.Header.Set("User-Agent", ua)
	g.emitAPIEvent(syn, mk(), nil)
	key := riskKey(t, "test-salt", "203.0.113.10", ua)
	dec, _ := g.risk.Evaluate(key)
	if dec.Score != 65 || len(dec.Signals) != 2 ||
		dec.Signals[0].Type != "WAF" || dec.Signals[1].Type != "API_SCHEMA" {
		t.Fatalf("detector intake: %+v", dec)
	}
	// 身份行为白名单命中：不累积
	g2 := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: filepath.Join(dir, "events2.log"), IdentitySalt: "test-salt",
		IdentityBehavior: &identityBehaviorJSON{Enabled: true, WhitelistIPs: []string{"203.0.113.0/24"}},
		RiskPolicy:       &riskPolicyJSON{Enabled: true},
	})
	g2.emitAPIEvent(syn, mk(), nil)
	dec, _ = g2.risk.Evaluate(key)
	if dec.Score != 0 {
		t.Fatalf("whitelisted identity must not accumulate: %+v", dec)
	}
}

// 配置重载（Provision/Cleanup）无泄漏：Cleanup 置 nil 且可重复；重装配继续处置。
func TestRiskPolicyReloadNoLeak(t *testing.T) {
	dir := t.TempDir()
	mk := func() *Guard {
		resetSharedEngineForTest()
		g := &Guard{
			AppID: "app1", EventsLog: filepath.Join(dir, "events.log"), IdentitySalt: "test-salt",
			RiskPolicy: &riskPolicyJSON{Enabled: true, Mode: "PROTECT"},
		}
		if err := g.Provision(caddy.Context{Context: t.Context()}); err != nil {
			t.Fatalf("provision: %v", err)
		}
		return g
	}
	g1 := mk()
	key := riskKey(t, "test-salt", "203.0.113.10", "sqlmap/1.7")
	g1.risk.AddSignal(key, "WAF", 100, "seeded")
	if _, _, err := riskServe(t, g1, "203.0.113.10:1", "http://waf-test.local/", "sqlmap/1.7", 200); err == nil {
		t.Fatal("gen1 must block")
	}
	if err := g1.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if g1.risk == nil {
		t.Fatal("cleanup must keep engine field assigned (request path reads are lock-free)")
	}
	if err := g1.Cleanup(); err != nil {
		t.Fatalf("second cleanup must be safe: %v", err)
	}
	g2 := mk()
	defer g2.Cleanup()
	g2.risk.AddSignal(key, "WAF", 100, "seeded")
	if _, _, err := riskServe(t, g2, "203.0.113.10:1", "http://waf-test.local/", "sqlmap/1.7", 200); err == nil {
		t.Fatal("gen2 must block")
	}
	resetSharedEngineForTest()
}

func TestRiskPolicyObserveWouldChallenge(t *testing.T) {
	dir := t.TempDir()
	evPath := filepath.Join(dir, "events.log")
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: evPath, IdentitySalt: "test-salt",
		RiskPolicy: &riskPolicyJSON{
			Enabled: true, Mode: "OBSERVE", Version: 7,
			RateLimitThreshold: 20, ChallengeThreshold: 40, BlockThreshold: 80,
		},
	})
	key := riskKey(t, "test-salt", "203.0.113.10", "sqlmap/1.7")
	g.risk.AddSignal(key, "WAF", 50, "seeded")
	rec, called, err := riskServe(t, g, "203.0.113.10:1", "http://waf-test.local/", "sqlmap/1.7", http.StatusOK)
	if err != nil || !called || rec.Code != http.StatusOK {
		t.Fatalf("OBSERVE challenge must continue: err=%v called=%v code=%d", err, called, rec.Code)
	}
	evs := riskEvents(t, evPath)
	if len(evs) != 1 || evs[0]["event_type"] != "RISK_POLICY_CHALLENGE" || evs[0]["action"] != "would_challenge" {
		t.Fatalf("would_challenge events=%v", evs)
	}
	risk := evs[0]["risk"].(map[string]any)
	if risk["action_taken"] != "would_challenge" || risk["score"].(float64) != 50 ||
		risk["threshold"].(float64) != 40 || risk["policy_version"].(float64) != 7 {
		t.Fatalf("risk detail=%v", risk)
	}
	if _, ok := evs[0]["final_decision"]; ok {
		t.Fatalf("OBSERVE event must not carry final_decision: %v", evs[0])
	}
}

func TestRiskPolicyChallengeBotDependencyValidation(t *testing.T) {
	challengePolicy := func() *riskPolicyJSON {
		return &riskPolicyJSON{
			Enabled: true, Mode: "PROTECT", RateLimitThreshold: 20,
			ChallengeThreshold: 40, BlockThreshold: 80,
		}
	}
	for _, tc := range []struct {
		name    string
		botMode string
		wantErr bool
	}{
		{name: "missing", botMode: "missing", wantErr: true},
		{name: "off", botMode: botModeOff, wantErr: true},
		{name: "observe", botMode: botModeObserve, wantErr: true},
		{name: "protect", botMode: botModeProtect, wantErr: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := Guard{AppID: "app1", EventsLog: "events.log", RiskPolicy: challengePolicy()}
			if tc.botMode != "missing" {
				g.BotPolicy = mustJSON(t, botStepSection(tc.botMode))
			}
			err := g.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		policy *riskPolicyJSON
	}{
		{name: "observe_does_not_require_bot", policy: &riskPolicyJSON{Enabled: true, Mode: "OBSERVE", ChallengeThreshold: 40}},
		{name: "default_off_does_not_require_bot", policy: &riskPolicyJSON{Enabled: true, Mode: "PROTECT"}},
		{name: "inverted_tier_does_not_require_bot", policy: &riskPolicyJSON{Enabled: true, Mode: "PROTECT", ChallengeThreshold: 20}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := Guard{AppID: "app1", EventsLog: "events.log", RiskPolicy: tc.policy}
			if err := g.Validate(); err != nil {
				t.Fatalf("non-executing challenge configuration must remain valid: %v", err)
			}
		})
	}
}

func TestRiskPolicyChallengeDependencyUsesApplicationOverride(t *testing.T) {
	global := &riskPolicyJSON{
		Enabled: true, Mode: "PROTECT", RateLimitThreshold: 20,
		ChallengeThreshold: 40, BlockThreshold: 80,
	}
	for _, tc := range []struct {
		name      string
		global    *riskPolicyJSON
		overrides []riskPolicyOverrideJSON
		wantErr   bool
	}{
		{
			name: "current_override_enables_challenge", global: &riskPolicyJSON{Enabled: true, Mode: "OBSERVE"},
			overrides: []riskPolicyOverrideJSON{{ApplicationID: "app1", Policy: *global}}, wantErr: true,
		},
		{
			name:      "current_override_disables_global_challenge",
			global:    global,
			overrides: []riskPolicyOverrideJSON{{ApplicationID: "app1", Policy: riskPolicyJSON{Enabled: false}}},
		},
		{
			name:      "unrelated_override_does_not_reject_current_app",
			global:    &riskPolicyJSON{Enabled: true, Mode: "OBSERVE"},
			overrides: []riskPolicyOverrideJSON{{ApplicationID: "app2", Policy: *global}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := Guard{
				AppID: "app1", EventsLog: "events.log", RiskPolicy: tc.global,
				RiskPolicyOverrides: tc.overrides,
			}
			err := g.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// H-08 回归：在已封禁或已达风险阈值的 X-API-Key/Cookie 之上附加伪造 Authorization 头，
// 不得绕过 api_identity_blocks 或 Risk Engine 处置。
func TestH08MultiCredentialBypassBlocked(t *testing.T) {
	t.Run("api_identity_blocks 检查全部提取凭据", func(t *testing.T) {
		rBase := httptest.NewRequest("GET", "http://waf-test.local/api", nil)
		rBase.Header.Set("X-API-Key", "blocked-api-key")
		blockedKey := identitybehavior.ResolveIdentity(rBase, "salt-h08", "203.0.113.50").Key

		g := provisionIBHTestGuard(t, Guard{
			AppID:        "app1",
			EventsLog:    filepath.Join(t.TempDir(), "events.log"),
			IdentitySalt: "salt-h08",
			APIIdentityBlocks: []identityBlockJSON{
				{ID: "blk-1", IdentityKey: blockedKey},
			},
		})
		// 附加假 Authorization 头，试图掩盖被封禁的 X-API-Key
		rBypass := httptest.NewRequest("GET", "http://waf-test.local/api", nil)
		rBypass.RemoteAddr = "203.0.113.50:1234"
		rBypass.Header.Set("Authorization", "Bearer dummy-bypass-token")
		rBypass.Header.Set("X-API-Key", "blocked-api-key")
		called := false
		err := g.ServeHTTP(httptest.NewRecorder(), rBypass, ibHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			called = true
			return nil
		}))
		var he caddyhttp.HandlerError
		if !errors.As(err, &he) || he.StatusCode != http.StatusForbidden || called {
			t.Fatalf("H-08: 附加 Authorization 不得绕过 X-API-Key 封禁: err=%v called=%v", err, called)
		}
	})

	t.Run("Risk Engine 评估全部提取凭据防附加 Authorization 绕过", func(t *testing.T) {
		rKey := httptest.NewRequest("GET", "http://waf-test.local/api", nil)
		rKey.Header.Set("X-API-Key", "risky-api-key")
		riskyKey := identitybehavior.ResolveIdentity(rKey, "salt-h08", "203.0.113.51").Key

		g := provisionIBHTestGuard(t, Guard{
			AppID:        "app1",
			EventsLog:    filepath.Join(t.TempDir(), "events.log"),
			IdentitySalt: "salt-h08",
			RiskPolicy:   &riskPolicyJSON{Enabled: true, Mode: "PROTECT", BlockThreshold: 80},
		})
		g.risk.AddSignal(riskyKey, "WAF", 90, "seeded-risky-apikey")

		// 同时携带假 Authorization 与受罚 X-API-Key
		rBypass := httptest.NewRequest("GET", "http://waf-test.local/api", nil)
		rBypass.RemoteAddr = "203.0.113.51:1234"
		rBypass.Header.Set("Authorization", "Bearer dummy-fresh-token")
		rBypass.Header.Set("X-API-Key", "risky-api-key")
		called := false
		err := g.ServeHTTP(httptest.NewRecorder(), rBypass, ibHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			called = true
			return nil
		}))
		var he caddyhttp.HandlerError
		if !errors.As(err, &he) || he.StatusCode != http.StatusForbidden || called {
			t.Fatalf("H-08: 附加 Authorization 不得绕过受罚 X-API-Key 风险阻断: err=%v called=%v", err, called)
		}
	})
}
