// APM 阶段1（ADR D6/D7/D8/D9）：访问日志全量覆盖与新字段契约测试。
package jiuzhang_guard

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/l7rules"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/temporaryblock"
)

// newAPMLogGuard 构建开启全量访问日志（默认仅开关，不采头体）的测试 Guard。
func newAPMLogGuard(t *testing.T, cfg Guard) (*Guard, string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "access-full.jsonl")
	cfg.AccessLog = &accessLogJSON{Enabled: true}
	g := newTestGuard(t, cfg)
	aw, err := newAccessLogWriter(logPath)
	if err != nil {
		t.Fatal(err)
	}
	g.accessLog = aw
	t.Cleanup(func() { aw.close() })
	return g, logPath
}

// 前置拦截：IP 黑名单 403 产生记录，status/waf_action/trace 关联键正确，无下游 TTFB。
func TestAccessLogFrontInterceptionDeny(t *testing.T) {
	g, logPath := newAPMLogGuard(t, Guard{
		AppID:      "app1",
		GlobalDeny: []ruleJSON{{ID: "d1", Address: "203.0.113.66", Priority: 1}},
	})
	called := false
	err := g.ServeHTTP(httptest.NewRecorder(), req("203.0.113.66:1234", nil), nextHandler{&called})
	if err == nil || called {
		t.Fatalf("deny should block: err=%v called=%v", err, called)
	}
	recs := readAccessLogRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("front interception must produce exactly 1 record, got %d", len(recs))
	}
	rec := recs[0]
	if rec.ResponseStatus != http.StatusForbidden || rec.WAFAction != wafActionBlock {
		t.Fatalf("deny record wrong: status=%d action=%q", rec.ResponseStatus, rec.WAFAction)
	}
	if !isLowerHexLen(rec.TraceID, 32) || !isLowerHexLen(rec.SpanID, 16) {
		t.Fatalf("trace ids malformed: %+v", rec)
	}
	if rec.EndpointKey != "GET /echo" || rec.PathTemplate != "/echo" {
		t.Fatalf("endpoint fields wrong: %q %q", rec.EndpointKey, rec.PathTemplate)
	}
	if rec.TTFBMS != 0 {
		t.Fatalf("front interception has no downstream stage, ttfb must be omitted, got %d", rec.TTFBMS)
	}
}

// 前置拦截：人工临时封禁 403 产生记录（封禁优先于白名单链路）。
func TestAccessLogFrontInterceptionTempBlock(t *testing.T) {
	g, logPath := newAPMLogGuard(t, Guard{AppID: "app1"})
	g.engine.blockCache.PutLocal(reqCtx(), temporaryblock.Block{
		ID: "tb1", ClientIP: "203.0.113.77", AppID: "app1",
		ExpiresAt: time.Now().Add(time.Hour), Auto: false,
	})
	called := false
	err := g.ServeHTTP(httptest.NewRecorder(), req("203.0.113.77:1", nil), nextHandler{&called})
	if err == nil || called {
		t.Fatalf("temp blocked ip should be rejected: err=%v called=%v", err, called)
	}
	recs := readAccessLogRecords(t, logPath)
	if len(recs) != 1 || recs[0].ResponseStatus != http.StatusForbidden || recs[0].WAFAction != wafActionBlock {
		t.Fatalf("temp block record wrong: %+v", recs)
	}
}

// 前置拦截：CC REJECT 429 产生记录；同 IP 前一放行请求为 ALLOW——逐请求各记一条。
func TestAccessLogCCReject429(t *testing.T) {
	g, logPath := newAPMLogGuard(t, Guard{
		AppID: "app1",
		RateLimits: []policyJSON{{
			ID: "cc1", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "ALL", RequestsLimit: 1, WindowSeconds: 60, BurstCapacity: 1,
			Action: "REJECT", Priority: 1,
		}},
	})
	ip := "203.0.113.88:1"
	called := false
	if err := g.ServeHTTP(httptest.NewRecorder(), req(ip, nil), nextHandler{&called}); err != nil || !called {
		t.Fatalf("first request should pass: %v", err)
	}
	rec := httptest.NewRecorder()
	called = false
	if err := g.ServeHTTP(rec, req(ip, nil), nextHandler{&called}); err != nil || called {
		t.Fatalf("second request should be 429: %v", err)
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	recs := readAccessLogRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("expected 2 records (allow + reject), got %d", len(recs))
	}
	if recs[0].WAFAction != wafActionAllow || recs[0].ResponseStatus != http.StatusOK {
		t.Fatalf("allowed record wrong: %+v", recs[0])
	}
	if recs[1].WAFAction != wafActionBlock || recs[1].ResponseStatus != http.StatusTooManyRequests {
		t.Fatalf("rejected record wrong: %+v", recs[1])
	}
	if recs[1].TTFBMS != 0 {
		t.Fatalf("rejected request has no downstream stage, got ttfb %d", recs[1].TTFBMS)
	}
	// 两条记录的 trace_id 必须各自独立（逐请求新建）
	if recs[0].TraceID == recs[1].TraceID {
		t.Fatal("trace id must be per-request unique")
	}
}

// CC OBSERVE 命中未拦截：记录 OBSERVE，状态码为下游真实 200。
func TestAccessLogCCObserve(t *testing.T) {
	g, logPath := newAPMLogGuard(t, Guard{
		AppID: "app1",
		RateLimits: []policyJSON{{
			ID: "cc-obs", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "ALL", RequestsLimit: 1, WindowSeconds: 60,
			Action: "OBSERVE", Priority: 1,
		}},
	})
	ip := "203.0.113.90:1"
	for i := 0; i < 2; i++ {
		called := false
		if err := g.ServeHTTP(httptest.NewRecorder(), req(ip, nil), nextHandler{&called}); err != nil || !called {
			t.Fatalf("observe must not block (req %d): %v", i, err)
		}
	}
	recs := readAccessLogRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}
	if recs[0].WAFAction != wafActionAllow {
		t.Fatalf("first request under threshold should be ALLOW, got %q", recs[0].WAFAction)
	}
	if recs[1].WAFAction != wafActionObserve || recs[1].ResponseStatus != http.StatusOK {
		t.Fatalf("observe record wrong: %+v", recs[1])
	}
}

// 前置拦截：L7 redirect 302 产生记录（直接写响应终结请求的路径）。
func TestAccessLogL7Redirect(t *testing.T) {
	g, logPath := newAPMLogGuard(t, Guard{
		AppID: "app1",
		L7Rules: l7Config(l7rules.RuleJSON{
			ID: "l7-redir", Priority: 1, Enabled: true,
			Conditions:   []l7rules.ConditionJSON{{Type: "uri", Op: "prefix", Value: "/old"}},
			Action:       "redirect",
			ActionConfig: l7rules.ActionConfigJSON{RedirectURL: "https://example.com/new", RedirectStatus: 302},
		}),
	})
	r := l7Req("GET", "/old/page", "203.0.113.10:1234")
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, r, nextHandler{new(bool)}); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 302 {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	recs := readAccessLogRecords(t, logPath)
	if len(recs) != 1 || recs[0].ResponseStatus != 302 || recs[0].WAFAction != wafActionBlock {
		t.Fatalf("l7 redirect record wrong: %+v", recs)
	}
	if recs[0].TTFBMS != 0 {
		t.Fatalf("l7 redirect has no downstream stage, got ttfb %d", recs[0].TTFBMS)
	}
}

// 放行链路：记录含 trace_id/span_id/endpoint_key/path_template/ttfb_ms，waf_action=ALLOW；
// 端点归一化对纯 WAF 路径（未开 API 动态防护）同样生效（D7）。
func TestAccessLogPassthroughAPMFields(t *testing.T) {
	g, logPath := newAPMLogGuard(t, Guard{AppID: "app1"})
	next := caddyHTTPHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		// 制造可观测的下游耗时，保证 TTFB > 0
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return nil
	})
	r := httptest.NewRequest("GET", "http://waf-test.local/users/12345?debug=1", nil)
	r.RemoteAddr = "203.0.113.66:1234"
	r.Header.Set("X-Request-Id", "req-apm-1")
	if err := g.ServeHTTP(httptest.NewRecorder(), r, next); err != nil {
		t.Fatal(err)
	}
	recs := readAccessLogRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	rec := recs[0]
	if rec.WAFAction != wafActionAllow || rec.ResponseStatus != http.StatusOK {
		t.Fatalf("passthrough record wrong: %+v", rec)
	}
	if !isLowerHexLen(rec.TraceID, 32) || !isLowerHexLen(rec.SpanID, 16) {
		t.Fatalf("trace ids malformed: %+v", rec)
	}
	if rec.EndpointKey != "GET /users/{id}" || rec.PathTemplate != "/users/{id}" {
		t.Fatalf("endpoint normalization wrong: %q %q", rec.EndpointKey, rec.PathTemplate)
	}
	if rec.TTFBMS < 5 {
		t.Fatalf("ttfb_ms should reflect downstream stage latency, got %d", rec.TTFBMS)
	}
	if rec.DurationMS < rec.TTFBMS {
		t.Fatalf("duration %d should cover ttfb %d", rec.DurationMS, rec.TTFBMS)
	}
	// 记录 trace 与请求上下文 trace 同源（D6 关联一致性）
	tc := traceContextFrom(r.Context())
	if rec.TraceID != tc.TraceID || rec.SpanID != tc.SpanID {
		t.Fatalf("record trace must match request context: %+v vs %+v", rec, tc)
	}
}

// 单请求只记一条：开启全采（头体）时前置拦截（含请求体）同样只落一条。
func TestAccessLogSingleRecordWithBodyCapture(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "access-full.jsonl")
	g := newTestGuard(t, Guard{
		AppID:      "app1",
		GlobalDeny: []ruleJSON{{ID: "d1", Address: "203.0.113.66", Priority: 1}},
	})
	aw, err := newAccessLogWriter(logPath)
	if err != nil {
		t.Fatal(err)
	}
	g.accessLog = aw
	t.Cleanup(func() { aw.close() })
	g.AccessLog = &accessLogJSON{Enabled: true, CaptureRequestBody: true, BodyLimitKB: 64}

	r := httptest.NewRequest("POST", "http://waf-test.local/login", strings.NewReader(`{"u":"a"}`))
	r.RemoteAddr = "203.0.113.66:1"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Request-Id", "req-deny-body")
	called := false
	if err := g.ServeHTTP(httptest.NewRecorder(), r, nextHandler{&called}); err == nil || called {
		t.Fatal("deny should block")
	}
	recs := readAccessLogRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("exactly 1 record expected, got %d", len(recs))
	}
	if recs[0].RequestBody == "" {
		t.Fatal("blocked request body should still be captured")
	}
}

// RequestContext 桥接 + API 事件 trace 关联：放行链路统一上下文填充 TraceID/SpanID/
// ApplicationID/Domain/ClientIP/ConnectionIP（D6），API 事件与访问日志同 trace_id。
func TestTraceBridgingIntoRequestContextAndEvents(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"id": "number"}}
	apiLogPath := filepath.Join(t.TempDir(), "api-runtime-events.log")
	g, accessLogPath := newAPMLogGuard(t, Guard{
		AppID:                "app1",
		AppCode:              "shop",
		APIDynamicProtection: true,
		APIProtectionMode:    "OBSERVE",
		APIFormalSchemas:     schemas,
	})
	al, err := apievents.NewLogger(apiLogPath, "test-node")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = al.Close() })
	g.apiEvents = al

	next := caddyHTTPHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	r := httptest.NewRequest("POST", "http://waf-test.local/v1/orders", strings.NewReader(`{"id":"abc"}`))
	r.RemoteAddr = "203.0.113.70:1234"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Request-Id", "req-bridge-1")
	if err := g.ServeHTTP(httptest.NewRecorder(), r, next); err != nil {
		t.Fatal(err)
	}

	rc := RequestContextFrom(r)
	if rc == nil {
		t.Fatal("RequestContext not injected")
	}
	if !isLowerHexLen(rc.TraceID, 32) || !isLowerHexLen(rc.SpanID, 16) {
		t.Fatalf("bridged trace ids malformed: %+v", rc)
	}
	if rc.ApplicationID != "app1" || rc.Domain != "waf-test.local" {
		t.Fatalf("bridged app/domain wrong: %q %q", rc.ApplicationID, rc.Domain)
	}
	if rc.ClientIP.String() != "203.0.113.70" || rc.ConnectionIP.String() != "203.0.113.70" {
		t.Fatalf("bridged ips wrong: client=%v conn=%v", rc.ClientIP, rc.ConnectionIP)
	}
	// 同源一致性：访问日志、API 事件、统一上下文同一 trace_id（D6 双向检索）
	accessRecs := readAccessLogRecords(t, accessLogPath)
	if len(accessRecs) != 1 || accessRecs[0].TraceID != rc.TraceID || accessRecs[0].SpanID != rc.SpanID {
		t.Fatalf("access log trace mismatch: %+v vs ctx %s/%s", accessRecs, rc.TraceID, rc.SpanID)
	}
	// OBSERVE 模式 + 模型偏离：访问日志 waf_action 应为 OBSERVE（API 观察命中未拦截）
	if accessRecs[0].WAFAction != wafActionObserve {
		t.Fatalf("api observe hit should mark OBSERVE, got %q", accessRecs[0].WAFAction)
	}
	apiRecs := readAPIRecords(t, apiLogPath)
	if len(apiRecs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(apiRecs))
	}
	if apiRecs[0].TraceID != rc.TraceID {
		t.Fatalf("api event trace_id %q != ctx %q", apiRecs[0].TraceID, rc.TraceID)
	}
}
