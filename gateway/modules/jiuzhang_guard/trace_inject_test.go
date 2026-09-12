// APM 阶段2 前提（ADR D6）：trace_inject_upstream 上游注入契约测试。
package jiuzhang_guard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// upstreamCapture 捕获进入下游链（WAF/反向代理方向）的请求，模拟上游视角。
type upstreamCapture struct{ got **http.Request }

func (c upstreamCapture) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	*c.got = r
	w.WriteHeader(200)
	return nil
}

// 开关关闭（默认）：发往上游的请求字节零变化——无入站 traceparent 时上游收不到该头；
// 有入站 traceparent/tracestate 时按原样透传（本模块不增不改不删）。
func TestTraceInjectUpstreamOff(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1"})
	var got *http.Request
	r := req("203.0.113.66:1234", nil)
	if err := g.ServeHTTP(httptest.NewRecorder(), r, upstreamCapture{&got}); err != nil {
		t.Fatal(err)
	}
	if tp := got.Header.Get("traceparent"); tp != "" {
		t.Fatalf("inject disabled: upstream must see no traceparent, got %q", tp)
	}

	got = nil
	r = req("203.0.113.66:1234", map[string]string{
		"traceparent": testExtTraceparent,
		"tracestate":  "evil=pass-through-when-off",
	})
	if err := g.ServeHTTP(httptest.NewRecorder(), r, upstreamCapture{&got}); err != nil {
		t.Fatal(err)
	}
	if tp := got.Header.Get("traceparent"); tp != testExtTraceparent {
		t.Fatalf("inject disabled: inbound traceparent must pass through unchanged, got %q", tp)
	}
	if ts := got.Header.Get("tracestate"); ts != "evil=pass-through-when-off" {
		t.Fatalf("inject disabled: tracestate must be untouched, got %q", ts)
	}
}

// 开关开启：放行请求的上游带合法 traceparent（version 00、sampled=01），trace_id/span_id
// 与入口写入请求上下文的内部上下文一致；tracestate 不转发；客户端响应头不含 trace 上下文。
func TestTraceInjectUpstreamOn(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", TraceInjectUpstream: true})
	var got *http.Request
	rec := httptest.NewRecorder()
	r := req("203.0.113.66:1234", map[string]string{"tracestate": "evil=must-be-stripped"})
	if err := g.ServeHTTP(rec, r, upstreamCapture{&got}); err != nil {
		t.Fatal(err)
	}
	tp := got.Header.Get("traceparent")
	tc := traceContextFrom(r.Context())
	want := "00-" + tc.TraceID + "-" + tc.SpanID + "-01"
	if tp != want {
		t.Fatalf("upstream traceparent = %q, want %q (internal context)", tp, want)
	}
	parts := strings.Split(tp, "-")
	if len(parts) != 4 || parts[0] != "00" || parts[3] != "01" ||
		!isLowerHexLen(parts[1], 32) || !isLowerHexLen(parts[2], 16) {
		t.Fatalf("injected traceparent malformed: %q", tp)
	}
	if ts := got.Header.Get("tracestate"); ts != "" {
		t.Fatalf("tracestate must not be forwarded when injecting, got %q", ts)
	}
	// 不向客户端返回 trace 上下文（D5-6）
	for k := range rec.Header() {
		lk := strings.ToLower(k)
		if lk == "traceparent" || lk == "tracestate" || strings.Contains(lk, "trace-id") {
			t.Fatalf("trace context must not be returned to client, got header %s", k)
		}
	}
}

// 注入的 trace_id 与访问日志记录一致（安全事件 ↔ 访问记录 ↔ 上游 span 同一关联键）。
func TestTraceInjectUpstreamMatchesAccessLog(t *testing.T) {
	g, logPath := newAPMLogGuard(t, Guard{AppID: "app1", TraceInjectUpstream: true})
	var got *http.Request
	if err := g.ServeHTTP(httptest.NewRecorder(), req("203.0.113.66:1234", nil), upstreamCapture{&got}); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(got.Header.Get("traceparent"), "-")
	if len(parts) != 4 {
		t.Fatalf("injected traceparent malformed: %q", got.Header.Get("traceparent"))
	}
	recs := readAccessLogRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("expected 1 access log record, got %d", len(recs))
	}
	if recs[0].TraceID != parts[1] || recs[0].SpanID != parts[2] {
		t.Fatalf("access log trace %s/%s != injected %s/%s",
			recs[0].TraceID, recs[0].SpanID, parts[1], parts[2])
	}
}

// 外部伪造 traceparent（默认不信任）：注入的是内部新建 trace_id（与入站不同），
// 外部 span_id 不透传；tracestate 清除。
func TestTraceInjectUpstreamOverridesForgedExternal(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", TraceInjectUpstream: true})
	var got *http.Request
	r := req("203.0.113.66:1234", map[string]string{
		"traceparent": testExtTraceparent,
		"tracestate":  "evil=should-be-stripped",
	})
	if err := g.ServeHTTP(httptest.NewRecorder(), r, upstreamCapture{&got}); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(got.Header.Get("traceparent"), "-")
	if len(parts) != 4 {
		t.Fatalf("injected traceparent malformed: %q", got.Header.Get("traceparent"))
	}
	if parts[1] == testExtTraceID {
		t.Fatal("forged external trace_id must not be injected (default distrust)")
	}
	if parts[2] == testExtSpanID {
		t.Fatal("external span_id must never be propagated")
	}
	if got.Header.Get("tracestate") != "" {
		t.Fatal("tracestate must be stripped when injecting")
	}
}

// trace_trust_external + trace_inject_upstream 同时开启：续接外部 trace_id，
// 但 span_id 仍为内部重新生成（ADR D5-2 续接语义在注入侧同样成立）。
func TestTraceInjectUpstreamTrustExternalContinue(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", TraceTrustExternal: true, TraceInjectUpstream: true})
	var got *http.Request
	if err := g.ServeHTTP(httptest.NewRecorder(), req("203.0.113.66:1234",
		map[string]string{"traceparent": testExtTraceparent}), upstreamCapture{&got}); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(got.Header.Get("traceparent"), "-")
	if len(parts) != 4 || parts[1] != testExtTraceID {
		t.Fatalf("trusted external trace_id should be continued, got %q", got.Header.Get("traceparent"))
	}
	if !isLowerHexLen(parts[2], 16) || parts[2] == testExtSpanID {
		t.Fatalf("span id must be regenerated, got %q", parts[2])
	}
}

// 前置拦截分支（黑名单 403）不到上游：next 不被调用，注入逻辑不执行，
// 请求头保持入站原样（不存在"拦截请求改写头发往上游"的路径）。
func TestTraceInjectUpstreamFrontInterceptionNoInject(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID:               "app1",
		TraceInjectUpstream: true,
		GlobalDeny:          []ruleJSON{{ID: "d1", Address: "203.0.113.66", Priority: 1}},
	})
	var got *http.Request
	r := req("203.0.113.66:1234", map[string]string{"traceparent": testExtTraceparent})
	err := g.ServeHTTP(httptest.NewRecorder(), r, upstreamCapture{&got})
	if err == nil {
		t.Fatal("deny should block")
	}
	if got != nil {
		t.Fatal("intercepted request must not reach upstream")
	}
	if tp := r.Header.Get("traceparent"); tp != testExtTraceparent {
		t.Fatalf("intercepted request headers must stay untouched, got %q", tp)
	}
}
