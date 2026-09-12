package jiuzhang_guard

import (
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testExtTraceID     = "0af7651916cd43dd8448eb211c80319c"
	testExtSpanID      = "b7ad6b7169203331"
	testExtTraceparent = "00-" + testExtTraceID + "-" + testExtSpanID + "-01"
)

// isLowerHexLen 判定 s 为长度 n 的小写 hex 串。
func isLowerHexLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// 默认策略：不信任外部 traceparent，总是新建 trace_id；不向客户端返回 trace_id/tracestate。
func TestTraceDefaultAlwaysNew(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1"})
	r := req("203.0.113.66:1234", map[string]string{
		"traceparent": testExtTraceparent,
		"tracestate":  "evil=should-be-ignored",
	})
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, r, nextHandler{new(bool)}); err != nil {
		t.Fatal(err)
	}
	tc := traceContextFrom(r.Context())
	if !isLowerHexLen(tc.TraceID, 32) || !isLowerHexLen(tc.SpanID, 16) {
		t.Fatalf("trace ids malformed: %+v", tc)
	}
	if tc.TraceID == testExtTraceID {
		t.Fatal("external traceparent must not be trusted by default")
	}
	// 不向客户端返回 trace 上下文（D5-6）
	for k := range rec.Header() {
		lk := strings.ToLower(k)
		if lk == "traceparent" || lk == "tracestate" || strings.Contains(lk, "trace-id") {
			t.Fatalf("trace context must not be returned to client, got header %s", k)
		}
	}
	// 不向上游转发 tracestate 属阶段1 既定边界：本模块从不设置该头（断言请求侧未被改动）
	if r.Header.Get("tracestate") != "evil=should-be-ignored" {
		t.Fatal("guard must not touch tracestate")
	}
}

// trace_trust_external=true 且外部 traceparent 校验通过：续接 trace_id，span_id 重新生成。
func TestTraceTrustExternalContinue(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", TraceTrustExternal: true})
	r := req("203.0.113.66:1234", map[string]string{"traceparent": testExtTraceparent})
	if err := g.ServeHTTP(httptest.NewRecorder(), r, nextHandler{new(bool)}); err != nil {
		t.Fatal(err)
	}
	tc := traceContextFrom(r.Context())
	if tc.TraceID != testExtTraceID {
		t.Fatalf("trusted external trace id should be continued, got %q", tc.TraceID)
	}
	if !isLowerHexLen(tc.SpanID, 16) || tc.SpanID == testExtSpanID {
		t.Fatalf("span id must be regenerated, got %q", tc.SpanID)
	}
}

// trace_trust_external=true 但外部 traceparent 不合法：一律新建（不续接）。
func TestTraceTrustExternalInvalidHeaders(t *testing.T) {
	invalid := []string{
		"ff-" + testExtTraceID + "-" + testExtSpanID + "-01",                            // version=ff
		"00-00000000000000000000000000000000-" + testExtSpanID + "-01",                  // trace_id 全零
		"00-" + testExtTraceID + "-0000000000000000-01",                                 // span_id 全零
		strings.ToUpper(testExtTraceparent),                                             // 大写 hex
		"00-" + testExtTraceID + "-" + testExtSpanID,                                    // 段数不足
		"00-" + testExtTraceID + "-" + testExtSpanID + "-01-extra",                      // 段数过多
		"00-" + testExtTraceID + "-" + testExtSpanID + "-01" + strings.Repeat("a", 100), // 长度超限
		"not-a-traceparent", // 非法 hex
	}
	for _, h := range invalid {
		g := newTestGuard(t, Guard{AppID: "app1", TraceTrustExternal: true})
		r := req("203.0.113.66:1234", map[string]string{"traceparent": h})
		if err := g.ServeHTTP(httptest.NewRecorder(), r, nextHandler{new(bool)}); err != nil {
			t.Fatalf("%q: %v", h, err)
		}
		tc := traceContextFrom(r.Context())
		if !isLowerHexLen(tc.TraceID, 32) || !isLowerHexLen(tc.SpanID, 16) {
			t.Fatalf("%q: malformed generated ids: %+v", h, tc)
		}
		if tc.TraceID == testExtTraceID {
			t.Fatalf("%q: invalid external context must not be continued", h)
		}
	}
}

// 前置拦截分支同样携带 trace 上下文（黑名单 403 路径）。
func TestTraceAvailableOnFrontInterception(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID:      "app1",
		GlobalDeny: []ruleJSON{{ID: "d1", Address: "203.0.113.66", Priority: 1}},
	})
	r := req("203.0.113.66:1234", nil)
	err := g.ServeHTTP(httptest.NewRecorder(), r, nextHandler{new(bool)})
	if err == nil {
		t.Fatal("deny should block")
	}
	tc := traceContextFrom(r.Context())
	if !isLowerHexLen(tc.TraceID, 32) || !isLowerHexLen(tc.SpanID, 16) {
		t.Fatalf("trace context must exist on interception branch: %+v", tc)
	}
}

// 派生兜底：crypto/rand 正常路径不经过；直接验证 deriveTraceContext 产出形态与唯一性。
func TestDeriveTraceContextFallback(t *testing.T) {
	r1 := req("203.0.113.66:1234", nil)
	r2 := req("203.0.113.66:1234", nil)
	a := deriveTraceContext(r1)
	b := deriveTraceContext(r2)
	if !isLowerHexLen(a.TraceID, 32) || !isLowerHexLen(a.SpanID, 16) {
		t.Fatalf("fallback ids malformed: %+v", a)
	}
	if a.TraceID == b.TraceID || a.SpanID == b.SpanID {
		t.Fatal("fallback ids must be unique")
	}
}
