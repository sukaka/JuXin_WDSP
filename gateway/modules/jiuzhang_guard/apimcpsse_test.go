// apimcpsse_test.go MCP SSE 逐消息结果检查端到端（§1.7/NG-T-M04 断言形态）：
// 首条正常已转发（客户端实收）、次条敏感不外发+断连+事件 disclosed_bytes/
// messages_forwarded 与实际一致（不冒充撤回，不报告整个调用通过）；
// keepalive 透传、非 SSE 透传零行为、OBSERVE 放行记录。
package jiuzhang_guard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

// newMCPGuardWithValueRules 构造带值级敏感规则的 MCP Guard。
func newMCPGuardWithValueRules(t *testing.T, mode string) (*Guard, string) {
	t.Helper()
	section := testMCPCatalogSection(t)
	g, logPath := newMCPGuard(t, mode, section, []mcpBindingJSON{
		{ApplicationID: "app-1", EndpointPath: "/mcp", CatalogName: "test-catalog", Mode: mode},
	})
	g.APISensitiveValueRules = []detectors.SensitiveValueRule{
		{DataType: "test_secret", Regex: `SECRET-[0-9]{6}`, Locations: []string{"json"}},
	}
	return g, logPath
}

const (
	sseFirstOK   = "data: {\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{\"ok\":true}}\n\n"
	sseSecondBad = "data: {\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{\"secret\":\"SECRET-123456\"}}\n\n"
	sseThird     = "data: {\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{\"never\":true}}\n\n"
)

// TestMCPSSEMidstreamBlockE2E PROTECT：首条已转发、次条敏感不外发、
// disclosed_bytes/messages_forwarded 与实际一致。
func TestMCPSSEMidstreamBlockE2E(t *testing.T) {
	g, logPath := newMCPGuardWithValueRules(t, "PROTECT")
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		// 真实反代语义：写错误向上传播（上游读取中止）
		if _, err := w.Write([]byte(sseFirstOK + sseSecondBad + sseThird)); err != nil {
			return err
		}
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpCallBody("echo", map[string]any{"text": "hi"})))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-mcp-sse-1")
	verified := jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-1"}
	*req = *req.WithContext(context.WithValue(req.Context(), jwtResultKey{}, verified))
	rec := httptest.NewRecorder()
	err := g.serveNext(rec, req, next)
	if err == nil {
		t.Fatal("中途阻断应传播错误（连接关闭语义）")
	}
	// 首条已实收（不冒充撤回）；次条/第三条不外发
	body := rec.Body.String()
	if !strings.Contains(body, sseFirstOK) {
		t.Fatalf("首条应实收: %q", body)
	}
	if strings.Contains(body, "SECRET-123456") || strings.Contains(body, sseThird) {
		t.Fatalf("次条/第三条不得外发: %q", body)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("事件数 = %d", len(recs))
	}
	var midstream map[string]string
	for _, m := range recs[0].Details {
		if m.RuleID == "mcp.result_blocked_midstream" {
			midstream = m.Evidence
		}
	}
	if midstream == nil {
		t.Fatalf("缺 mcp.result_blocked_midstream: %+v", recs[0].Details)
	}
	// 读数与实际一致：恰好放行 1 条、外发字节恰为首条长度
	if midstream["messages_forwarded"] != "1" {
		t.Fatalf("messages_forwarded = %q，应 1", midstream["messages_forwarded"])
	}
	if midstream["disclosed_bytes"] != strconv.Itoa(len(sseFirstOK)) {
		t.Fatalf("disclosed_bytes = %q，应 %d", midstream["disclosed_bytes"], len(sseFirstOK))
	}
	// 不报告「整个调用通过」：final_action 不得为干净 ALLOW 且无 FULL 语义伪造
	if recs[0].FinalAction == "ALLOW" {
		t.Fatal("中途阻断不得报告通过")
	}
}

// TestMCPSSEObservePassThroughE2E OBSERVE：敏感命中只记录放行（全流到达）。
func TestMCPSSEObservePassThroughE2E(t *testing.T) {
	g, logPath := newMCPGuardWithValueRules(t, "OBSERVE")
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sseFirstOK + sseSecondBad))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpCallBody("echo", map[string]any{"text": "hi"})))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-mcp-sse-2")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("OBSERVE 应放行: %v", err)
	}
	body := rec.Body.String()
	if !strings.Contains(body, sseFirstOK) || !strings.Contains(body, sseSecondBad) {
		t.Fatalf("OBSERVE 全流应到达: %q", body)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("事件数 = %d", len(recs))
	}
	var sensitive bool
	for _, m := range recs[0].Details {
		if m.RuleID == "mcp.result_sensitive_value" && m.Category == "OBSERVE" {
			sensitive = true
		}
		if m.RuleID == "mcp.result_blocked_midstream" {
			t.Fatal("OBSERVE 不产中途阻断")
		}
	}
	if !sensitive {
		t.Fatalf("OBSERVE 敏感命中未记录: %+v", recs[0].Details)
	}
}

// TestMCPSSEKeepaliveAndNonSSEForms keepalive 注释透传、非 JSON-RPC 事件放行、
// 非 SSE 响应透传零行为。
func TestMCPSSEKeepaliveAndNonSSEForms(t *testing.T) {
	keepalive := ": heartbeat\n\n"
	nonJSONRPC := "data: not-a-jsonrpc\n\n"
	g, _ := newMCPGuardWithValueRules(t, "PROTECT")
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(keepalive + nonJSONRPC + sseFirstOK))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpCallBody("echo", map[string]any{"text": "hi"})))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-mcp-sse-3")
	verified := jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-1"}
	*req = *req.WithContext(context.WithValue(req.Context(), jwtResultKey{}, verified))
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("keepalive/非 JSON-RPC 应放行: %v", err)
	}
	body := rec.Body.String()
	if !strings.Contains(body, keepalive) {
		t.Fatalf("keepalive 应原样透传: %q", body)
	}
	if !strings.Contains(body, nonJSONRPC) {
		t.Fatalf("非 JSON-RPC 形态事件应单条放行（UNKNOWN 不阻断）: %q", body)
	}

	// 非 SSE 响应（application/json）：透传零行为（非流式结果检查在响应相位）
	next2 := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":42,"result":{"ok":true}}`))
		return nil
	})
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpCallBody("echo", map[string]any{"text": "hi"})))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Request-Id", "req-mcp-sse-4")
	*req2 = *req2.WithContext(context.WithValue(req2.Context(), jwtResultKey{}, verified))
	if err := g.serveNext(rec2, req2, next2); err != nil {
		t.Fatalf("非 SSE 应放行: %v", err)
	}
	if !strings.Contains(rec2.Body.String(), `"ok":true`) {
		t.Fatalf("非 SSE 响应透传: %q", rec2.Body.String())
	}
}

// TestMCPSSEMidstreamBlockRPShape PROTECT+反代恐慌形态（批次 C 联调修正锚定）：
// 反代对中途写错误 panic(http.ErrAbortHandler)（reverseproxy.go:1283）——
// proxyWithMCPSSEGuard 折算为普通错误返回：事件照常持久化（含
// disclosed_bytes/messages_forwarded）、首条已 flush 实收、非本哨兵恐慌再抛。
func TestMCPSSEMidstreamBlockRPShape(t *testing.T) {
	g, logPath := newMCPGuardWithValueRules(t, "PROTECT")
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		// 真实反代语义：写错误向上传播后 panic(http.ErrAbortHandler)
		if _, err := w.Write([]byte(sseFirstOK + sseSecondBad + sseThird)); err != nil {
			panic(http.ErrAbortHandler)
		}
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpCallBody("echo", map[string]any{"text": "hi"})))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-mcp-sse-rp-1")
	verified := jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-1"}
	*req = *req.WithContext(context.WithValue(req.Context(), jwtResultKey{}, verified))
	rec := httptest.NewRecorder()
	err := g.serveNext(rec, req, next)
	if err == nil {
		t.Fatal("中途阻断应传播错误（连接关闭语义）")
	}
	// 首条已实收（flush 后不依赖缓冲收束）；次条/第三条不外发
	body := rec.Body.String()
	if !strings.Contains(body, sseFirstOK) {
		t.Fatalf("首条应实收: %q", body)
	}
	if !rec.Flushed {
		t.Fatal("首条外发应即时 flush（disclosed_bytes 诚实性）")
	}
	if strings.Contains(body, "SECRET-123456") || strings.Contains(body, sseThird) {
		t.Fatalf("次条/第三条不得外发: %q", body)
	}
	// 事件随请求持久化（反代恐慌不再吞事件）
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("事件数 = %d（反代恐慌路径事件丢失回退）", len(recs))
	}
	var midstream map[string]string
	for _, m := range recs[0].Details {
		if m.RuleID == "mcp.result_blocked_midstream" {
			midstream = m.Evidence
		}
	}
	if midstream == nil {
		t.Fatalf("缺 mcp.result_blocked_midstream: %+v", recs[0].Details)
	}
	if midstream["messages_forwarded"] != "1" {
		t.Fatalf("messages_forwarded = %q，应 1", midstream["messages_forwarded"])
	}
	if midstream["disclosed_bytes"] != strconv.Itoa(len(sseFirstOK)) {
		t.Fatalf("disclosed_bytes = %q，应 %d", midstream["disclosed_bytes"], len(sseFirstOK))
	}
	if recs[0].FinalAction != "BLOCK" {
		t.Fatalf("中途阻断 final_action 应按实修正 BLOCK（不得报告通过）: %q", recs[0].FinalAction)
	}
}

// TestMCSSEForeignAbortHandlerRethrown 非本哨兵的 ErrAbortHandler 原样再抛
// （存量语义不变——客户端断连等其他中止不吞不改写）。
func TestMCSSEForeignAbortHandlerRethrown(t *testing.T) {
	g, _ := newMCPGuardWithValueRules(t, "PROTECT")
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		panic(http.ErrAbortHandler) // 非 mcpSSE 哨兵的恐慌（如客户端断连）
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpCallBody("echo", map[string]any{"text": "hi"})))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-mcp-sse-rp-2")
	verified := jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-1"}
	*req = *req.WithContext(context.WithValue(req.Context(), jwtResultKey{}, verified))
	rec := httptest.NewRecorder()
	defer func() {
		if recover() != http.ErrAbortHandler {
			t.Fatal("非本哨兵恐慌应原样再抛")
		}
	}()
	_ = g.serveNext(rec, req, next)
}
