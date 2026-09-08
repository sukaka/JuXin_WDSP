package detectors

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// mcpTestParsed 构造 MCP JSON-RPC 请求解析产物（/mcp 路径已由分类器确认 jsonrpc 形态）。
func mcpTestParsed(method string, values map[string]string) *parser.Parsed {
	p := &parser.Parsed{
		Method: "POST", RawPath: "/mcp", ContentType: "application/json",
		IsJSON: true, BodySize: 200,
		JSONFields: map[string]string{"jsonrpc": "string"},
		JSONValues: map[string]string{"jsonrpc": "2.0"},
	}
	if method != "" {
		p.JSONFields["method"] = "string"
		p.JSONValues["method"] = method
	}
	for k, v := range values {
		p.JSONValues[k] = v
	}
	return p
}

// mcpTestValueRules 编译测试用值级敏感规则（手机号，json 位置）。
func mcpTestValueRules(t *testing.T) []CompiledSensitiveValueRule {
	t.Helper()
	rules, err := CompileSensitiveValueRules([]SensitiveValueRule{
		{DataType: "phone", Regex: `1[3-9]\d{9}`, Locations: []string{"json"}, Level: "SENSITIVE"},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	return rules
}

// mcpTestCtx 构造已带 LLM 观测的请求上下文（模拟 CheckLLM 已产出观测）。
func mcpTestCtx(id string) *dsctx.RequestContext {
	ctx := dsctx.New(id, dsctx.DefaultParseLimits())
	ctx.SetLLMObservation(&dsctx.LLMObservation{PromptPresent: true})
	return ctx
}

// TestCheckMCPKnownMethod 词表内方法：无明细、mcp_method 如实写入观测。
func TestCheckMCPKnownMethod(t *testing.T) {
	ctx := mcpTestCtx("mcp-1")
	CheckMCP(ctx, mcpTestParsed("tools/list", nil), mcpTestValueRules(t))
	if obs := ctx.GetLLMObservation(); obs == nil || obs.MCPMethod != "tools/list" {
		t.Fatalf("mcp_method not recorded: %+v", ctx.GetLLMObservation())
	}
	for _, m := range ctx.CopyMatches() {
		if strings.HasPrefix(m.RuleID, "llm.mcp_") {
			t.Fatalf("known method must not produce finding: %+v", m)
		}
	}
}

// TestCheckMCPUnknownMethod 词表外方法：llm.mcp_unknown_method OBSERVE/LOW，
// 证据含方法名；mcp_method 仍如实记录（观测口径）。
func TestCheckMCPUnknownMethod(t *testing.T) {
	ctx := mcpTestCtx("mcp-2")
	CheckMCP(ctx, mcpTestParsed("custom/execShell", nil), nil)
	if obs := ctx.GetLLMObservation(); obs == nil || obs.MCPMethod != "custom/execShell" {
		t.Fatalf("unknown method must still be recorded: %+v", ctx.GetLLMObservation())
	}
	ms := llmMatches(ctx, "llm.mcp_unknown_method")
	if len(ms) != 1 {
		t.Fatalf("matches=%d, all=%+v", len(ms), ctx.CopyMatches())
	}
	m := ms[0]
	if m.Category != "OBSERVE" || m.Severity != "LOW" {
		t.Fatalf("discipline broken: %s/%s", m.Category, m.Severity)
	}
	if m.Evidence["method"] != "custom/execShell" {
		t.Fatalf("evidence = %+v", m.Evidence)
	}
}

// TestCheckMCPResponseObject JSON-RPC 响应对象（无 method，含 result）：
// 非调用，不记录 mcp_method、不产明细（保守不判）。
func TestCheckMCPResponseObject(t *testing.T) {
	ctx := mcpTestCtx("mcp-3")
	p := mcpTestParsed("", nil)
	p.JSONFields["result"] = "object"
	CheckMCP(ctx, p, mcpTestValueRules(t))
	if obs := ctx.GetLLMObservation(); obs == nil || obs.MCPMethod != "" {
		t.Fatalf("response object must not record mcp_method: %+v", ctx.GetLLMObservation())
	}
	if len(ctx.CopyMatches()) != 0 {
		t.Fatalf("response object must not produce findings: %+v", ctx.CopyMatches())
	}
}

// TestCheckMCPSensitiveArg tools/call 参数值命中值级敏感规则：
// llm.mcp_sensitive_arg OBSERVE/MEDIUM，证据只含工具名/规则名——不落参数名与参数值。
func TestCheckMCPSensitiveArg(t *testing.T) {
	const secret = "13800138000"
	ctx := mcpTestCtx("mcp-4")
	p := mcpTestParsed("tools/call", map[string]string{
		"params.name":          "query_customer",
		"params.arguments.sql": "SELECT * FROM customers WHERE phone = '" + secret + "'",
		"params.arguments.top": "10",
	})
	CheckMCP(ctx, p, mcpTestValueRules(t))
	if obs := ctx.GetLLMObservation(); obs == nil || obs.MCPMethod != "tools/call" {
		t.Fatalf("mcp_method = %+v", ctx.GetLLMObservation())
	}
	ms := llmMatches(ctx, "llm.mcp_sensitive_arg")
	if len(ms) != 1 {
		t.Fatalf("matches=%d, all=%+v", len(ms), ctx.CopyMatches())
	}
	m := ms[0]
	if m.Category != "OBSERVE" || m.Severity != "MEDIUM" {
		t.Fatalf("discipline broken: %s/%s", m.Category, m.Severity)
	}
	if m.Evidence["tool"] != "query_customer" || m.Evidence["data_type"] != "phone" {
		t.Fatalf("evidence = %+v", m.Evidence)
	}
	// 不落值不落参数名：证据不得含参数值、参数路径；键集合仅 tool/data_type
	for k, v := range m.Evidence {
		if strings.Contains(v, secret) || strings.Contains(v, "sql") || strings.Contains(v, "params") {
			t.Fatalf("evidence leaks value/arg: %s=%s", k, v)
		}
		if k != "tool" && k != "data_type" {
			t.Fatalf("unexpected evidence key %q", k)
		}
	}
	// 未知方法命中（本例方法为词表内 tools/call，不应有）
	if n := len(llmMatches(ctx, "llm.mcp_unknown_method")); n != 0 {
		t.Fatalf("tools/call is known: %+v", ctx.CopyMatches())
	}
}

// TestCheckMCPSensitiveArgNoRules 值级规则未下发：参数值检测零行为，
// method 词表核对与 mcp_method 观测不受影响（识别与观测不依赖规则下发）。
func TestCheckMCPSensitiveArgNoRules(t *testing.T) {
	ctx := mcpTestCtx("mcp-5")
	p := mcpTestParsed("tools/call", map[string]string{
		"params.name":          "query_customer",
		"params.arguments.sql": "phone = '13800138000'",
	})
	CheckMCP(ctx, p, nil)
	if obs := ctx.GetLLMObservation(); obs == nil || obs.MCPMethod != "tools/call" {
		t.Fatalf("mcp_method = %+v", ctx.GetLLMObservation())
	}
	if len(ctx.CopyMatches()) != 0 {
		t.Fatalf("no rules must mean no findings: %+v", ctx.CopyMatches())
	}
}

// TestCheckMCPOtherMethodArgsNotScanned 非 tools/call 方法不做参数值检测
// （params.arguments 前缀外的留存值不参与；resources/read 形态不误判）。
func TestCheckMCPOtherMethodArgsNotScanned(t *testing.T) {
	ctx := mcpTestCtx("mcp-6")
	p := mcpTestParsed("resources/read", map[string]string{
		"params.uri": "file:///contacts/13800138000.txt",
	})
	CheckMCP(ctx, p, mcpTestValueRules(t))
	if n := len(llmMatches(ctx, "llm.mcp_sensitive_arg")); n != 0 {
		t.Fatalf("non-tools/call must not scan args: %+v", ctx.CopyMatches())
	}
}

// TestCheckMCPSensitiveArgCaps 命中明细上限 5 条（防事件膨胀）。
func TestCheckMCPSensitiveArgCaps(t *testing.T) {
	ctx := mcpTestCtx("mcp-7")
	values := map[string]string{"params.name": "bulk"}
	for _, k := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		values["params.arguments."+k] = "13800138000"
	}
	CheckMCP(ctx, mcpTestParsed("tools/call", values), mcpTestValueRules(t))
	if n := len(llmMatches(ctx, "llm.mcp_sensitive_arg")); n != maxMCPSensitiveArgMatches {
		t.Fatalf("matches = %d, want cap %d", n, maxMCPSensitiveArgMatches)
	}
}

// TestCheckMCPNilGuards 空输入防御：nil 上下文/解析产物/非 JSON 不 panic、零行为。
func TestCheckMCPNilGuards(t *testing.T) {
	CheckMCP(nil, mcpTestParsed("tools/list", nil), nil)
	ctx := mcpTestCtx("mcp-8")
	CheckMCP(ctx, nil, nil)
	p := mcpTestParsed("tools/list", nil)
	p.IsJSON = false
	CheckMCP(ctx, p, nil)
	if len(ctx.CopyMatches()) != 0 {
		t.Fatalf("non-JSON must be zero behavior: %+v", ctx.CopyMatches())
	}
}
