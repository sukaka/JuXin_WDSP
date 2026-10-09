// result_test.go 结果检查矩阵（output_schema/值级敏感/CONFIDENTIAL 升级/
// 双闸 blocked/UNKNOWN 放行/result 成员提取）。
package mcpguard

import (
	"encoding/json"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// TestResultSchemaViolation output_schema 校验（双闸 blocked / OBSERVE 拟动作）。
func TestResultSchemaViolation(t *testing.T) {
	msg := callMsg(t, "echo", map[string]any{"text": "x"})
	// echo output_schema：{type object, properties{result:string}, additionalProperties:false}
	t.Run("双闸 blocked", func(t *testing.T) {
		ctx := newTestCtx()
		blocked := EvaluateResult(ctx, msg, json.RawMessage(`{"result":123}`), scopedConfig(testCatalog(), ModeProtect), nil, true)
		if !blocked {
			t.Fatal("双闸应 blocked")
		}
		m := findMatch(ctx, "mcp.result_schema_violation")
		if m == nil || m.Category != "BLOCK" || m.Evidence["rule"] != "type_mismatch" ||
			m.Evidence["mcp_error_code"] != "-32014" || m.Evidence["mcp_http_status"] != "403" {
			t.Fatalf("违规 = %+v", m)
		}
	})
	t.Run("OBSERVE 拟动作不 blocked", func(t *testing.T) {
		ctx := newTestCtx()
		blocked := EvaluateResult(ctx, msg, json.RawMessage(`{"result":123}`), scopedConfig(testCatalog(), ModeProtect), nil, false)
		if blocked {
			t.Fatal("引擎 OBSERVE 不 blocked")
		}
		if m := findMatch(ctx, "mcp.result_schema_violation"); m == nil || m.Category != "OBSERVE" {
			t.Fatalf("拟动作 = %+v", m)
		}
	})
	t.Run("合法结果通过", func(t *testing.T) {
		ctx := newTestCtx()
		if blocked := EvaluateResult(ctx, msg, json.RawMessage(`{"result":"ok"}`), scopedConfig(testCatalog(), ModeProtect), nil, true); blocked {
			t.Fatal("合法结果不应 blocked")
		}
		if findMatch(ctx, "mcp.result_schema_violation") != nil {
			t.Fatal("合法结果不产违规")
		}
	})
	t.Run("结果含未知字段违规", func(t *testing.T) {
		ctx := newTestCtx()
		blocked := EvaluateResult(ctx, msg, json.RawMessage(`{"result":"ok","extra":1}`), scopedConfig(testCatalog(), ModeProtect), nil, true)
		if !blocked {
			t.Fatal("未知字段应 blocked")
		}
		if m := findMatch(ctx, "mcp.result_schema_violation"); m.Evidence["rule"] != "unknown_field" {
			t.Fatalf("rule = %+v", m.Evidence)
		}
	})
}

// TestResultSensitiveValue 值级敏感规则遍历（证据不落值；CONFIDENTIAL 升级）。
func TestResultSensitiveValue(t *testing.T) {
	t.Run("命中证据不落值", func(t *testing.T) {
		msg := callMsg(t, "echo", map[string]any{"text": "x"})
		ctx := newTestCtx()
		blocked := EvaluateResult(ctx, msg, json.RawMessage(`{"result":"key=SECRET-123456"}`), scopedConfig(testCatalog(), ModeProtect), valueRulesForTest(), true)
		if !blocked {
			t.Fatal("敏感命中双闸应 blocked")
		}
		m := findMatch(ctx, "mcp.result_sensitive_value")
		if m == nil || m.Evidence["data_type"] != "test_secret" || m.Evidence["path"] != "result" ||
			m.Evidence["value_len"] == "" {
			t.Fatalf("证据 = %+v", m)
		}
		for k, v := range m.Evidence {
			if k != "value_fp" && len(v) > 0 && containsSecret(v) {
				t.Fatalf("证据落原值（红线）: %s=%s", k, v)
			}
		}
	})
	t.Run("CONFIDENTIAL severity MEDIUM→HIGH", func(t *testing.T) {
		msg := callMsg(t, "risky", map[string]any{})
		ctx := newTestCtx()
		EvaluateResult(ctx, msg, json.RawMessage(`{"secret":"SECRET-123456"}`), scopedConfig(testCatalog(), ModeObserve), valueRulesForTest(), false)
		m := findMatch(ctx, "mcp.result_sensitive_value")
		if m == nil || m.Severity != "HIGH" || m.Evidence["data_classification"] != "CONFIDENTIAL" {
			t.Fatalf("CONFIDENTIAL 升级 = %+v", m)
		}
		if m.Category != "OBSERVE" {
			t.Fatal("定级不升动作（OBSERVE 绑定仍 OBSERVE）")
		}
	})
	t.Run("PUBLIC 不升级", func(t *testing.T) {
		msg := callMsg(t, "echo", map[string]any{"text": "x"})
		ctx := newTestCtx()
		EvaluateResult(ctx, msg, json.RawMessage(`{"result":"SECRET-123456"}`), scopedConfig(testCatalog(), ModeObserve), valueRulesForTest(), false)
		if m := findMatch(ctx, "mcp.result_sensitive_value"); m == nil || m.Severity != "MEDIUM" {
			t.Fatalf("PUBLIC 不升级 = %+v", m)
		}
	})
	t.Run("嵌套路径命中", func(t *testing.T) {
		msg := callMsg(t, "echo", map[string]any{"text": "x"})
		ctx := newTestCtx()
		EvaluateResult(ctx, msg, json.RawMessage(`{"result":{"items":[{"token":"SECRET-123456"}]}}`), scopedConfig(testCatalog(), ModeObserve), valueRulesForTest(), false)
		m := findMatch(ctx, "mcp.result_sensitive_value")
		if m == nil || m.Evidence["path"] != "result.items[0].token" {
			t.Fatalf("嵌套路径 = %+v", m)
		}
	})
	t.Run("未命中零行为", func(t *testing.T) {
		msg := callMsg(t, "echo", map[string]any{"text": "x"})
		ctx := newTestCtx()
		EvaluateResult(ctx, msg, json.RawMessage(`{"result":"clean"}`), scopedConfig(testCatalog(), ModeProtect), valueRulesForTest(), true)
		if findMatch(ctx, "mcp.result_sensitive_value") != nil {
			t.Fatal("未命中零行为")
		}
	})
}

// TestResultUnknownPass UNKNOWN 放行（不可解析/缺席/不在册——恒不阻断）。
func TestResultUnknownPass(t *testing.T) {
	msg := callMsg(t, "echo", map[string]any{"text": "x"})
	cases := []struct {
		name   string
		msg    *mcprpcMessage
		result json.RawMessage
		cfg    *Config
	}{
		{"结果非法 JSON", msg, json.RawMessage(`{`), scopedConfig(testCatalog(), ModeProtect)},
		{"目录缺席", msg, json.RawMessage(`{"result":1}`), scopedConfig(nil, ModeProtect)},
		{"工具不在册", callMsg(t, "ghost", map[string]any{}), json.RawMessage(`{"result":1}`), scopedConfig(testCatalog(), ModeProtect)},
	}
	for _, tc := range cases {
		ctx := newTestCtx()
		if blocked := EvaluateResult(ctx, tc.msg, tc.result, tc.cfg, valueRulesForTest(), true); blocked {
			t.Errorf("%s: 应放行", tc.name)
		}
		for _, m := range ctx.CopyMatches() {
			if m.Category == "BLOCK" {
				t.Errorf("%s: 恒不阻断", tc.name)
			}
		}
	}
}

// TestExtractResultMember result 成员提取两形态。
func TestExtractResultMember(t *testing.T) {
	// any 形态
	raw, ok := ExtractResultMember(map[string]any{"jsonrpc": "2.0", "id": float64(7), "result": map[string]any{"x": "y"}})
	if !ok || string(raw) != `{"x":"y"}` {
		t.Fatalf("any 形态 = %s %v", raw, ok)
	}
	if _, ok := ExtractResultMember(map[string]any{"error": map[string]any{"code": -32600}}); ok {
		t.Fatal("错误对象无 result 不冒充工具结果")
	}
	if _, ok := ExtractResultMember("scalar"); ok {
		t.Fatal("非对象不提取")
	}
	// 原文形态（SSE data）
	raw2, ok2 := ExtractResultMemberRaw([]byte(`{"jsonrpc":"2.0","id":7,"result":{"x":1}}`))
	if !ok2 || string(raw2) != `{"x":1}` {
		t.Fatalf("原文形态 = %s %v", raw2, ok2)
	}
	if _, ok := ExtractResultMemberRaw([]byte(`{"jsonrpc":"2.0","id":7,"error":{"code":-32600}}`)); ok {
		t.Fatal("错误对象不提取")
	}
	if _, ok := ExtractResultMemberRaw([]byte(`not json`)); ok {
		t.Fatal("非法 JSON 不提取")
	}
	// IsSSEContentType
	for ct, want := range map[string]bool{
		"text/event-stream": true, "Text/Event-Stream; charset=utf-8": true,
		"application/json": false, "application/grpc": false,
	} {
		if IsSSEContentType(ct) != want {
			t.Errorf("%s: %v", ct, IsSSEContentType(ct))
		}
	}
}

func containsSecret(v string) bool {
	return len(v) >= 12 && v == "SECRET-123456" || (len(v) > 6 && v[:6] == "SECRET")
}

var _ = detectors.CompiledSensitiveValueRule{}
var _ = json.RawMessage{}
var _ = dsctx.RequestContext{}
