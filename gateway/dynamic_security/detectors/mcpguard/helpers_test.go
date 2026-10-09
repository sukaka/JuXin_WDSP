// helpers_test.go mcpguard 测试共享构造：目录/绑定/消息/上下文。
package mcpguard

import (
	"encoding/json"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser/mcprpc"
)

// testCatalog 测试目录（工具集覆盖检查链各分支）。
func testCatalog() *Catalog {
	mustSchema := func(raw string) *Schema { return CompileSchema(json.RawMessage(raw)) }
	return &Catalog{
		Name: "test-catalog", Hash: "mcp-catalog-sha256:v1:deadbeef",
		Tools: map[string]*Tool{
			"echo": {
				Name: "echo", Version: "1.0", Hash: "mcp-tool-sha256:v1:echo",
				RiskLevel: "LOW", DataClassification: "PUBLIC",
				InputSchema:  mustSchema(`{"type":"object","properties":{"text":{"type":"string"},"count":{"type":"integer"}},"required":["text"],"additionalProperties":false}`),
				OutputSchema: mustSchema(`{"type":"object","properties":{"result":{"type":"string"}},"additionalProperties":false}`),
			},
			"file_read": {
				Name: "file_read", Hash: "mcp-tool-sha256:v1:file_read", RiskLevel: "MEDIUM", DataClassification: "INTERNAL",
				ArgConstraints: []ArgConstraint{{Field: "path", Kind: ConstraintPathPrefix, Allow: []string{"/var/data/"}}},
			},
			"net_fetch": {
				Name: "net_fetch", Hash: "mcp-tool-sha256:v1:net_fetch", RiskLevel: "MEDIUM", DataClassification: "INTERNAL",
				ArgConstraints: []ArgConstraint{{Field: "url", Kind: ConstraintDomainSuffix, Allow: []string{"example.com"}}},
			},
			"limited": {
				Name: "limited", Hash: "mcp-tool-sha256:v1:limited-unique", RiskLevel: "LOW", DataClassification: "PUBLIC",
				MaxCallsPerMinute: 2,
			},
			"risky": {
				Name: "risky", Hash: "mcp-tool-sha256:v1:risky", RiskLevel: "HIGH", DataClassification: "CONFIDENTIAL",
			},
			"approval": {
				Name: "approval", Hash: "mcp-tool-sha256:v1:approval", RiskLevel: "LOW", ApprovalRequired: true, DataClassification: "PUBLIC",
			},
			"acl_tool": {
				Name: "acl_tool", Hash: "mcp-tool-sha256:v1:acl", RiskLevel: "LOW", DataClassification: "INTERNAL",
				AllowedPrincipals: []string{"user-1"}, AllowedRoles: []string{"admin"}, AllowedTenants: []string{"t-1"},
			},
			"noschema": {
				Name: "noschema", Hash: "mcp-tool-sha256:v1:noschema", RiskLevel: "LOW", DataClassification: "PUBLIC",
			},
			"degraded": {
				Name: "degraded", Hash: "mcp-tool-sha256:v1:degraded", RiskLevel: "LOW", DataClassification: "PUBLIC",
				InputSchema:          mustSchema(`{"type":"object","properties":{"id":{"type":"string","pattern":"^[a-z]+$"}}}`),
				InputDegraded:        true,
				InputUnsupportedKeys: []string{"pattern"},
			},
		},
	}
}

// scopedConfig 单端点作用域配置（resolved 承载——Evaluate 消费形态）。
func scopedConfig(catalog *Catalog, mode string) *Config {
	ep := &Endpoint{Catalog: catalog, Mode: mode}
	return &Config{resolved: ep}
}

// fullConfig 全量映射配置（ForEndpoint 测试）。
func fullConfig(catalog *Catalog, mode string) *Config {
	return &Config{Apps: map[string]map[string]Endpoint{
		"app-1": {"/mcp": {Catalog: catalog, Mode: mode}},
	}}
}

// callMsg 构造 tools/call 消息（经 mcprpc.ParseMessage 真实解析）。
func callMsg(t *testing.T, toolName string, arguments any) *mcprpc.Message {
	t.Helper()
	argsRaw, err := json.Marshal(arguments)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":` + jsonString(toolName) + `,"arguments":` + string(argsRaw) + `}}`)
	msg, err := mcprpc.ParseMessage(raw, mcprpc.DefaultBudgets())
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	return msg
}

func jsonString(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

// callMsgRaw 原文形态构造（重复键等非常规场景）。
func callMsgRaw(t *testing.T, raw string) *mcprpc.Message {
	t.Helper()
	msg, err := mcprpc.ParseMessage([]byte(raw), mcprpc.DefaultBudgets())
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	return msg
}

// otherMsg 构造非 tools/call 方法消息。
func otherMsg(t *testing.T, method string) *mcprpc.Message {
	t.Helper()
	return callMsgRaw(t, `{"jsonrpc":"2.0","id":1,"method":`+jsonString(method)+`}`)
}

func newTestCtx() *dsctx.RequestContext {
	return dsctx.New("req-mcp-1", dsctx.DefaultParseLimits())
}

func findMatch(ctx *dsctx.RequestContext, ruleID string) *dsctx.DetectorMatch {
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == ruleID {
			mm := m
			return &mm
		}
	}
	return nil
}

// covStatus 断言辅助。
func assertCov(t *testing.T, cov *coverage.Observation, status coverage.Status, reason coverage.ReasonCode) {
	t.Helper()
	if cov == nil {
		t.Fatalf("覆盖观测为 nil（应 %s/%s）", status, reason)
	}
	if cov.Status != status {
		t.Fatalf("覆盖状态 = %s，应 %s", cov.Status, status)
	}
	if reason != "" && cov.ReasonCode != reason {
		t.Fatalf("reason = %q，应 %q", cov.ReasonCode, reason)
	}
}

// ---------- rule_id 契约测试辅助 ----------

// budgetErrForTest 预算错误构造（ErrBudget 链）。
func budgetErrForTest() error {
	return &mcprpc.BudgetError{Rule: "depth_exceeded", Limit: 32, Actual: 33}
}

// shapeErrForTest 批处理形态错误（ErrShape 链）。
func shapeErrForTest() error { return mcprpc.ErrShape }

// jsonRawForTest JSON 原文构造。
func jsonRawForTest(s string) json.RawMessage { return json.RawMessage(s) }

// valueRulesForTest 值级敏感规则（合成 SECRET- 前缀词表——合成数据非真实秘密）。
func valueRulesForTest() []detectors.CompiledSensitiveValueRule {
	rules, err := detectors.CompileSensitiveValueRules([]detectors.SensitiveValueRule{
		{DataType: "test_secret", Regex: `SECRET-[0-9]{6}`, Locations: []string{"json"}},
	})
	if err != nil {
		panic(err)
	}
	return rules
}

// mcprpcMessage 测试别名（result 测试形参简写）。
type mcprpcMessage = mcprpc.Message
