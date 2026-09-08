package pipeline

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// TestProcessMCPEndToEnd MCP 内容级全链路（W12-GW / P2-04 续，任务书 §154）：
// /mcp JSON-RPC 识别 + mcp_method 观测扩展 + tools/call 参数值敏感检测 +
// 词表外方法信号；证据不落参数值。
func TestProcessMCPEndToEnd(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_customer","arguments":{"sql":"phone = '13800138000'"}}}`
	r, _ := http.NewRequest(http.MethodPost, "http://h/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Request-Id", "mcp-pipe-1")
	res, err := Process(r, Config{
		Enabled: true, Mode: "OBSERVE",
		SensitiveValueRules: []detectors.SensitiveValueRule{
			{DataType: "phone", Regex: `1[3-9]\d{9}`, Locations: []string{"json"}, Level: "SENSITIVE"},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obs := res.Context.GetLLMObservation()
	if obs == nil || obs.MCPMethod != "tools/call" {
		t.Fatalf("mcp_method = %+v", obs)
	}
	var sensitiveArg bool
	for _, m := range res.Context.CopyMatches() {
		if m.RuleID == "llm.mcp_sensitive_arg" {
			sensitiveArg = true
			if m.Evidence["tool"] != "query_customer" || m.Evidence["data_type"] != "phone" {
				t.Fatalf("evidence = %+v", m.Evidence)
			}
			for k, v := range m.Evidence {
				if strings.Contains(v, "13800138000") || strings.Contains(v, "sql") {
					t.Fatalf("evidence leaks value/arg: %s=%s", k, v)
				}
			}
		}
	}
	if !sensitiveArg {
		t.Fatalf("llm.mcp_sensitive_arg missing: %+v", res.Context.CopyMatches())
	}
}

// TestProcessMCPUnknownMethod 词表外方法：llm.mcp_unknown_method OBSERVE/LOW，
// mcp_method 如实记录（观测口径）。
func TestProcessMCPUnknownMethod(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":7,"method":"custom/doEverything","params":{}}`
	r, _ := http.NewRequest(http.MethodPost, "http://h/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	res, err := Process(r, Config{Enabled: true, Mode: "OBSERVE"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obs := res.Context.GetLLMObservation()
	if obs == nil || obs.MCPMethod != "custom/doEverything" {
		t.Fatalf("mcp_method = %+v", obs)
	}
	var found bool
	for _, m := range res.Context.CopyMatches() {
		if m.RuleID == "llm.mcp_unknown_method" {
			found = true
			if m.Category != "OBSERVE" || m.Severity != "LOW" || m.Evidence["method"] != "custom/doEverything" {
				t.Fatalf("bad unknown method match: %+v", m)
			}
		}
	}
	if !found {
		t.Fatalf("llm.mcp_unknown_method missing: %+v", res.Context.CopyMatches())
	}
}

// TestProcessMCPNoRulesZeroBehavior 值级规则未下发：MCP 识别与 mcp_method 观测不受影响，
// 参数值检测零行为（识别与观测不依赖规则下发）。
func TestProcessMCPNoRulesZeroBehavior(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query","arguments":{"sql":"phone = '13800138000'"}}}`
	r, _ := http.NewRequest(http.MethodPost, "http://h/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	res, err := Process(r, Config{Enabled: true, Mode: "OBSERVE"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obs := res.Context.GetLLMObservation()
	if obs == nil || obs.MCPMethod != "tools/call" {
		t.Fatalf("mcp_method = %+v", obs)
	}
	for _, m := range res.Context.CopyMatches() {
		if m.RuleID == "llm.mcp_sensitive_arg" || m.RuleID == "llm.mcp_unknown_method" {
			t.Fatalf("no rules must mean no mcp findings: %+v", m)
		}
	}
}
