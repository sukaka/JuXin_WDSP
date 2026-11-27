package aiagents

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aiorchestrator"
	"github.com/jiuzhang-waf/server/internal/aitools"
)

func makeWS4TestInput(task aiorchestrator.TaskType, results map[string]interface{}) *aiorchestrator.AnalyzeInput {
	tools := make([]*fakeAPITool, 0, len(results))
	for code, res := range results {
		tools = append(tools, &fakeAPITool{code: code, res: res})
	}
	reg := newAPIAgentRegistry(tools...)
	return &aiorchestrator.AnalyzeInput{
		TaskID:    uuid.New(),
		TaskType:  task,
		Principal: &aitools.Principal{UserID: uuid.New(), Username: "tester"},
		ToolCtx:   &aiorchestrator.ToolContext{Registry: reg},
		Evidence:  aiorchestrator.NewEvidenceSet(),
	}
}

// TestWafPolicyRecommendShortSlicesAndMissingBoolNoPanic 验证：
// 1) policy.get 返回 1 条或 2 条策略时不会触发 items[:3] 越界 panic；
// 2) is_builtin 字段缺失或非 bool 时不 panic；
// 3) 统计/例外工具返回非预期结构时不 panic。
func TestWafPolicyRecommendShortSlicesAndMissingBoolNoPanic(t *testing.T) {
	agent := NewWafPolicyAgent(nil)
	for _, count := range []int{1, 2} {
		items := make([]map[string]interface{}, 0, count)
		for i := 0; i < count; i++ {
			items = append(items, map[string]interface{}{
				"name":               "默认策略",
				"protection_mode":    "PROTECT",
				"paranoia_level":     1,
				"inbound_threshold":  5,
				"outbound_threshold": 4,
				// 故意省略 is_builtin 验证安全断言
			})
		}
		in := makeWS4TestInput(aiorchestrator.TaskPolicyRec, map[string]interface{}{
			"policy.get":                map[string]interface{}{"items": items},
			"security_event.statistics": map[string]interface{}{"items": "malformed"},
			"statistics.top_rules":      "unexpected-string",
		})
		res, err := agent.Analyze(context.Background(), in)
		if err != nil {
			t.Fatalf("count=%d Analyze error: %v", count, err)
		}
		if res == nil || !strings.Contains(res.FactsText, "默认策略") {
			t.Fatalf("count=%d unexpected output: %+v", count, res)
		}
	}
}

// TestWafPolicyFalsePositiveShortEventIDAndMalformedToolsNoPanic 验证短事件 ID（<8字符）
// 与非预期工具返回值均不触发切片越界或类型断言 panic。
func TestWafPolicyFalsePositiveShortEventIDAndMalformedToolsNoPanic(t *testing.T) {
	agent := NewWafPolicyAgent(nil)
	in := makeWS4TestInput(aiorchestrator.TaskFalsePositive, map[string]interface{}{
		"security_event.get": map[string]interface{}{
			"method":      "GET",
			"domain":      "example.com",
			"path":        "/login",
			"attack_type": "SQL_INJECTION",
			"matches":     []interface{}{map[string]interface{}{"rule_id": float64(942100)}},
		},
		"rule.get":         nil,
		"exception.search": map[string]interface{}{"items": nil},
	})
	in.EventIDs = []string{"ev1"}
	res, err := agent.Analyze(context.Background(), in)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res == nil || !strings.Contains(res.FactsText, "事件 ev1") || !strings.Contains(res.FactsText, "942100") {
		t.Fatalf("unexpected facts: %+v", res)
	}
}

// TestMiscAndEventAgentsMalformedToolOutputsNoPanic 验证各 Agent 在工具返回 nil/异常类型时均不 panic。
func TestMiscAndEventAgentsMalformedToolOutputsNoPanic(t *testing.T) {
	malformed := map[string]interface{}{
		"request_trace.get":            map[string]interface{}{"waf_events": "bad", "access_control_events": nil},
		"access_control_log.search":    map[string]interface{}{"total": 1, "items": nil},
		"audit_log.search":             "not-a-map",
		"application.search":           map[string]interface{}{"total": 1, "items": []interface{}{map[string]interface{}{"name": "app1"}}},
		"certificate.get_metadata":     nil,
		"gateway.get_status":           "not-a-map",
		"statistics.runtime":           map[string]interface{}{"components": "bad"},
		"system_log.search":            map[string]interface{}{"items": nil},
		"security_event.statistics":    map[string]interface{}{"items": nil},
		"statistics.top_source_ips":    map[string]interface{}{"items": nil},
		"statistics.security_overview": nil,
	}

	logIn := makeWS4TestInput(aiorchestrator.TaskLogQuery, malformed)
	logIn.EventIDs = []string{"req-1"}
	if _, err := NewLogAnalysisAgent(nil).Analyze(context.Background(), logIn); err != nil {
		t.Fatalf("LogAnalysisAgent: %v", err)
	}
	if _, err := NewAssetAgent(nil).Analyze(context.Background(), makeWS4TestInput(aiorchestrator.TaskGeneralQA, malformed)); err != nil {
		t.Fatalf("AssetAgent: %v", err)
	}
	if _, err := NewOpsDiagnosticAgent(nil).Analyze(context.Background(), makeWS4TestInput(aiorchestrator.TaskGeneralQA, malformed)); err != nil {
		t.Fatalf("OpsDiagnosticAgent: %v", err)
	}
	if _, err := NewSecurityEventAgent(nil).Analyze(context.Background(), makeWS4TestInput(aiorchestrator.TaskEventAnalysis, malformed)); err != nil {
		t.Fatalf("SecurityEventAgent: %v", err)
	}
}
