// agents_tools_handler_test.go 动态 Agent 目录合并测试（AI 能力增强第一波）：
// 静态目录保持不变；动态 Agent（api_security 等形态相关）经 SyncRegistry extraAgents 追加；
// 纯 WAF 形态（无 extras）目录不含 api_security。
package aihandlers

import "testing"

// TestMergeAgentCatalogPureWAF 无动态追加时目录等于静态 AgentCatalog（纯 WAF 形态不出现 api_security）。
func TestMergeAgentCatalogPureWAF(t *testing.T) {
	merged := mergeAgentCatalog(nil)
	if len(merged) != len(AgentCatalog) {
		t.Fatalf("mergeAgentCatalog(nil) 长度 = %d, want %d", len(merged), len(AgentCatalog))
	}
	for i, a := range AgentCatalog {
		if merged[i] != a {
			t.Errorf("merged[%d] = %+v, want %+v", i, merged[i], a)
		}
	}
	for _, a := range merged {
		if a.Code == "api_security" {
			t.Fatal("纯 WAF 形态目录不得出现 api_security")
		}
	}
}

// TestMergeAgentCatalogDynamicAppend 动态 Agent 追加在静态目录之后，可同步进 ai_agents。
func TestMergeAgentCatalogDynamicAppend(t *testing.T) {
	extra := AgentMeta{Code: "api_security", Name: "API 安全分析 Agent", Description: "API 域只读分析"}
	merged := mergeAgentCatalog([]AgentMeta{extra})
	if len(merged) != len(AgentCatalog)+1 {
		t.Fatalf("合并后长度 = %d, want %d", len(merged), len(AgentCatalog)+1)
	}
	last := merged[len(merged)-1]
	if last != extra {
		t.Errorf("动态 Agent 应追加在尾部, got %+v", last)
	}
}

// TestMergeAgentCatalogDedup 同 code 动态条目覆盖静态描述而非重复；空 code 跳过。
func TestMergeAgentCatalogDedup(t *testing.T) {
	override := AgentMeta{Code: "knowledge", Name: "知识库 Agent（覆盖）", Description: "d"}
	merged := mergeAgentCatalog([]AgentMeta{override, {Code: ""}, {Code: "api_security", Name: "API 安全分析 Agent"}})
	if len(merged) != len(AgentCatalog)+1 {
		t.Fatalf("合并后长度 = %d, want %d（同 code 去重、空 code 跳过）", len(merged), len(AgentCatalog)+1)
	}
	var knowledge *AgentMeta
	for i := range merged {
		if merged[i].Code == "knowledge" {
			knowledge = &merged[i]
		}
	}
	if knowledge == nil || knowledge.Name != override.Name {
		t.Errorf("同 code 动态条目应覆盖静态目录, got %+v", knowledge)
	}
}
