package gatewayconfig

import (
	"testing"
)

// TestBuildGuardHandlerL7Rules l7_rules 段注入：非 nil 注入处理器配置，nil 保持零行为变化。
func TestBuildGuardHandlerL7Rules(t *testing.T) {
	g := testGuardConfig()
	app := AppData{AppID: "app-1", Code: "shop"}

	// nil：不出现 l7_rules 键（API 形态/历史版本一致）
	h := buildGuardHandler(g, app, 0)
	if _, ok := h["l7_rules"]; ok {
		t.Fatal("L7Rules 为 nil 时处理器配置不应出现 l7_rules")
	}

	// 非 nil：注入完整段（含空数组语义）
	g.L7Rules = &GuardL7Rules{Rules: []GuardL7Rule{{
		ID: "r1", Name: "规则", Priority: 100, Enabled: true,
		Conditions: []GuardL7Condition{{Type: "uri", Op: "prefix", Value: "/admin"}},
		Action:     "block",
		ActionConfig: GuardL7ActionConfig{
			Status: 403, RedirectStatus: 302, ContentType: "text/html; charset=utf-8",
		},
	}}}
	h = buildGuardHandler(g, app, 0)
	seg, ok := h["l7_rules"].(*GuardL7Rules)
	if !ok {
		t.Fatalf("处理器配置缺少 l7_rules 段: %v", h["l7_rules"])
	}
	if len(seg.Rules) != 1 || seg.Rules[0].ID != "r1" || seg.Rules[0].Action != "block" {
		t.Fatalf("l7_rules 段内容异常: %+v", seg)
	}
}
