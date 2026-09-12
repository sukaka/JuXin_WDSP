package ruleoverrides

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestValidateInput(t *testing.T) {
	app := uuid.New()
	o := &Override{RuleID: 942100, ScopeType: ScopeApplication, ScopeID: &app, Action: ActionDisable}
	if err := ValidateInput(o); err != nil {
		t.Fatal(err)
	}
	o2 := &Override{RuleID: 942100, ScopeType: ScopeGlobal, Action: ActionDisable}
	if err := ValidateInput(o2); err != nil {
		t.Fatal(err)
	}
	if o2.ScopeID != nil {
		t.Fatal("global should clear scope_id")
	}
	bad := &Override{RuleID: 0, ScopeType: ScopeGlobal, Action: ActionDisable}
	if err := ValidateInput(bad); err == nil {
		t.Fatal("expected error")
	}
	pol := &Override{RuleID: 1, ScopeType: ScopePolicy, Action: ActionDisable}
	if err := ValidateInput(pol); err == nil {
		t.Fatal("policy without scope_id should fail")
	}
}

func TestResolveDisableRuleIDsPriority(t *testing.T) {
	appID := uuid.New()
	polID := uuid.New()
	otherApp := uuid.New()
	all := []Override{
		{RuleID: 100, ScopeType: ScopeGlobal, Action: ActionDisable},
		{RuleID: 100, ScopeType: ScopePolicy, ScopeID: &polID, Action: ActionEnable}, // 策略层启用覆盖全局禁用
		{RuleID: 200, ScopeType: ScopeGlobal, Action: ActionDisable},
		{RuleID: 200, ScopeType: ScopeApplication, ScopeID: &appID, Action: ActionEnable},
		{RuleID: 300, ScopeType: ScopeApplication, ScopeID: &otherApp, Action: ActionDisable}, // 其他应用
		{RuleID: 400, ScopeType: ScopePolicy, ScopeID: &polID, Action: ActionDisable},
	}
	ids := ResolveDisableRuleIDs(all, appID, &polID)
	// 100: ENABLE at policy → not disabled
	// 200: ENABLE at app → not disabled
	// 300: other app → ignore
	// 400: policy DISABLE → disabled
	if len(ids) != 1 || ids[0] != 400 {
		t.Fatalf("got %v want [400]", ids)
	}
	// 无策略时全局 100、200 均 DISABLE
	ids2 := ResolveDisableRuleIDs(all, appID, nil)
	// 100 global disable, 200 app enable wins, 400 policy ignored without policy
	if len(ids2) != 1 || ids2[0] != 100 {
		t.Fatalf("got %v want [100]", ids2)
	}
}

func TestBuildDisableSecLang(t *testing.T) {
	lines := BuildDisableSecLang([]int{942100, 941100})
	if len(lines) != 2 {
		t.Fatalf("len=%d", len(lines))
	}
	if !strings.Contains(lines[0], "ctl:ruleRemoveById=942100") {
		t.Fatal(lines[0])
	}
	if !strings.Contains(lines[0], "id:7200001") {
		t.Fatal("expected base id", lines[0])
	}
	if !strings.Contains(lines[1], "ctl:ruleRemoveById=941100") {
		t.Fatal(lines[1])
	}
}
