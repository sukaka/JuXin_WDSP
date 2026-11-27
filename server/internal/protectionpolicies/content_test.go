package protectionpolicies

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/ruleoverrides"
	"github.com/jiuzhang-waf/server/internal/wafrules"
)

func TestEvaluateRuleEffectiveStatus(t *testing.T) {
	if got := EvaluateRuleEffectiveStatus(ModeOff, 2, 1, false); got != RuleStatusModeOff {
		t.Errorf("ModeOff status = %q, want %q", got, RuleStatusModeOff)
	}
	if got := EvaluateRuleEffectiveStatus(ModeProtect, 2, 1, true); got != RuleStatusDisabledByOverride {
		t.Errorf("override disabled status = %q, want %q", got, RuleStatusDisabledByOverride)
	}
	if got := EvaluateRuleEffectiveStatus(ModeProtect, 1, 2, false); got != RuleStatusSkippedByPL {
		t.Errorf("PL2 under PL1 status = %q, want %q", got, RuleStatusSkippedByPL)
	}
	if got := EvaluateRuleEffectiveStatus(ModeObserve, 2, 2, false); got != RuleStatusActive {
		t.Errorf("PL2 under PL2 status = %q, want %q", got, RuleStatusActive)
	}
	if got := EvaluateRuleEffectiveStatus(ModeProtect, 1, 0, false); got != RuleStatusActive {
		t.Errorf("PL0 rule status = %q, want %q", got, RuleStatusActive)
	}
}

func TestExtractRuleParanoiaLevel(t *testing.T) {
	if got := ExtractRuleParanoiaLevel([]string{"attack-sqli", "paranoia-level/3"}, nil); got != 3 {
		t.Errorf("tag PL = %d, want 3", got)
	}
	if got := ExtractRuleParanoiaLevel(nil, []byte(`{"pl":2}`)); got != 2 {
		t.Errorf("parsed_spec PL = %d, want 2", got)
	}
	if got := ExtractRuleParanoiaLevel([]string{"attack-sqli"}, []byte(`{}`)); got != 0 {
		t.Errorf("no PL = %d, want 0", got)
	}
}

func TestBuildPolicyContentResponseAndDirectives(t *testing.T) {
	policy := &Policy{
		ID:                       uuid.MustParse("11111111-2222-3333-4444-555555555555"),
		Code:                     "high-security",
		Name:                     "高安全策略",
		ProtectionMode:           ModeProtect,
		ParanoiaLevel:            2,
		InboundAnomalyThreshold:  5,
		OutboundAnomalyThreshold: 4,
	}
	overrideLines := ruleoverrides.BuildDisableSecLang([]int{942100})
	customLines := []string{`SecRule ARGS "@rx forbidden" "id:7100001,phase:2,deny,status:403,msg:'custom'"`}
	directives := gatewayconfig.BuildPolicyDirectives(
		policy.ProtectionMode,
		policy.ParanoiaLevel,
		policy.InboundAnomalyThreshold,
		policy.OutboundAnomalyThreshold,
		nil,
		customLines,
		overrideLines,
	)

	if !strings.Contains(directives, "SecRuleEngine On") {
		t.Errorf("directives missing SecRuleEngine On: %s", directives)
	}
	if !strings.Contains(directives, "setvar:tx.blocking_paranoia_level=2,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4") {
		t.Errorf("directives missing PL/threshold SecAction: %s", directives)
	}
	if !strings.Contains(directives, "ctl:ruleRemoveById=942100") {
		t.Errorf("directives missing rule override: %s", directives)
	}
	if !strings.Contains(directives, "id:7100001") {
		t.Errorf("directives missing custom rule: %s", directives)
	}

	h := NewHandler(nil, nil)
	h.SetCRSDir("../../../gateway/rules/crs/rules")
	rawRows := []rawWafRuleRow{
		{
			RuleID:     942100,
			RuleSource: wafrules.SourceCRS,
			FileName:   "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
			Name:       "SQLi",
			Severity:   "CRITICAL",
			Phase:      2,
			Tags:       []byte(`["attack-sqli","paranoia-level/1"]`),
			AttackType: "SQL_INJECTION",
		},
		{
			RuleID:     920170,
			RuleSource: wafrules.SourceCRS,
			FileName:   "REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
			Name:       "GET with body",
			Severity:   "CRITICAL",
			Phase:      1,
			Tags:       []byte(`["attack-protocol","paranoia-level/1"]`),
			AttackType: "PROTOCOL_VIOLATION",
		},
		{
			RuleID:     942440,
			RuleSource: wafrules.SourceCRS,
			FileName:   "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
			Name:       "SQL Comment",
			Severity:   "CRITICAL",
			Phase:      2,
			Tags:       []byte(`["attack-sqli","paranoia-level/3"]`),
			AttackType: "SQL_INJECTION",
		},
	}

	resp := h.buildPolicyContentResponse(
		policy,
		directives,
		[]PolicyOverrideItem{{RuleID: 942100, ScopeType: "POLICY", Action: "DISABLE", EffectiveActive: true}},
		[]PolicyCustomRuleItem{{RuleID: 7100001, Name: "custom", GeneratedRule: customLines[0]}},
		nil,
		map[int]bool{942100: true},
		rawRows,
		ContentFilter{Page: 1, PageSize: 20},
	)

	if resp.Summary.TotalRules != 3 || resp.Summary.ActiveRules != 1 ||
		resp.Summary.DisabledByOverride != 1 || resp.Summary.SkippedByPL != 1 {
		t.Fatalf("unexpected summary: %+v", resp.Summary)
	}
	if resp.SecRuleEngine != "On" {
		t.Errorf("SecRuleEngine = %q, want On", resp.SecRuleEngine)
	}
	if len(resp.Rules) != 3 {
		t.Fatalf("rules len = %d, want 3", len(resp.Rules))
	}
	// 规则 920170 应通过文件回源自动补全原始 SecRule 文本（含链式子规则）
	if resp.Rules[0].RuleID != 920170 || resp.Rules[0].EffectiveStatus != RuleStatusActive {
		t.Errorf("rule[0] = %+v", resp.Rules[0])
	}
	if !strings.Contains(resp.Rules[0].RawRule, "id:920170") || !strings.Contains(resp.Rules[0].RawRule, "Content-Length") {
		t.Errorf("expected raw rule fallback for 920170, got: %q", resp.Rules[0].RawRule)
	}
	if resp.Rules[1].RuleID != 942100 || resp.Rules[1].EffectiveStatus != RuleStatusDisabledByOverride {
		t.Errorf("rule[1] = %+v", resp.Rules[1])
	}
	if resp.Rules[2].RuleID != 942440 || resp.Rules[2].EffectiveStatus != RuleStatusSkippedByPL {
		t.Errorf("rule[2] = %+v", resp.Rules[2])
	}
}

func TestContentHandlerRejectsInvalidUUID(t *testing.T) {
	h := NewHandler(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/protection-policies/not-a-uuid/content", nil)
	req.SetPathValue("id", "not-a-uuid")
	rr := httptest.NewRecorder()
	h.Content(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}
