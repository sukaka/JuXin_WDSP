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
			RuleID:     901164,
			RuleSource: wafrules.SourceCRS,
			FileName:   "REQUEST-901-INITIALIZATION.conf",
			Name:       "初始化内部规则",
			Severity:   "NOTICE",
			Phase:      1,
			Tags:       []byte(`["OWASP_CRS"]`),
			AttackType: "OTHER",
			CRSVersion: "4.28.0",
		},
		{
			RuleID:     942100,
			RuleSource: wafrules.SourceCRS,
			FileName:   "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
			Name:       "SQLi",
			Severity:   "CRITICAL",
			Phase:      2,
			Tags:       []byte(`["attack-sqli","paranoia-level/1"]`),
			AttackType: "SQL_INJECTION",
			CRSVersion: "4.28.0",
			OvSummary:  "人工补充：针对本司订单检索接口的 SQL 注入核心检测规则。",
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
			CRSVersion: "4.28.0",
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
			CRSVersion: "4.28.0",
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

	if resp.Summary.TotalRules != 4 || resp.Summary.ActiveRules != 2 ||
		resp.Summary.DisabledByOverride != 1 || resp.Summary.SkippedByPL != 1 {
		t.Fatalf("unexpected summary: %+v", resp.Summary)
	}
	if resp.SecRuleEngine != "On" {
		t.Errorf("SecRuleEngine = %q, want On", resp.SecRuleEngine)
	}
	if len(resp.Rules) != 4 {
		t.Fatalf("rules len = %d, want 4", len(resp.Rules))
	}
	// 规则 901164 应展示精确中文名与结构化中文说明，并自动回源补全原始 SecRule
	if resp.Rules[0].RuleID != 901164 || resp.Rules[0].Name != "初始化：默认受限文件扩展名清单" {
		t.Errorf("rule[0] name/id = %+v", resp.Rules[0])
	}
	if resp.Rules[0].Detail == nil || resp.Rules[0].Detail.RuleType != "INTERNAL" ||
		!strings.Contains(resp.Rules[0].Description, "敏感文件扩展名清单") ||
		!strings.Contains(resp.Rules[0].RawRule, "restricted_extensions") {
		t.Errorf("rule[0] detail/raw_rule unexpected: desc=%q detail=%+v raw=%q", resp.Rules[0].Description, resp.Rules[0].Detail, resp.Rules[0].RawRule)
	}
	// 规则 920170 应通过文件回源自动补全原始 SecRule 文本（含链式子规则）
	if resp.Rules[1].RuleID != 920170 || resp.Rules[1].EffectiveStatus != RuleStatusActive {
		t.Errorf("rule[1] = %+v", resp.Rules[1])
	}
	if !strings.Contains(resp.Rules[1].RawRule, "id:920170") || !strings.Contains(resp.Rules[1].RawRule, "Content-Length") {
		t.Errorf("expected raw rule fallback for 920170, got: %q", resp.Rules[1].RawRule)
	}
	// 规则 942100 应透出人工维护说明覆盖
	if resp.Rules[2].RuleID != 942100 || resp.Rules[2].EffectiveStatus != RuleStatusDisabledByOverride {
		t.Errorf("rule[2] = %+v", resp.Rules[2])
	}
	if resp.Rules[2].Detail == nil || resp.Rules[2].Detail.Source != "CUSTOM" ||
		!strings.Contains(resp.Rules[2].Description, "人工补充") {
		t.Errorf("rule[2] expected custom description override, got desc=%q detail=%+v", resp.Rules[2].Description, resp.Rules[2].Detail)
	}
	if resp.Rules[3].RuleID != 942440 || resp.Rules[3].EffectiveStatus != RuleStatusSkippedByPL {
		t.Errorf("rule[3] = %+v", resp.Rules[3])
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
