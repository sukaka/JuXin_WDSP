// stage_test.go 攻击阶段推断纯函数用例（设计 #16.2 枚举与差距分析映射表）。
package attacksessions

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestStageForBehaviorRule(t *testing.T) {
	cases := []struct {
		ruleCode string
		want     string
	}{
		// 侦察六规则（网关 identitybehavior/recon.go 契约）
		{"RECON-URI-001", StageRecon},
		{"RECON-404-001", StageRecon},
		{"RECON-PATH-001", StageRecon},
		{"RECON-METHOD-001", StageRecon},
		{"RECON-PARAM-001", StageRecon},
		{"RECON-LOWSLOW-001", StageRecon},
		{"AUTH-FAIL-001", StageAuthProbe},
		// Business 滥用检测产出（#12.2/#13 语义映射）
		{"BIZ-LOGIN-001", StageAuthProbe},
		{"BIZ-EXPORT-001", StageDataAccess},
		{"BIZ-OBJENUM-001", StageAuthorizationProbe},
		// 未知兜底
		{"JR-RECON-003", StageUnknown}, // 不带 RECON- 前缀的历史规则码不误判
		{"SOMETHING-ELSE", StageUnknown},
		{"", StageUnknown},
	}
	for _, c := range cases {
		if got := StageForBehaviorRule(c.ruleCode); got != c.want {
			t.Errorf("StageForBehaviorRule(%q) = %s, want %s", c.ruleCode, got, c.want)
		}
	}
}

func TestStageForRuntimeDetails(t *testing.T) {
	cases := []struct {
		name    string
		details []dsctx.DetectorMatch
		want    string
	}{
		{"nil", nil, StageUnknown},
		{"empty", []dsctx.DetectorMatch{}, StageUnknown},
		{"shadow endpoint", []dsctx.DetectorMatch{{Detector: "lifecycle", RuleID: "lifecycle.new_endpoint"}}, StageDiscovery},
		{"deprecated call", []dsctx.DetectorMatch{{Detector: "lifecycle", RuleID: "lifecycle.deprecated_api_call"}}, StageDiscovery},
		{"auth finding", []dsctx.DetectorMatch{{Detector: "authentication", RuleID: "auth.missing_credential"}}, StageAuthProbe},
		{"bola unauthenticated", []dsctx.DetectorMatch{{Detector: "resource_access", RuleID: "resource.unauthenticated_object_access"}}, StageAuthorizationProbe},
		{"schema violation", []dsctx.DetectorMatch{{Detector: "api_schema", RuleID: "schema.type_mismatch"}}, StageExploit},
		{"parser ambiguity", []dsctx.DetectorMatch{{Detector: "api_parser", RuleID: "parser.duplicate_json_key"}}, StageExploit},
		{"waf detail", []dsctx.DetectorMatch{{Detector: "waf", RuleID: "942100"}}, StageExploit},
		{"sensitive value", []dsctx.DetectorMatch{{Detector: "sensitive_data", RuleID: "sensitive.value"}}, StageDataAccess},
		{"sensitive field name only", []dsctx.DetectorMatch{{Detector: "sensitive_data", RuleID: "sensitive.field"}}, StageUnknown},
		{"unmapped detector", []dsctx.DetectorMatch{{Detector: "identity", RuleID: "identity.present"}}, StageUnknown},
		{
			// 多命中取最高阶段（DISCOVERY < EXPLOIT < DATA_ACCESS）
			"mixed takes max",
			[]dsctx.DetectorMatch{
				{Detector: "lifecycle", RuleID: "lifecycle.new_endpoint"},
				{Detector: "api_schema", RuleID: "schema.param_length"},
				{Detector: "sensitive_data", RuleID: "sensitive.value"},
			},
			StageDataAccess,
		},
		{
			// resource_access 检测器其他规则不误判 AUTHORIZATION_PROBE
			"other resource rule",
			[]dsctx.DetectorMatch{{Detector: "resource_access", RuleID: "resource.rate_exceeded"}},
			StageUnknown,
		},
	}
	for _, c := range cases {
		if got := StageForRuntimeDetails(c.details); got != c.want {
			t.Errorf("%s: StageForRuntimeDetails = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestStageForSecurityEvent(t *testing.T) {
	if got := StageForSecurityEvent("SQLI"); got != StageExploit {
		t.Errorf("SQLi = %s, want EXPLOIT", got)
	}
	if got := StageForSecurityEvent("OTHER"); got != StageExploit {
		t.Errorf("OTHER = %s, want EXPLOIT", got)
	}
	if got := StageForSecurityEvent(""); got != StageUnknown {
		t.Errorf("empty = %s, want UNKNOWN", got)
	}
}

func TestMaxStageRankOrder(t *testing.T) {
	// 秩序：UNKNOWN < RECON < DISCOVERY < AUTH_PROBE < AUTHORIZATION_PROBE < EXPLOIT < DATA_ACCESS < PERSISTENCE
	chain := []string{StageUnknown, StageRecon, StageDiscovery, StageAuthProbe,
		StageAuthorizationProbe, StageExploit, StageDataAccess, StagePersistence}
	for i := 0; i < len(chain); i++ {
		for j := 0; j < len(chain); j++ {
			want := chain[i]
			if j > i {
				want = chain[j]
			}
			if got := MaxStage(chain[i], chain[j]); got != want {
				t.Errorf("MaxStage(%s, %s) = %s, want %s", chain[i], chain[j], got, want)
			}
		}
	}
	// 未知值按 UNKNOWN 秩处理
	if got := MaxStage("GARBAGE", StageRecon); got != StageRecon {
		t.Errorf("MaxStage(GARBAGE, RECON) = %s, want RECON", got)
	}
}

func TestParseDetectorMatches(t *testing.T) {
	if got := parseDetectorMatches(nil); got != nil {
		t.Errorf("nil raw = %v, want nil", got)
	}
	if got := parseDetectorMatches([]byte("not-json")); got != nil {
		t.Errorf("bad json = %v, want nil（坏数据不阻断）", got)
	}
	got := parseDetectorMatches([]byte(`[{"detector":"waf","rule_id":"942100"}]`))
	if len(got) != 1 || got[0].Detector != "waf" || got[0].RuleID != "942100" {
		t.Errorf("valid json = %+v", got)
	}
}
