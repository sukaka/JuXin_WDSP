package gatewayconfig

import "testing"

func TestBuildGuardHandlerRiskPolicyOverrides(t *testing.T) {
	cfg := &GuardConfig{RiskPolicyOverrides: []GuardRiskPolicyOverride{{
		ApplicationID: "app-1",
		Policy: GuardRiskPolicy{
			Enabled: true, Mode: "PROTECT", Version: 4, BlockThreshold: 80, RateLimitThreshold: 40,
			RateLimitRPS: 10, SignalWindowSeconds: 3600, Scores: map[string]int{"WAF": 50},
			RiskLevels: map[string]int{"medium": 20, "high": 40, "critical": 70},
		},
	}}}
	handler := buildGuardHandler(cfg, AppData{AppID: "app-1", Code: "shop"}, 0)
	items, ok := handler["risk_policy_overrides"].([]GuardRiskPolicyOverride)
	if !ok || len(items) != 1 {
		t.Fatalf("risk_policy_overrides=%T %+v", handler["risk_policy_overrides"], handler["risk_policy_overrides"])
	}
	if items[0].ApplicationID != "app-1" || items[0].Policy.Version != 4 || items[0].Policy.Scores["WAF"] != 50 {
		t.Fatalf("override=%+v", items[0])
	}
}
