package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildGuardHandlerRiskPolicyChallenge(t *testing.T) {
	cfg := &GuardConfig{
		RiskPolicy: &GuardRiskPolicy{Enabled: true, Mode: "PROTECT", Version: 5, RateLimitThreshold: 40, ChallengeThreshold: 60, BlockThreshold: 80},
		RiskPolicyOverrides: []GuardRiskPolicyOverride{{
			ApplicationID: "app-1",
			Policy:        GuardRiskPolicy{Enabled: true, Mode: "OBSERVE", Version: 7, RateLimitThreshold: 30, ChallengeThreshold: 55, BlockThreshold: 70},
		}},
	}
	handler := buildGuardHandler(cfg, AppData{AppID: "app-1", Code: "shop"}, 0)
	if got := handler["risk_policy"].(*GuardRiskPolicy).ChallengeThreshold; got != 60 {
		t.Fatalf("global challenge threshold=%d, want 60", got)
	}
	overrides := handler["risk_policy_overrides"].([]GuardRiskPolicyOverride)
	if len(overrides) != 1 || overrides[0].Policy.ChallengeThreshold != 55 {
		t.Fatalf("override challenge policy=%+v", overrides)
	}
	raw, err := json.Marshal(handler)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"challenge_threshold":60`) || !strings.Contains(string(raw), `"challenge_threshold":55`) {
		t.Fatalf("published challenge thresholds missing: %s", raw)
	}

	zeroRaw, err := json.Marshal(buildGuardHandler(&GuardConfig{
		RiskPolicy: &GuardRiskPolicy{Enabled: true, ChallengeThreshold: 0},
	}, AppData{AppID: "app-1", Code: "shop"}, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(zeroRaw), `"challenge_threshold":0`) {
		t.Fatalf("explicit zero must not be omitted: %s", zeroRaw)
	}
}
