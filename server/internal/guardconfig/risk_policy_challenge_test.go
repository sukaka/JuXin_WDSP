package guardconfig

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func TestRiskPolicyChallengeConfigHashAndSnapshot(t *testing.T) {
	newConfig := func(global, override int) *gatewayconfig.GuardConfig {
		return &gatewayconfig.GuardConfig{
			RiskPolicy: &gatewayconfig.GuardRiskPolicy{Enabled: true, Version: 3, RateLimitThreshold: 40, ChallengeThreshold: global, BlockThreshold: 80},
			RiskPolicyOverrides: []gatewayconfig.GuardRiskPolicyOverride{{
				ApplicationID: "app-1",
				Policy:        gatewayconfig.GuardRiskPolicy{Enabled: true, Version: 4, RateLimitThreshold: 30, ChallengeThreshold: override, BlockThreshold: 70},
			}},
		}
	}
	marshalSnapshot := func(cfg *gatewayconfig.GuardConfig) []byte {
		t.Helper()
		raw, err := json.Marshal(RedactGuardConfig(cfg))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	disabledRaw := marshalSnapshot(newConfig(0, 0))
	enabledRaw := marshalSnapshot(newConfig(60, 55))
	if strings.Count(string(disabledRaw), `"challenge_threshold":0`) != 2 {
		t.Fatalf("snapshot omitted explicit disabled thresholds: %s", disabledRaw)
	}
	if sha256.Sum256(disabledRaw) == sha256.Sum256(enabledRaw) {
		t.Fatal("challenge threshold change must change the access-control config hash")
	}
	decoded, err := decodeGuardConfigSnapshot(enabledRaw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RiskPolicy == nil || decoded.RiskPolicy.ChallengeThreshold != 60 ||
		len(decoded.RiskPolicyOverrides) != 1 || decoded.RiskPolicyOverrides[0].Policy.ChallengeThreshold != 55 {
		t.Fatalf("rollback snapshot lost challenge thresholds: %+v", decoded)
	}

	legacy, err := decodeGuardConfigSnapshot([]byte(`{"risk_policy":{"enabled":true,"version":1},"risk_policy_overrides":[{"application_id":"app-1","policy":{"enabled":true,"version":2}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if legacy.RiskPolicy.ChallengeThreshold != 0 || legacy.RiskPolicyOverrides[0].Policy.ChallengeThreshold != 0 {
		t.Fatalf("legacy snapshot must default challenge to disabled: %+v", legacy)
	}
}
