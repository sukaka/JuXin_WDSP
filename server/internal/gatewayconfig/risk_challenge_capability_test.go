package gatewayconfig

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCapabilityFactsFromGuardRiskChallenge(t *testing.T) {
	appA := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	appB := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	appOutside := uuid.MustParse("00000000-0000-0000-0000-000000000003")
	coveredGlobal := &GuardConfig{
		RiskPolicy: &GuardRiskPolicy{Enabled: true, ChallengeThreshold: 60},
		RiskPolicyOverrides: []GuardRiskPolicyOverride{
			{ApplicationID: appA.String(), Policy: GuardRiskPolicy{ChallengeThreshold: 65}},
			{ApplicationID: appB.String(), Policy: GuardRiskPolicy{Enabled: true}},
		},
	}
	globalWithOverrides := &GuardConfig{
		RiskPolicy: &GuardRiskPolicy{Enabled: true, ChallengeThreshold: 60},
		RiskPolicyOverrides: []GuardRiskPolicyOverride{
			{ApplicationID: appA.String(), Policy: GuardRiskPolicy{ChallengeThreshold: 65}},
			{ApplicationID: appOutside.String(), Policy: GuardRiskPolicy{Enabled: true, ChallengeThreshold: 55}},
		},
	}
	zeroOverride := &GuardConfig{
		RiskPolicy: &GuardRiskPolicy{Enabled: true, ChallengeThreshold: 60},
		RiskPolicyOverrides: []GuardRiskPolicyOverride{
			{ApplicationID: appA.String(), Policy: GuardRiskPolicy{Enabled: true}},
			{ApplicationID: appOutside.String(), Policy: GuardRiskPolicy{Enabled: true, ChallengeThreshold: 55}},
		},
	}
	globalDisabled := &GuardConfig{
		RiskPolicy: &GuardRiskPolicy{Enabled: true},
		RiskPolicyOverrides: []GuardRiskPolicyOverride{
			{ApplicationID: appOutside.String(), Policy: GuardRiskPolicy{Enabled: true, ChallengeThreshold: 55}},
		},
	}
	for _, tc := range []struct {
		name         string
		cfg          *GuardConfig
		targetAppIDs []uuid.UUID
		want         bool
	}{
		{name: "nil", cfg: nil},
		{name: "empty", cfg: &GuardConfig{}},
		{name: "legacy threshold zero", cfg: &GuardConfig{RiskPolicy: &GuardRiskPolicy{Enabled: true}}},
		{name: "policy disabled", cfg: &GuardConfig{RiskPolicy: &GuardRiskPolicy{ChallengeThreshold: 60}}},
		{name: "global observe enabled", cfg: &GuardConfig{RiskPolicy: &GuardRiskPolicy{Enabled: true, Mode: "OBSERVE", ChallengeThreshold: 60}}, want: true},
		{name: "override enabled", cfg: &GuardConfig{RiskPolicyOverrides: []GuardRiskPolicyOverride{{Policy: GuardRiskPolicy{Enabled: true, ChallengeThreshold: 55}}}}, want: true},
		{name: "override disabled", cfg: &GuardConfig{RiskPolicyOverrides: []GuardRiskPolicyOverride{{Policy: GuardRiskPolicy{ChallengeThreshold: 55}}}}},
		{name: "global remains effective for future apps when all current apps override", cfg: coveredGlobal, want: true},
		{name: "local disabled override wins over global", cfg: coveredGlobal, targetAppIDs: []uuid.UUID{appA}},
		{name: "local zero threshold override wins over global", cfg: coveredGlobal, targetAppIDs: []uuid.UUID{appB}},
		{name: "local all targets disabled does not retain global future app requirement", cfg: coveredGlobal, targetAppIDs: []uuid.UUID{appA, appB}},
		{name: "local uncovered app inherits global", cfg: globalWithOverrides, targetAppIDs: []uuid.UUID{appB}, want: true},
		{name: "local disabled target ignores enabled outside override", cfg: globalWithOverrides, targetAppIDs: []uuid.UUID{appA}},
		{name: "local zero target ignores enabled outside override", cfg: zeroOverride, targetAppIDs: []uuid.UUID{appA}},
		{name: "local enabled override without global", cfg: globalDisabled, targetAppIDs: []uuid.UUID{appOutside}, want: true},
		{name: "local inherited disabled global ignores outside override", cfg: globalDisabled, targetAppIDs: []uuid.UUID{appA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := capabilityFactsFromGuard(tc.cfg, tc.targetAppIDs...).RiskChallenge; got != tc.want {
				t.Fatalf("RiskChallenge=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestCapabilityGateRiskChallenge(t *testing.T) {
	legacy := RequiredCapabilities(CapabilityFacts{})
	if !requiredEmpty(legacy) {
		t.Fatalf("legacy risk policy must keep an empty capability gate: %+v", legacy)
	}
	required := RequiredCapabilities(CapabilityFacts{RiskChallenge: true})
	if len(required.Actions) != 1 || required.Actions[0] != "risk_challenge" {
		t.Fatalf("required actions=%+v, want risk_challenge", required.Actions)
	}

	cfg := &GuardConfig{RiskPolicy: &GuardRiskPolicy{Enabled: true, ChallengeThreshold: 60}}
	dir := t.TempDir()
	writeManifest(t, dir, fullManifest("gw-old", time.Now().UTC()))
	publisher := &Publisher{sidecarDir: dir}
	ok, code, msg := publisher.evaluateCapabilityGate(context.Background(), cfg)
	if ok || code != "CAPABILITY_MISSING" || !strings.Contains(msg, "CAP_MISSING:actions.risk_challenge(required=risk_challenge") {
		t.Fatalf("old node gate ok=%v code=%s msg=%s", ok, code, msg)
	}
	if ok, code, msg := publisher.evaluateCapabilityGate(context.Background(), &GuardConfig{RiskPolicy: &GuardRiskPolicy{Enabled: true}}); !ok || code != "" {
		t.Fatalf("pure legacy policy gate changed: ok=%v code=%s msg=%s", ok, code, msg)
	}

	localAppID := uuid.MustParse("00000000-0000-0000-0000-000000000011")
	outsideAppID := uuid.MustParse("00000000-0000-0000-0000-000000000012")
	localCfg := &GuardConfig{
		RiskPolicy: &GuardRiskPolicy{Enabled: true, ChallengeThreshold: 60},
		RiskPolicyOverrides: []GuardRiskPolicyOverride{
			{ApplicationID: localAppID.String(), Policy: GuardRiskPolicy{ChallengeThreshold: 60}},
			{ApplicationID: outsideAppID.String(), Policy: GuardRiskPolicy{Enabled: true, ChallengeThreshold: 55}},
		},
	}
	if ok, code, msg := publisher.evaluateCapabilityGate(context.Background(), localCfg, localAppID); !ok || code != "" {
		t.Fatalf("disabled local override must bypass challenge gate: ok=%v code=%s msg=%s", ok, code, msg)
	}
	if ok, code, _ := publisher.evaluateCapabilityGate(context.Background(), localCfg); ok || code != "CAPABILITY_MISSING" {
		t.Fatalf("global publish must retain global challenge requirement: ok=%v code=%s", ok, code)
	}

	newDir := t.TempDir()
	manifest := fullManifest("gw-new", time.Now().UTC())
	manifest.Actions = append(manifest.Actions, "risk_challenge")
	writeManifest(t, newDir, manifest)
	publisher = &Publisher{sidecarDir: newDir}
	if ok, code, msg := publisher.evaluateCapabilityGate(context.Background(), cfg); !ok || code != "" {
		t.Fatalf("capable node rejected: ok=%v code=%s msg=%s", ok, code, msg)
	}
}
