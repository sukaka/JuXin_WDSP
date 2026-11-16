package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildGuardHandlerCredentialRate(t *testing.T) {
	app := AppData{AppID: "app-1", Code: "shop"}
	cfg := testGuardConfig()
	cfg.APIDynamicProtection = true
	cfg.CredentialRatePerMinute = 120
	handler := buildGuardHandler(cfg, app, 0)
	if got, ok := handler["credential_rate_per_minute"].(int); !ok || got != 120 {
		t.Fatalf("handler credential rate = %#v, want 120", handler["credential_rate_per_minute"])
	}
	raw, err := json.Marshal(handler)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"credential_rate_per_minute":120`) {
		t.Fatalf("handler JSON missing credential rate: %s", raw)
	}

	for _, cfg := range []*GuardConfig{
		{APIDynamicProtection: true},
		{APIDynamicProtection: true, CredentialRatePerMinute: 0},
		{APIDynamicProtection: false, CredentialRatePerMinute: 120},
	} {
		raw, err := json.Marshal(buildGuardHandler(cfg, app, 0))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "credential_rate_per_minute") {
			t.Fatalf("zero or WDSP-off credential rate must be omitted: %s", raw)
		}
	}
}

func TestStripAPIGuardSectionsCredentialRate(t *testing.T) {
	override := testGuardConfig()
	override.APIDynamicProtection = true
	override.CredentialRatePerMinute = 60
	gated := stripAPIGuardSections(override)
	if gated.CredentialRatePerMinute != 0 {
		t.Fatalf("WDSP-off rollback retained credential rate %d", gated.CredentialRatePerMinute)
	}
	if override.CredentialRatePerMinute != 60 {
		t.Fatal("rollback gating mutated the source snapshot")
	}
}
