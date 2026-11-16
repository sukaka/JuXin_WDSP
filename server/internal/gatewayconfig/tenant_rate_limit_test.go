package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildGuardHandlerTenantRate(t *testing.T) {
	app := AppData{AppID: "app-1", Code: "shop"}
	cfg := testGuardConfig()
	cfg.APIDynamicProtection = true
	cfg.TenantRatePerMinute = 120
	handler := buildGuardHandler(cfg, app, 0)
	if got, ok := handler["tenant_rate_per_minute"].(int); !ok || got != 120 {
		t.Fatalf("handler tenant rate = %#v, want 120", handler["tenant_rate_per_minute"])
	}
	raw, err := json.Marshal(handler)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"tenant_rate_per_minute":120`) {
		t.Fatalf("handler JSON missing tenant rate: %s", raw)
	}

	for _, cfg := range []*GuardConfig{
		{APIDynamicProtection: true},
		{APIDynamicProtection: true, TenantRatePerMinute: 0},
		{APIDynamicProtection: false, TenantRatePerMinute: 120},
	} {
		raw, err := json.Marshal(buildGuardHandler(cfg, app, 0))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "tenant_rate_per_minute") {
			t.Fatalf("zero or WDSP-off tenant rate must be omitted: %s", raw)
		}
	}
}

func TestStripAPIGuardSectionsTenantRate(t *testing.T) {
	override := testGuardConfig()
	override.APIDynamicProtection = true
	override.TenantRatePerMinute = 60
	gated := stripAPIGuardSections(override)
	if gated.TenantRatePerMinute != 0 {
		t.Fatalf("WDSP-off rollback retained tenant rate %d", gated.TenantRatePerMinute)
	}
	if override.TenantRatePerMinute != 60 {
		t.Fatal("rollback gating mutated the source snapshot")
	}
}
