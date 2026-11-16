package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildGuardHandlerGroupRate(t *testing.T) {
	app := AppData{AppID: "app-1", Code: "shop"}
	cfg := testGuardConfig()
	cfg.APIDynamicProtection = true
	cfg.GroupRatePerMinute = 120
	cfg.APIEndpointGroups = map[string]map[string][]string{
		"app-1": {"POST /v1/orders": {"GROUP_A", "GROUP_B"}},
	}
	handler := buildGuardHandler(cfg, app, 0)
	if got, ok := handler["group_rate_per_minute"].(int); !ok || got != 120 {
		t.Fatalf("handler group rate = %#v, want 120", handler["group_rate_per_minute"])
	}
	if got, ok := handler["api_endpoint_groups"].(map[string]map[string][]string); !ok || len(got["app-1"]["POST /v1/orders"]) != 2 {
		t.Fatalf("handler endpoint groups = %#v", handler["api_endpoint_groups"])
	}
	raw, err := json.Marshal(handler)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"group_rate_per_minute":120`, `"api_endpoint_groups":{"app-1":{"POST /v1/orders":["GROUP_A","GROUP_B"]}}`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("handler JSON missing %s: %s", want, raw)
		}
	}

	for _, cfg := range []*GuardConfig{
		{APIDynamicProtection: true, APIEndpointGroups: map[string]map[string][]string{"app-1": {"POST /v1/orders": {"GROUP_A"}}}},
		{APIDynamicProtection: true, GroupRatePerMinute: 0, APIEndpointGroups: map[string]map[string][]string{"app-1": {"POST /v1/orders": {"GROUP_A"}}}},
		{APIDynamicProtection: false, GroupRatePerMinute: 120, APIEndpointGroups: map[string]map[string][]string{"app-1": {"POST /v1/orders": {"GROUP_A"}}}},
	} {
		raw, err := json.Marshal(buildGuardHandler(cfg, app, 0))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "group_rate_per_minute") || strings.Contains(string(raw), "api_endpoint_groups") {
			t.Fatalf("zero or WDSP-off group rate must omit both keys: %s", raw)
		}
	}
}

func TestStripAPIGuardSectionsGroupRate(t *testing.T) {
	override := testGuardConfig()
	override.APIDynamicProtection = true
	override.GroupRatePerMinute = 60
	override.APIEndpointGroups = map[string]map[string][]string{"app-1": {"POST /v1/orders": {"GROUP_A"}}}
	gated := stripAPIGuardSections(override)
	if gated.GroupRatePerMinute != 0 || gated.APIEndpointGroups != nil {
		t.Fatalf("WDSP-off rollback retained group rate config: %+v", gated)
	}
	if override.GroupRatePerMinute != 60 || override.APIEndpointGroups["app-1"]["POST /v1/orders"][0] != "GROUP_A" {
		t.Fatal("rollback gating mutated the source snapshot")
	}
}
