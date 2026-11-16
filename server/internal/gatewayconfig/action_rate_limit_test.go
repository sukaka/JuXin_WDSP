package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildGuardHandlerActionRate(t *testing.T) {
	app := AppData{AppID: "app-1", Code: "shop"}
	cfg := testGuardConfig()
	cfg.APIDynamicProtection = true
	cfg.ActionRatePerMinute = 120
	cfg.APIEndpointActions = map[string]string{
		"POST /v1/orders":  "CREATE",
		"POST /v1/reviews": "MANUAL_REVIEW_V2",
	}
	handler := buildGuardHandler(cfg, app, 0)
	if got, ok := handler["action_rate_per_minute"].(int); !ok || got != 120 {
		t.Fatalf("handler action rate = %#v, want 120", handler["action_rate_per_minute"])
	}
	if got, ok := handler["api_endpoint_actions"].(map[string]string); !ok ||
		got["POST /v1/orders"] != "CREATE" || got["POST /v1/reviews"] != "MANUAL_REVIEW_V2" {
		t.Fatalf("handler endpoint actions = %#v", handler["api_endpoint_actions"])
	}
	raw, err := json.Marshal(handler)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"action_rate_per_minute":120`,
		`"api_endpoint_actions":{"POST /v1/orders":"CREATE","POST /v1/reviews":"MANUAL_REVIEW_V2"}`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("handler JSON missing %s: %s", want, raw)
		}
	}

	for _, cfg := range []*GuardConfig{
		{APIDynamicProtection: true, APIEndpointActions: map[string]string{"POST /v1/orders": "CREATE"}},
		{APIDynamicProtection: true, ActionRatePerMinute: 0, APIEndpointActions: map[string]string{"POST /v1/orders": "CREATE"}},
		{APIDynamicProtection: false, ActionRatePerMinute: 120, APIEndpointActions: map[string]string{"POST /v1/orders": "CREATE"}},
	} {
		raw, err := json.Marshal(buildGuardHandler(cfg, app, 0))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "action_rate_per_minute") || strings.Contains(string(raw), "api_endpoint_actions") {
			t.Fatalf("zero or WDSP-off action rate must omit both keys: %s", raw)
		}
	}
}

func TestStripAPIGuardSectionsActionRate(t *testing.T) {
	override := testGuardConfig()
	override.APIDynamicProtection = true
	override.ActionRatePerMinute = 60
	override.APIEndpointActions = map[string]string{"POST /v1/orders": "CREATE"}
	gated := stripAPIGuardSections(override)
	if gated.ActionRatePerMinute != 0 || gated.APIEndpointActions != nil {
		t.Fatalf("WDSP-off rollback retained action rate config: %+v", gated)
	}
	if override.ActionRatePerMinute != 60 || override.APIEndpointActions["POST /v1/orders"] != "CREATE" {
		t.Fatal("rollback gating mutated the source snapshot")
	}
}
