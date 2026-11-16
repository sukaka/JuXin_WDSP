package gatewayconfig

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestBuildGuardHandlerAPIRateLimitAction(t *testing.T) {
	app := AppData{AppID: "app-1", Code: "shop"}
	for _, tc := range []struct {
		action  string
		seconds int
	}{
		{action: "RATE_LIMIT", seconds: 1},
		{action: "BLOCK", seconds: 60},
		{action: "TEMP_BLOCK", seconds: 86400},
	} {
		cfg := testGuardConfig()
		cfg.APIDynamicProtection = true
		cfg.APIRateLimitAction = tc.action
		cfg.APITempBlockSeconds = tc.seconds
		handler := buildGuardHandler(cfg, app, 0)
		if got := handler["api_rate_limit_action"]; got != tc.action {
			t.Fatalf("handler action = %#v, want %s", got, tc.action)
		}
		if got, ok := handler["api_temp_block_seconds"].(int); !ok || got != tc.seconds {
			t.Fatalf("handler seconds = %#v, want %d", handler["api_temp_block_seconds"], tc.seconds)
		}
		raw, err := json.Marshal(handler)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{fmt.Sprintf(`"api_rate_limit_action":%q`, tc.action), fmt.Sprintf(`"api_temp_block_seconds":%d`, tc.seconds)} {
			if !strings.Contains(string(raw), want) {
				t.Fatalf("handler JSON missing %s: %s", want, raw)
			}
		}
	}

	for _, cfg := range []*GuardConfig{
		{APIDynamicProtection: true},
		{APIDynamicProtection: false, APIRateLimitAction: "TEMP_BLOCK", APITempBlockSeconds: 60},
	} {
		raw, err := json.Marshal(buildGuardHandler(cfg, app, 0))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "api_rate_limit_action") || strings.Contains(string(raw), "api_temp_block_seconds") {
			t.Fatalf("empty or WDSP-off action settings must be omitted: %s", raw)
		}
	}
}

func TestStripAPIGuardSectionsAPIRateLimitAction(t *testing.T) {
	override := testGuardConfig()
	override.APIDynamicProtection = true
	override.APIRateLimitAction = "TEMP_BLOCK"
	override.APITempBlockSeconds = 60
	gated := stripAPIGuardSections(override)
	if gated.APIRateLimitAction != "" || gated.APITempBlockSeconds != 0 {
		t.Fatalf("WDSP-off rollback retained action settings: %+v", gated)
	}
	if override.APIRateLimitAction != "TEMP_BLOCK" || override.APITempBlockSeconds != 60 {
		t.Fatal("rollback gating mutated the source snapshot")
	}
}
