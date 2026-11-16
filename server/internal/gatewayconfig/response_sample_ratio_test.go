package gatewayconfig

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildGuardHandlerResponseSampleRatio(t *testing.T) {
	app := AppData{AppID: "app-1", Code: "shop"}
	for _, tc := range []struct {
		name  string
		ratio float64
		json  string
	}{
		{name: "全量", ratio: 1, json: `"api_response_sample_ratio":1`},
		{name: "显式零", ratio: 0, json: `"api_response_sample_ratio":0`},
		{name: "小数", ratio: 0.25, json: `"api_response_sample_ratio":0.25`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testGuardConfig()
			cfg.APIDynamicProtection = true
			cfg.APIResponseSampleRatio = &tc.ratio
			handler := buildGuardHandler(cfg, app, 0)
			got, ok := handler["api_response_sample_ratio"].(float64)
			if !ok || got != tc.ratio {
				t.Fatalf("handler ratio = %#v, want %v", handler["api_response_sample_ratio"], tc.ratio)
			}
			raw, err := json.Marshal(handler)
			if err != nil {
				t.Fatalf("marshal handler: %v", err)
			}
			if !strings.Contains(string(raw), tc.json) {
				t.Fatalf("handler JSON missing %s: %s", tc.json, raw)
			}
		})
	}

	unconfigured := testGuardConfig()
	unconfigured.APIDynamicProtection = true
	if _, ok := buildGuardHandler(unconfigured, app, 0)["api_response_sample_ratio"]; ok {
		t.Fatal("unconfigured ratio must be omitted so the gateway default 1 applies")
	}

	zero := 0.0
	off := testGuardConfig()
	off.APIResponseSampleRatio = &zero
	raw, err := json.Marshal(buildGuardHandler(off, app, 0))
	if err != nil {
		t.Fatalf("marshal WDSP-off handler: %v", err)
	}
	if strings.Contains(string(raw), "api_response_sample_ratio") {
		t.Fatalf("WDSP-off handler must omit ratio: %s", raw)
	}
}

func TestStripAPIGuardSectionsResponseSampleRatio(t *testing.T) {
	zero := 0.0
	override := testGuardConfig()
	override.APIDynamicProtection = true
	override.APIResponseSampleRatio = &zero
	gated := stripAPIGuardSections(override)
	if gated.APIResponseSampleRatio != nil {
		t.Fatalf("WDSP-off rollback must strip ratio: %v", *gated.APIResponseSampleRatio)
	}
	if override.APIResponseSampleRatio == nil || *override.APIResponseSampleRatio != 0 {
		t.Fatal("gating must not mutate the source snapshot")
	}
}

func TestReinjectConfigSecretsPreservesResponseSampleRatioZero(t *testing.T) {
	const configJSON = `{"apps":{"http":{"servers":{"srv0":{"routes":[{"handle":[{"handler":"jiuzhang_guard","api_response_sample_ratio":0}]}]}}}}}`
	publisher := &Publisher{}
	got, err := publisher.reinjectConfigSecrets(context.Background(), configJSON)
	if err != nil {
		t.Fatalf("reinject secrets: %v", err)
	}
	if got != configJSON {
		t.Fatalf("secret-free rollback changed explicit zero:\n got %s\nwant %s", got, configJSON)
	}
}
