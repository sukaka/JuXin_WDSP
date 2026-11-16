package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildGuardHandlerMaskCrypto(t *testing.T) {
	cfg := testGuardConfig()
	cfg.APIDynamicProtection = true
	cfg.APIMaskCrypto = &GuardMaskCrypto{KID: "mask_k1", KeyHex: strings.Repeat("ab", 32)}
	cfg.APIMaskRules = []GuardMaskRule{
		{Algorithm: "ENCRYPT", Params: map[string]any{"key_id": "mask_k1"}},
		{Algorithm: "MAP", Params: map[string]any{"map_id": "map_1"}},
	}
	raw, err := json.Marshal(buildGuardHandler(cfg, AppData{AppID: "app-1", Code: "shop"}, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"api_mask_crypto":{"kid":"mask_k1","key_hex":"` + strings.Repeat("ab", 32) + `"}`,
		`"params":{"key_id":"mask_k1"}`, `"params":{"map_id":"map_1"}`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("handler JSON missing %s: %s", want, raw)
		}
	}
	cfg.APIDynamicProtection = false
	raw, err = json.Marshal(buildGuardHandler(cfg, AppData{AppID: "app-1", Code: "shop"}, 0))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "api_mask_crypto") {
		t.Fatalf("WDSP-off handler contains mask crypto: %s", raw)
	}
}

func TestStripAPIGuardSectionsMaskCrypto(t *testing.T) {
	override := testGuardConfig()
	override.APIDynamicProtection = true
	override.APIMaskCrypto = &GuardMaskCrypto{KID: "mask_k1", KeyHex: strings.Repeat("ab", 32)}
	gated := stripAPIGuardSections(override)
	if gated.APIMaskCrypto != nil {
		t.Fatalf("WDSP-off rollback retained mask crypto: %+v", gated.APIMaskCrypto)
	}
	if override.APIMaskCrypto == nil {
		t.Fatal("rollback gating mutated source snapshot")
	}
}
