package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildGuardHandlerIdentityBlocks(t *testing.T) {
	cfg := testGuardConfig()
	cfg.APIDynamicProtection = true
	cfg.APIIdentityBlocks = []GuardIdentityBlock{{ID: "id-1", IdentityKey: "fp-1"}}
	raw, err := json.Marshal(buildGuardHandler(cfg, AppData{AppID: "app-1", Code: "shop"}, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"api_identity_blocks":[{"id":"id-1","identity_key":"fp-1"}]`) {
		t.Fatalf("handler JSON missing identity blocks: %s", raw)
	}
	cfg.APIDynamicProtection = false
	raw, err = json.Marshal(buildGuardHandler(cfg, AppData{AppID: "app-1", Code: "shop"}, 0))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "api_identity_blocks") {
		t.Fatalf("WDSP-off handler contains identity blocks: %s", raw)
	}
}

func TestStripAPIGuardSectionsIdentityBlocks(t *testing.T) {
	override := testGuardConfig()
	override.APIDynamicProtection = true
	override.APIIdentityBlocks = []GuardIdentityBlock{{ID: "id-1", IdentityKey: "fp-1"}}
	gated := stripAPIGuardSections(override)
	if gated.APIIdentityBlocks != nil {
		t.Fatalf("WDSP-off rollback retained identity blocks: %+v", gated.APIIdentityBlocks)
	}
	if len(override.APIIdentityBlocks) != 1 {
		t.Fatal("rollback gating mutated source snapshot")
	}
}
