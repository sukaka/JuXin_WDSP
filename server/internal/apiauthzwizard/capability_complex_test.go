package apiauthzwizard

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/capability"
)

func TestSidecarCapabilityCheckerSelectsAz4OnlyForAnyOf(t *testing.T) {
	dir := t.TempDir()
	manifest := capability.Manifest{
		ContractVersion: capability.ContractVersion,
		NodeID:          "gw-authz",
		ProductVersion:  "jiuzhang-guard/test",
		Detectors:       []capability.DetectorCap{{Name: "authzdecide", Version: "az/3"}},
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	write := func() {
		t.Helper()
		raw, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "capability.json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	checker := SidecarCapabilityChecker(dir)
	if ok, reason := checker(context.Background(), requiredAuthzAZ("OWNER")); !ok {
		t.Fatalf("az/3 must satisfy legacy OWNER PROTECT readiness: %s", reason)
	}
	if ok, reason := checker(context.Background(), requiredAuthzAZ("ANY_OF")); ok || !strings.Contains(reason, "az/4") {
		t.Fatalf("az/3 must not satisfy ANY_OF readiness: ok=%t reason=%s", ok, reason)
	}
	manifest.Detectors[0].Version = "az/4"
	write()
	if ok, reason := checker(context.Background(), requiredAuthzAZ("ANY_OF")); !ok {
		t.Fatalf("az/4 must satisfy ANY_OF readiness: %s", reason)
	}
}
