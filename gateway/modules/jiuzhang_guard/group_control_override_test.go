package jiuzhang_guard

import (
	"path/filepath"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func TestSharedDeviceAccountLimitApplicationOverrides(t *testing.T) {
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app-custom-group", EventsLog: filepath.Join(t.TempDir(), "events.log"), IdentitySalt: "test-salt",
		RiskPolicyOverrides: []riskPolicyOverrideJSON{
			{ApplicationID: "app-custom-group", Policy: riskPolicyJSON{}, SharedDeviceAccountLimit: 4},
			{ApplicationID: "app-other-group", Policy: riskPolicyJSON{}, SharedDeviceAccountLimit: 6},
			{ApplicationID: "app-invalid-group", Policy: riskPolicyJSON{}, SharedDeviceAccountLimit: 1},
		},
	})
	for appID, want := range map[string]int{
		"app-custom-group": 4, "app-other-group": 6,
		"app-invalid-group":    detectors.DefaultSharedDeviceAccountLimit,
		"app-without-override": detectors.DefaultSharedDeviceAccountLimit,
	} {
		g.AppID = appID
		if got := g.sharedDeviceAccountLimit(); got != want {
			t.Fatalf("application %s limit=%d want %d", appID, got, want)
		}
	}
}
