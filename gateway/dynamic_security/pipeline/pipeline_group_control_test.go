package pipeline

import (
	"net/http"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

func TestProcessSharedDeviceAccountsObservesWithoutBlocking(t *testing.T) {
	stores := &detectors.StoreOverrides{IPSpread: detectors.NewMemoryIPSpreadStore(64, nil)}
	var result *Result
	for _, principal := range []string{"principal-hash-a", "principal-hash-b", "principal-hash-c"} {
		r, err := http.NewRequest(http.MethodGet, "http://example.test/v1/orders", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) TestBrowser/1.0")
		r.Header.Set("Accept", "application/json")
		result, err = Process(r, Config{
			Enabled: true, Mode: "PROTECT", ApplicationID: "app-group", IdentitySalt: "test-salt", Stores: stores,
			JWTVerification: &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: principal},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.Context.DeviceFingerprint == "" {
			t.Fatal("passive device fingerprint missing from real request parsing")
		}
		if result.FinalAction == "BLOCK" || result.FinalAction == "RATE_LIMIT" {
			t.Fatalf("observation must not directly block: %s", result.FinalAction)
		}
	}
	matches := result.Context.CopyMatches()
	found := false
	for _, match := range matches {
		if match.RuleID == "behavior.shared_device_accounts" {
			found = true
			if match.Evidence["distinct_accounts"] != "3" || match.Category != "OBSERVE" {
				t.Fatalf("match=%+v", match)
			}
		}
	}
	if !found {
		t.Fatalf("shared device observation missing: %+v", matches)
	}
}
