package pipeline

import (
	"net/http"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

func TestProcessSharedDeviceAccountsUsesCustomLimit(t *testing.T) {
	stores := &detectors.StoreOverrides{
		IPSpread:       detectors.NewMemoryIPSpreadStore(64, nil),
		BehaviorWindow: detectors.NewMemoryWindowStore(64, nil),
	}
	var result *Result
	for _, principal := range []string{"principal-hash-a", "principal-hash-b"} {
		r, err := http.NewRequest(http.MethodGet, "http://example.test/v1/team", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) TestBrowser/1.0")
		r.Header.Set("Accept", "application/json")
		result, err = Process(r, Config{
			Enabled: true, Mode: "PROTECT", ApplicationID: "app-custom-limit",
			IdentitySalt: "test-salt", Stores: stores, SharedDeviceAccountLimit: 2,
			JWTVerification: &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: principal},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.FinalAction == "BLOCK" || result.FinalAction == "RATE_LIMIT" {
			t.Fatalf("custom observation must not block: %s", result.FinalAction)
		}
	}
	found := false
	for _, match := range result.Context.CopyMatches() {
		if match.RuleID == "behavior.shared_device_accounts" {
			found = true
			if match.Evidence["distinct_accounts"] != "2" || match.Category != "OBSERVE" {
				t.Fatalf("custom-limit match=%+v", match)
			}
		}
	}
	if !found {
		t.Fatalf("custom limit 2 did not observe second account: %+v", result.Context.CopyMatches())
	}
}
