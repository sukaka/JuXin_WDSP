package pipeline

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

func TestProcessObjectEnumerationIsolatesApplications(t *testing.T) {
	store := detectors.NewMemoryObjectEnumerationStore(100, nil)
	for _, applicationID := range []string{"app-a", "app-b"} {
		for i := 0; i < 7; i++ {
			r, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://h/v1/cases/%d", 9100+i), nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Authorization", "Bearer unit-test-credential-0123456789")
			res, err := Process(r, Config{
				Enabled: true, Mode: "OBSERVE", IdentitySalt: "unit-test-salt", ApplicationID: applicationID,
				JWTVerification: &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "same-verified-subject"},
				Stores:          &detectors.StoreOverrides{ObjectEnumeration: store},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, match := range res.Context.CopyMatches() {
				if match.RuleID == "resource.object_enumeration" {
					t.Fatalf("application %s must not inherit another application's object window: %+v", applicationID, match)
				}
			}
		}
	}
}
