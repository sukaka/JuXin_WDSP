package pipeline

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

func TestProcessObjectEnumerationIsObserveOnlyAndRedacted(t *testing.T) {
	store := detectors.NewMemoryObjectEnumerationStore(100, nil)
	for i := 0; i < 8; i++ {
		r, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://h/v1/cases/%d", 6100+i), nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer unit-test-credential-0123456789")
		res, err := Process(r, Config{
			Enabled: true, Mode: "PROTECT", IdentitySalt: "unit-test-salt",
			JWTVerification: &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "verified-subject-fingerprint"},
			Stores:          &detectors.StoreOverrides{ObjectEnumeration: store},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.FinalAction == "BLOCK" {
			t.Fatalf("enumeration observation must not block: %+v", res.Context.CopyMatches())
		}
		if i < 7 {
			continue
		}
		var found bool
		for _, match := range res.Context.CopyMatches() {
			if match.RuleID != "resource.object_enumeration" {
				continue
			}
			found = true
			if match.Category != "OBSERVE" || match.Evidence["distinct_objects"] != "8" || match.Evidence["identity_assurance"] != "JWT_VERIFIED" {
				t.Fatalf("unexpected match: %+v", match)
			}
			for _, value := range match.Evidence {
				if strings.Contains(value, "610") {
					t.Fatalf("raw object identifier leaked: %+v", match.Evidence)
				}
			}
		}
		if !found {
			t.Fatalf("enumeration signal missing: %+v", res.Context.CopyMatches())
		}
	}
}
