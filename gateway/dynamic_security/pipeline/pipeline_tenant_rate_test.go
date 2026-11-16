package pipeline

import (
	"net/http"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

func TestProcessTenantRateMounted(t *testing.T) {
	const tenant = "pipeline-tenant-rate-secret"
	cfg := Config{
		Enabled:             true,
		Mode:                "PROTECT",
		IdentitySalt:        "pipeline-tenant-rate-salt",
		TenantRatePerMinute: 1,
		JWTVerification: &jwtverify.VerificationResult{
			Status:           jwtverify.StatusVerified,
			VerifiedTenantID: tenant,
		},
	}
	first := asmProcess(t, asmBearerReq(t, http.MethodGet, "http://h/v1/tenant-rate", "", ""), cfg)
	if hasRule(first, "ratelimit.tenant_rate") || first.FinalAction == "RATE_LIMIT" {
		t.Fatalf("first request must be below tenant limit: %+v", first.Context.CopyMatches())
	}
	second := asmProcess(t, asmBearerReq(t, http.MethodGet, "http://h/v1/tenant-rate", "", ""), cfg)
	if !hasRule(second, "ratelimit.tenant_rate") || second.FinalAction != "RATE_LIMIT" {
		t.Fatalf("second request must produce tenant RATE_LIMIT in PROTECT: action=%s matches=%+v", second.FinalAction, second.Context.CopyMatches())
	}
	for _, m := range second.Context.CopyMatches() {
		if m.RuleID != "ratelimit.tenant_rate" {
			continue
		}
		for _, value := range m.Evidence {
			if value == tenant {
				t.Fatalf("tenant plaintext leaked into pipeline evidence: %+v", m.Evidence)
			}
		}
	}
}

func TestProcessTenantRateSkipsUntrustedMissingTenantAndDisabled(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		jwt   *jwtverify.VerificationResult
	}{
		{name: "no verification result", limit: 1},
		{name: "unverified", limit: 1, jwt: &jwtverify.VerificationResult{Status: jwtverify.StatusUnverified, VerifiedTenantID: "pipeline-untrusted-tenant"}},
		{name: "missing tenant", limit: 1, jwt: &jwtverify.VerificationResult{Status: jwtverify.StatusVerified}},
		{name: "zero disabled", limit: 0, jwt: &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedTenantID: "pipeline-disabled-tenant"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Enabled:             true,
				Mode:                "PROTECT",
				IdentitySalt:        "pipeline-tenant-rate-skip-" + tc.name,
				TenantRatePerMinute: tc.limit,
				JWTVerification:     tc.jwt,
			}
			for hit := 0; hit < 2; hit++ {
				res := asmProcess(t, asmBearerReq(t, http.MethodGet, "http://h/v1/tenant-rate-skip", "", ""), cfg)
				if hasRule(res, "ratelimit.tenant_rate") || res.FinalAction == "RATE_LIMIT" {
					t.Fatalf("untrusted, missing tenant or disabled config must skip: %+v", res.Context.CopyMatches())
				}
			}
		})
	}
}
