package detectors

import (
	"reflect"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

func isolateTenantRateDetectorTrackerForTest(t *testing.T, capacity int) *windowTracker {
	t.Helper()
	tracker := newWindowTracker(capacity, nil)
	previous := defaultTenantRateTracker
	defaultTenantRateTracker = tracker
	t.Cleanup(func() {
		defaultTenantRateTracker = previous
	})
	return tracker
}

func TestCheckTenantRateVerifiedThresholdAndEvidence(t *testing.T) {
	tracker := isolateTenantRateDetectorTrackerForTest(t, 16)
	const (
		tenant = "tenant-secret-acme"
		salt   = "tenant-rate-test-salt"
		limit  = 2
	)
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedTenantID: tenant}
	for hit := 1; hit <= limit; hit++ {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckTenantRate(ctx, jwt, salt, limit)
		if ctx.MatchCount() != 0 {
			t.Fatalf("hit %d at/below limit must not match: %+v", hit, ctx.CopyMatches())
		}
	}

	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckTenantRate(ctx, jwt, salt, limit)
	m := findMatch(ctx, "ratelimit.tenant_rate")
	if m == nil {
		t.Fatalf("hit limit+1 must produce tenant rate match: %+v", ctx.CopyMatches())
	}
	if m.Detector != "api_ratelimit" || m.Category != "RATE_LIMIT" || m.Severity != "HIGH" || m.ScoreDelta != 30 {
		t.Fatalf("bad match attributes: %+v", m)
	}
	wantEvidence := map[string]string{"window_count": "3", "limit": "2", "window": "1m"}
	if !reflect.DeepEqual(m.Evidence, wantEvidence) {
		t.Fatalf("evidence must contain only allowlisted fields: got %+v, want %+v", m.Evidence, wantEvidence)
	}
	key := Fingerprint(salt, "jwt-tenant:"+tenant)
	if _, ok := tracker.entries.get(key); !ok {
		t.Fatalf("tracker must use the domain-separated tenant fingerprint key %q", key)
	}
	for k, v := range m.Evidence {
		if k == "tenant" || k == "tenant_id" || k == "tenant_fingerprint" || v == tenant || v == key {
			t.Fatalf("tenant plaintext or fingerprint leaked into evidence: %+v", m.Evidence)
		}
	}
}

func TestCheckTenantRateSkipsUntrustedMissingTenantAndDisabled(t *testing.T) {
	tracker := isolateTenantRateDetectorTrackerForTest(t, 16)
	tests := []struct {
		name  string
		jwt   *jwtverify.VerificationResult
		limit int
	}{
		{name: "nil context result", jwt: nil, limit: 1},
		{name: "unverified", jwt: &jwtverify.VerificationResult{Status: jwtverify.StatusUnverified, VerifiedTenantID: "tenant-untrusted"}, limit: 1},
		{name: "invalid", jwt: &jwtverify.VerificationResult{Status: jwtverify.StatusInvalid, VerifiedTenantID: "tenant-invalid"}, limit: 1},
		{name: "verified without tenant", jwt: &jwtverify.VerificationResult{Status: jwtverify.StatusVerified}, limit: 1},
		{name: "zero disabled", jwt: &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedTenantID: "tenant-zero"}, limit: 0},
		{name: "negative disabled", jwt: &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedTenantID: "tenant-negative"}, limit: -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := dsctx.New("t", dsctx.DefaultParseLimits())
			for hit := 0; hit < 2; hit++ {
				CheckTenantRate(ctx, tc.jwt, "tenant-rate-skip-salt", tc.limit)
			}
			if ctx.MatchCount() != 0 {
				t.Fatalf("untrusted, missing tenant or disabled input must skip: %+v", ctx.CopyMatches())
			}
		})
	}
	CheckTenantRate(nil, &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedTenantID: "tenant-nil-context"}, "salt", 1)
	if got := len(tracker.entries.items); got != 0 {
		t.Fatalf("skipped requests must not create tracker state, got %d entries", got)
	}
}

func TestCheckTenantRateIsolatesTenants(t *testing.T) {
	isolateTenantRateDetectorTrackerForTest(t, 16)
	const salt = "tenant-rate-isolation-salt"
	tenantA := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedTenantID: "tenant-a"}
	tenantB := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedTenantID: "tenant-b"}

	ctxA1 := dsctx.New("a1", dsctx.DefaultParseLimits())
	CheckTenantRate(ctxA1, tenantA, salt, 1)
	ctxB1 := dsctx.New("b1", dsctx.DefaultParseLimits())
	CheckTenantRate(ctxB1, tenantB, salt, 1)
	if ctxA1.MatchCount() != 0 || ctxB1.MatchCount() != 0 {
		t.Fatalf("first request for distinct tenants must stay independent: a=%+v b=%+v", ctxA1.CopyMatches(), ctxB1.CopyMatches())
	}
	ctxA2 := dsctx.New("a2", dsctx.DefaultParseLimits())
	CheckTenantRate(ctxA2, tenantA, salt, 1)
	m := findMatch(ctxA2, "ratelimit.tenant_rate")
	if m == nil || m.Evidence["window_count"] != "2" {
		t.Fatalf("second request for tenant A must exceed only its own limit: %+v", ctxA2.CopyMatches())
	}
}
