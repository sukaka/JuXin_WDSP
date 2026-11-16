package detectors

import (
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

func isolateTenantRateStoreTrackerForTest(t *testing.T, capacity int, now func() time.Time) *windowTracker {
	t.Helper()
	tracker := newWindowTracker(capacity, now)
	previous := defaultTenantRateTracker
	defaultTenantRateTracker = tracker
	t.Cleanup(func() { defaultTenantRateTracker = previous })
	return tracker
}

func TestStoreOverrides_TenantRateWindowRouted(t *testing.T) {
	tracker := isolateTenantRateStoreTrackerForTest(t, 16, nil)
	fake := &fakeWindowStore{count: 3, hist: []int{2}}
	const (
		tenant = "tenant-secret-override"
		salt   = "tenant-rate-override-salt"
	)
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedTenantID: tenant}
	ctx := contextWithOverrides(&StoreOverrides{TenantRateWindow: fake})
	CheckTenantRate(ctx, jwt, salt, 2)
	wantKey := Fingerprint(salt, "jwt-tenant:"+tenant)
	if len(fake.calls) != 1 || fake.calls[0] != wantKey {
		t.Fatalf("tenant rate override must receive only the salted fingerprint: %v", fake.calls)
	}
	m := findMatch(ctx, "ratelimit.tenant_rate")
	if m == nil || m.Evidence["window_count"] != "3" {
		t.Fatalf("override count must drive tenant rate match: %+v", ctx.CopyMatches())
	}
	if _, ok := tracker.entries.get(wantKey); ok {
		t.Fatal("default tenant rate tracker must not be touched when override set")
	}
}

func TestStoreOverrides_TenantRateWindowMemoryDefaults(t *testing.T) {
	bindings := []struct {
		name string
		bind func(*dsctx.RequestContext)
	}{
		{name: "unbound", bind: func(*dsctx.RequestContext) {}},
		{name: "nil field", bind: func(ctx *dsctx.RequestContext) {
			ctx.BindDetectorStoreOverrides(&StoreOverrides{})
		}},
		{name: "cleared", bind: func(ctx *dsctx.RequestContext) {
			ctx.BindDetectorStoreOverrides(&StoreOverrides{TenantRateWindow: &fakeWindowStore{count: 2}})
			ctx.BindDetectorStoreOverrides(nil)
		}},
	}
	for _, binding := range bindings {
		t.Run(binding.name, func(t *testing.T) {
			tracker := isolateTenantRateStoreTrackerForTest(t, 16, nil)
			const key = "tenant:default-tenant-fingerprint"
			ctx := dsctx.New("t", dsctx.DefaultParseLimits())
			binding.bind(ctx)
			count, history := tenantRateCounts(ctx, key)
			if count != 1 || len(history) != 0 {
				t.Fatalf("default first hit: count=%d history=%v", count, history)
			}
			if _, ok := tracker.entries.get(key); !ok {
				t.Fatal("default tenant rate tracker must be used")
			}
		})
	}
}

func TestTenantRateCounts_DefaultWindowAndCapacity(t *testing.T) {
	now := time.Date(2026, 11, 15, 10, 0, 30, 0, time.UTC)
	tracker := isolateTenantRateStoreTrackerForTest(t, 2, func() time.Time { return now })
	const key = "tenant:window-a"
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	if count, _ := tenantRateCounts(ctx, key); count != 1 {
		t.Fatalf("first hit: %d", count)
	}
	if count, _ := tenantRateCounts(ctx, key); count != 2 {
		t.Fatalf("same window second hit: %d", count)
	}
	now = now.Add(31 * time.Second)
	if count, history := tenantRateCounts(ctx, key); count != 1 || len(history) != 1 || history[0] != 2 {
		t.Fatalf("natural minute roll: count=%d history=%v", count, history)
	}
	tenantRateCounts(ctx, "tenant:window-b")
	tenantRateCounts(ctx, "tenant:window-c")
	if got := len(tracker.entries.items); got != 2 {
		t.Fatalf("tenant tracker must remain bounded at two keys, got %d", got)
	}
	if count, history := tenantRateCounts(ctx, key); count != 1 || len(history) != 0 {
		t.Fatalf("evicted tenant key must restart without history: count=%d history=%v", count, history)
	}
}
