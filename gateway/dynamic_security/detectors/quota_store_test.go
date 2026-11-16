package detectors

import (
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

type fakeQuotaStore struct {
	calls []string
	count int
}

func (f *fakeQuotaStore) AddAndCount(key string) int {
	f.calls = append(f.calls, key)
	return f.count
}

func isolateQuotaTrackersForTest(t *testing.T) (*fixedWindowTracker, *fixedWindowTracker) {
	t.Helper()
	hourly := newFixedWindowTracker(time.Hour, quotaMaxKeys, nil)
	daily := newFixedWindowTracker(24*time.Hour, quotaMaxKeys, nil)
	previousHourly, previousDaily := defaultHourlyQuotaTracker, defaultDailyQuotaTracker
	defaultHourlyQuotaTracker, defaultDailyQuotaTracker = hourly, daily
	t.Cleanup(func() {
		defaultHourlyQuotaTracker = previousHourly
		defaultDailyQuotaTracker = previousDaily
	})
	return hourly, daily
}

func TestStoreOverrides_HourlyQuotaRouted(t *testing.T) {
	hourly, _ := isolateQuotaTrackersForTest(t)
	fake := &fakeQuotaStore{count: 4}
	const identity, endpoint = "auth:hourly-override", "GET /v1/orders"
	ctx := contextWithOverrides(&StoreOverrides{HourlyQuota: fake})
	CheckAPIHourlyQuota(ctx, identity, endpoint, 3)
	wantKey := identity + "|" + endpoint
	if len(fake.calls) != 1 || fake.calls[0] != wantKey {
		t.Fatalf("hourly quota override not used: %v", fake.calls)
	}
	m := findMatch(ctx, "ratelimit.api_hourly_quota")
	if m == nil || m.Evidence["window_count"] != "4" {
		t.Fatalf("override count must drive hourly quota match: %+v", ctx.CopyMatches())
	}
	if _, ok := hourly.entries.get(wantKey); ok {
		t.Fatal("default hourly quota tracker must not be touched when override set")
	}
}

func TestStoreOverrides_DailyQuotaRouted(t *testing.T) {
	_, daily := isolateQuotaTrackersForTest(t)
	fake := &fakeQuotaStore{count: 4}
	const identity, endpoint = "auth:daily-override", "GET /v1/orders"
	ctx := contextWithOverrides(&StoreOverrides{DailyQuota: fake})
	CheckAPIDailyQuota(ctx, identity, endpoint, 3)
	wantKey := identity + "|" + endpoint
	if len(fake.calls) != 1 || fake.calls[0] != wantKey {
		t.Fatalf("daily quota override not used: %v", fake.calls)
	}
	m := findMatch(ctx, "ratelimit.api_daily_quota")
	if m == nil || m.Evidence["window_count"] != "4" {
		t.Fatalf("override count must drive daily quota match: %+v", ctx.CopyMatches())
	}
	if _, ok := daily.entries.get(wantKey); ok {
		t.Fatal("default daily quota tracker must not be touched when override set")
	}
}

func TestStoreOverrides_QuotaMemoryDefaults(t *testing.T) {
	bindings := []struct {
		name string
		bind func(*dsctx.RequestContext)
	}{
		{name: "unbound", bind: func(*dsctx.RequestContext) {}},
		{name: "nil field", bind: func(ctx *dsctx.RequestContext) {
			ctx.BindDetectorStoreOverrides(&StoreOverrides{})
		}},
		{name: "cleared", bind: func(ctx *dsctx.RequestContext) {
			ctx.BindDetectorStoreOverrides(&StoreOverrides{
				HourlyQuota: &fakeQuotaStore{count: 2},
				DailyQuota:  &fakeQuotaStore{count: 2},
			})
			ctx.BindDetectorStoreOverrides(nil)
		}},
	}
	quotaChecks := []struct {
		name  string
		key   string
		check func(*dsctx.RequestContext)
	}{
		{name: "hourly", key: "auth:hourly-default|GET /v1/orders", check: func(ctx *dsctx.RequestContext) {
			CheckAPIHourlyQuota(ctx, "auth:hourly-default", "GET /v1/orders", 1)
		}},
		{name: "daily", key: "auth:daily-default|GET /v1/orders", check: func(ctx *dsctx.RequestContext) {
			CheckAPIDailyQuota(ctx, "auth:daily-default", "GET /v1/orders", 1)
		}},
	}
	for _, quota := range quotaChecks {
		for _, binding := range bindings {
			t.Run(quota.name+"/"+binding.name, func(t *testing.T) {
				hourly, daily := isolateQuotaTrackersForTest(t)
				ctx := dsctx.New("t", dsctx.DefaultParseLimits())
				binding.bind(ctx)
				quota.check(ctx)
				tracker := hourly
				if quota.name == "daily" {
					tracker = daily
				}
				if _, ok := tracker.entries.get(quota.key); !ok {
					t.Fatal("default quota tracker must be used")
				}
				if ctx.MatchCount() != 0 {
					t.Fatalf("first default-memory hit must not exceed limit: %+v", ctx.CopyMatches())
				}
			})
		}
	}
}

func TestMemoryQuotaStore_NaturalWindows(t *testing.T) {
	now := time.Date(2026, 9, 11, 10, 30, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	hourly := NewMemoryQuotaStore(time.Hour, 0, clock)
	daily := NewMemoryQuotaStore(24*time.Hour, 0, clock)
	const key = "auth:memory-quota|GET /v1/orders"
	if hourly.AddAndCount(key) != 1 || daily.AddAndCount(key) != 1 {
		t.Fatal("first hourly/daily hit must start at one")
	}
	if hourly.AddAndCount(key) != 2 || daily.AddAndCount(key) != 2 {
		t.Fatal("same windows must accumulate")
	}
	now = time.Date(2026, 9, 11, 11, 0, 0, 0, time.UTC)
	if count := hourly.AddAndCount(key); count != 1 {
		t.Fatalf("natural hour must reset hourly quota: %d", count)
	}
	if count := daily.AddAndCount(key); count != 3 {
		t.Fatalf("hour rollover must not reset daily quota: %d", count)
	}
	now = time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	if count := hourly.AddAndCount(key); count != 1 {
		t.Fatalf("new hour must reset hourly quota: %d", count)
	}
	if count := daily.AddAndCount(key); count != 1 {
		t.Fatalf("UTC day rollover must reset daily quota: %d", count)
	}
}
