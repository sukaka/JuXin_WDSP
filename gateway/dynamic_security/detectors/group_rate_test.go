package detectors

import (
	"reflect"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func isolateGroupRateTrackerForTest(t *testing.T, capacity int, now func() time.Time) *windowTracker {
	t.Helper()
	tracker := newWindowTracker(capacity, now)
	previous := defaultGroupRateTracker
	defaultGroupRateTracker = tracker
	t.Cleanup(func() { defaultGroupRateTracker = previous })
	return tracker
}

func TestCheckGroupRateThresholdNormalizationAndEvidence(t *testing.T) {
	tracker := isolateGroupRateTrackerForTest(t, 16, nil)
	const app = "app-group-threshold"
	for hit := 1; hit <= 2; hit++ {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckGroupRate(ctx, app, "  order_query\t", 2)
		if ctx.MatchCount() != 0 {
			t.Fatalf("hit %d at/below limit must not match: %+v", hit, ctx.CopyMatches())
		}
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckGroupRate(ctx, app, "ORDER_QUERY", 2)
	matches := ctx.CopyMatches()
	if len(matches) != 1 {
		t.Fatalf("N+1 must produce one match: %+v", matches)
	}
	m := matches[0]
	if m.Detector != "api_ratelimit" || m.RuleID != "ratelimit.group_rate" || m.Category != "RATE_LIMIT" || m.Severity != "HIGH" {
		t.Fatalf("bad group rate attributes: %+v", m)
	}
	wantEvidence := map[string]string{"group_code": "ORDER_QUERY", "window_count": "3", "limit": "2", "window": "1m"}
	if !reflect.DeepEqual(m.Evidence, wantEvidence) {
		t.Fatalf("evidence boundary: got %+v want %+v", m.Evidence, wantEvidence)
	}
	if _, ok := tracker.entries.get(app + "|ORDER_QUERY"); !ok {
		t.Fatalf("normalized application/group key missing: %+v", tracker.entries.items)
	}
}

func TestCheckGroupRateSkipsBlankAndDisabled(t *testing.T) {
	tracker := isolateGroupRateTrackerForTest(t, 16, nil)
	CheckGroupRate(nil, "app", "ORDER_QUERY", 1)
	for _, tc := range []struct {
		app   string
		group string
		limit int
	}{
		{app: " ", group: "ORDER_QUERY", limit: 1},
		{app: "app", group: "\t", limit: 1},
		{app: "app", group: "ORDER_QUERY", limit: 0},
		{app: "app", group: "ORDER_QUERY", limit: -1},
	} {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		for hit := 0; hit < 2; hit++ {
			CheckGroupRate(ctx, tc.app, tc.group, tc.limit)
		}
		if ctx.MatchCount() != 0 {
			t.Fatalf("blank or disabled input must skip: %+v", ctx.CopyMatches())
		}
	}
	if len(tracker.entries.items) != 0 {
		t.Fatal("skipped group requests must not create counter state")
	}
}

func TestCheckGroupRateIsolatesApplicationsAndGroups(t *testing.T) {
	isolateGroupRateTrackerForTest(t, 16, nil)
	ctx := dsctx.New("a1", dsctx.DefaultParseLimits())
	CheckGroupRate(ctx, "app-a", "ORDER_QUERY", 1)
	ctx = dsctx.New("a2", dsctx.DefaultParseLimits())
	CheckGroupRate(ctx, "app-a", "order_query", 1)
	if findMatch(ctx, "ratelimit.group_rate") == nil {
		t.Fatal("second request for app/group must exceed")
	}
	for _, tc := range []struct{ app, group string }{
		{app: "app-b", group: "ORDER_QUERY"},
		{app: "app-a", group: "ORDER_WRITE"},
	} {
		ctx := dsctx.New("isolated", dsctx.DefaultParseLimits())
		CheckGroupRate(ctx, tc.app, tc.group, 1)
		if ctx.MatchCount() != 0 {
			t.Fatalf("different app/group must not share counter: %+v", ctx.CopyMatches())
		}
	}
}

func TestStoreOverrides_GroupRateWindowRouted(t *testing.T) {
	tracker := isolateGroupRateTrackerForTest(t, 16, nil)
	fake := &fakeWindowStore{count: 2}
	ctx := contextWithOverrides(&StoreOverrides{GroupRateWindow: fake})
	CheckGroupRate(ctx, "app-override", "order_query", 1)
	wantKey := "app-override|ORDER_QUERY"
	if len(fake.calls) != 1 || fake.calls[0] != wantKey {
		t.Fatalf("group rate override not used: %v", fake.calls)
	}
	m := findMatch(ctx, "ratelimit.group_rate")
	if m == nil || m.Evidence["window_count"] != "2" {
		t.Fatalf("override count must drive group match: %+v", ctx.CopyMatches())
	}
	if _, ok := tracker.entries.get(wantKey); ok {
		t.Fatal("default group tracker must not be touched when override set")
	}
}

func TestStoreOverrides_GroupRateWindowMemoryDefaults(t *testing.T) {
	bindings := []struct {
		name string
		bind func(*dsctx.RequestContext)
	}{
		{name: "unbound", bind: func(*dsctx.RequestContext) {}},
		{name: "nil field", bind: func(ctx *dsctx.RequestContext) {
			ctx.BindDetectorStoreOverrides(&StoreOverrides{})
		}},
		{name: "cleared", bind: func(ctx *dsctx.RequestContext) {
			ctx.BindDetectorStoreOverrides(&StoreOverrides{GroupRateWindow: &fakeWindowStore{count: 2}})
			ctx.BindDetectorStoreOverrides(nil)
		}},
	}
	for _, binding := range bindings {
		t.Run(binding.name, func(t *testing.T) {
			tracker := isolateGroupRateTrackerForTest(t, 16, nil)
			const key = "app-default|ORDER_QUERY"
			ctx := dsctx.New("t", dsctx.DefaultParseLimits())
			binding.bind(ctx)
			count, history := groupRateCounts(ctx, key)
			if count != 1 || len(history) != 0 {
				t.Fatalf("default first hit: count=%d history=%v", count, history)
			}
			if _, ok := tracker.entries.get(key); !ok {
				t.Fatal("default group tracker must be used")
			}
		})
	}
}

func TestGroupRateCounts_DefaultWindowAndCapacity(t *testing.T) {
	now := time.Date(2026, 11, 16, 10, 0, 30, 0, time.UTC)
	tracker := isolateGroupRateTrackerForTest(t, 2, func() time.Time { return now })
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	groupRateCounts(ctx, "app-a|ORDER_QUERY")
	if count, _ := groupRateCounts(ctx, "app-a|ORDER_QUERY"); count != 2 {
		t.Fatalf("same window second hit: %d", count)
	}
	now = now.Add(31 * time.Second)
	if count, history := groupRateCounts(ctx, "app-a|ORDER_QUERY"); count != 1 || len(history) != 1 || history[0] != 2 {
		t.Fatalf("natural minute roll: count=%d history=%v", count, history)
	}
	groupRateCounts(ctx, "app-a|ORDER_WRITE")
	groupRateCounts(ctx, "app-b|ORDER_QUERY")
	if len(tracker.entries.items) != 2 {
		t.Fatal("default group tracker must remain bounded")
	}
	if count, history := groupRateCounts(ctx, "app-a|ORDER_QUERY"); count != 1 || len(history) != 0 {
		t.Fatalf("evicted group key must restart: count=%d history=%v", count, history)
	}
}
