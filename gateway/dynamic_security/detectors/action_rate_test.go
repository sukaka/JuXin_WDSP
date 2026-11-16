package detectors

import (
	"reflect"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func isolateActionRateTrackerForTest(t *testing.T, capacity int, now func() time.Time) *windowTracker {
	t.Helper()
	tracker := newWindowTracker(capacity, now)
	previous := defaultActionRateTracker
	defaultActionRateTracker = tracker
	t.Cleanup(func() { defaultActionRateTracker = previous })
	return tracker
}

func TestCheckActionRateThresholdNormalizationAndEvidence(t *testing.T) {
	tracker := isolateActionRateTrackerForTest(t, 16, nil)
	const app = "app-action-threshold"
	for hit := 1; hit <= 2; hit++ {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckActionRate(ctx, app, "  read_detail\t", 2)
		if ctx.MatchCount() != 0 {
			t.Fatalf("hit %d at/below limit must not match: %+v", hit, ctx.CopyMatches())
		}
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckActionRate(ctx, app, "READ_DETAIL", 2)
	matches := ctx.CopyMatches()
	if len(matches) != 1 {
		t.Fatalf("N+1 must produce one match: %+v", matches)
	}
	m := matches[0]
	if m.Detector != "api_ratelimit" || m.RuleID != "ratelimit.action_rate" || m.Category != "RATE_LIMIT" || m.Severity != "HIGH" {
		t.Fatalf("bad action rate attributes: %+v", m)
	}
	wantEvidence := map[string]string{"action": "READ_DETAIL", "window_count": "3", "limit": "2", "window": "1m"}
	if !reflect.DeepEqual(m.Evidence, wantEvidence) {
		t.Fatalf("evidence boundary: got %+v want %+v", m.Evidence, wantEvidence)
	}
	if _, ok := tracker.entries.get(app + "|READ_DETAIL"); !ok {
		t.Fatalf("normalized application/action key missing: %+v", tracker.entries.items)
	}
}

func TestCheckActionRateSkipsBlankAndDisabled(t *testing.T) {
	tracker := isolateActionRateTrackerForTest(t, 16, nil)
	CheckActionRate(nil, "app", "READ_DETAIL", 1)
	for _, tc := range []struct {
		app    string
		action string
		limit  int
	}{
		{app: " ", action: "READ_DETAIL", limit: 1},
		{app: "app", action: "\t", limit: 1},
		{app: "app", action: "READ_DETAIL", limit: 0},
		{app: "app", action: "READ_DETAIL", limit: -1},
	} {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		for hit := 0; hit < 2; hit++ {
			CheckActionRate(ctx, tc.app, tc.action, tc.limit)
		}
		if ctx.MatchCount() != 0 {
			t.Fatalf("blank or disabled input must skip: %+v", ctx.CopyMatches())
		}
	}
	if len(tracker.entries.items) != 0 {
		t.Fatal("skipped action requests must not create counter state")
	}
}

func TestCheckActionRateIsolatesApplicationsAndActions(t *testing.T) {
	isolateActionRateTrackerForTest(t, 16, nil)
	ctx := dsctx.New("a1", dsctx.DefaultParseLimits())
	CheckActionRate(ctx, "app-a", "READ_DETAIL", 1)
	ctx = dsctx.New("a2", dsctx.DefaultParseLimits())
	CheckActionRate(ctx, "app-a", "read_detail", 1)
	if findMatch(ctx, "ratelimit.action_rate") == nil {
		t.Fatal("second request for app/action must exceed")
	}
	for _, tc := range []struct {
		app    string
		action string
	}{
		{app: "app-b", action: "READ_DETAIL"},
		{app: "app-a", action: "DELETE"},
	} {
		ctx := dsctx.New("isolated", dsctx.DefaultParseLimits())
		CheckActionRate(ctx, tc.app, tc.action, 1)
		if ctx.MatchCount() != 0 {
			t.Fatalf("different app/action must not share counter: %+v", ctx.CopyMatches())
		}
	}
}

func TestStoreOverrides_ActionRateWindowRouted(t *testing.T) {
	tracker := isolateActionRateTrackerForTest(t, 16, nil)
	fake := &fakeWindowStore{count: 2}
	ctx := contextWithOverrides(&StoreOverrides{ActionRateWindow: fake})
	CheckActionRate(ctx, "app-override", "read_detail", 1)
	wantKey := "app-override|READ_DETAIL"
	if len(fake.calls) != 1 || fake.calls[0] != wantKey {
		t.Fatalf("action rate override not used: %v", fake.calls)
	}
	m := findMatch(ctx, "ratelimit.action_rate")
	if m == nil || m.Evidence["window_count"] != "2" {
		t.Fatalf("override count must drive action match: %+v", ctx.CopyMatches())
	}
	if _, ok := tracker.entries.get(wantKey); ok {
		t.Fatal("default action tracker must not be touched when override set")
	}
}

func TestStoreOverrides_ActionRateWindowMemoryDefaults(t *testing.T) {
	bindings := []struct {
		name string
		bind func(*dsctx.RequestContext)
	}{
		{name: "unbound", bind: func(*dsctx.RequestContext) {}},
		{name: "nil field", bind: func(ctx *dsctx.RequestContext) {
			ctx.BindDetectorStoreOverrides(&StoreOverrides{})
		}},
		{name: "cleared", bind: func(ctx *dsctx.RequestContext) {
			ctx.BindDetectorStoreOverrides(&StoreOverrides{ActionRateWindow: &fakeWindowStore{count: 2}})
			ctx.BindDetectorStoreOverrides(nil)
		}},
	}
	for _, binding := range bindings {
		t.Run(binding.name, func(t *testing.T) {
			tracker := isolateActionRateTrackerForTest(t, 16, nil)
			const key = "app-default|READ_DETAIL"
			ctx := dsctx.New("t", dsctx.DefaultParseLimits())
			binding.bind(ctx)
			count, history := actionRateCounts(ctx, key)
			if count != 1 || len(history) != 0 {
				t.Fatalf("default first hit: count=%d history=%v", count, history)
			}
			if _, ok := tracker.entries.get(key); !ok {
				t.Fatal("default action tracker must be used")
			}
		})
	}
}

func TestActionRateCounts_DefaultWindowAndCapacity(t *testing.T) {
	now := time.Date(2026, 11, 15, 10, 0, 30, 0, time.UTC)
	tracker := isolateActionRateTrackerForTest(t, 2, func() time.Time { return now })
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	actionRateCounts(ctx, "app-a|READ_DETAIL")
	if count, _ := actionRateCounts(ctx, "app-a|READ_DETAIL"); count != 2 {
		t.Fatalf("same window second hit: %d", count)
	}
	now = now.Add(31 * time.Second)
	if count, history := actionRateCounts(ctx, "app-a|READ_DETAIL"); count != 1 || len(history) != 1 || history[0] != 2 {
		t.Fatalf("natural minute roll: count=%d history=%v", count, history)
	}
	actionRateCounts(ctx, "app-a|DELETE")
	actionRateCounts(ctx, "app-b|READ_DETAIL")
	if len(tracker.entries.items) != 2 {
		t.Fatal("default action tracker must remain bounded")
	}
	if count, history := actionRateCounts(ctx, "app-a|READ_DETAIL"); count != 1 || len(history) != 0 {
		t.Fatalf("evicted action key must restart: count=%d history=%v", count, history)
	}
}
