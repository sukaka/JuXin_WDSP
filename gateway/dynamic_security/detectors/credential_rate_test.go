package detectors

import (
	"reflect"
	"sync"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func isolateCredentialRateTrackerForTest(t *testing.T, capacity int, now func() time.Time) *windowTracker {
	t.Helper()
	tracker := newWindowTracker(capacity, now)
	previous := defaultCredentialRateTracker
	defaultCredentialRateTracker = tracker
	t.Cleanup(func() {
		defaultCredentialRateTracker = previous
	})
	return tracker
}

func TestCheckCredentialRate_CredentialTypesAndThreshold(t *testing.T) {
	tests := []struct {
		name     string
		credKey  string
		credType string
	}{
		{name: "authorization", credKey: "auth:authorization-fingerprint", credType: "AUTHORIZATION"},
		{name: "api key", credKey: "key:api-key-fingerprint", credType: "API_KEY"},
		{name: "session", credKey: "sess:session-fingerprint", credType: "SESSION"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isolateCredentialRateTrackerForTest(t, 16, nil)
			const limit = 2
			for hit := 1; hit <= limit; hit++ {
				ctx := dsctx.New("t", dsctx.DefaultParseLimits())
				CheckCredentialRate(ctx, tc.credKey, limit)
				if ctx.MatchCount() != 0 {
					t.Fatalf("hit %d at/below limit must not match: %+v", hit, ctx.CopyMatches())
				}
			}

			ctx := dsctx.New("t", dsctx.DefaultParseLimits())
			CheckCredentialRate(ctx, tc.credKey, limit)
			matches := ctx.CopyMatches()
			if len(matches) != 1 {
				t.Fatalf("hit limit+1 must produce exactly one match: %+v", matches)
			}
			m := findMatch(ctx, "ratelimit.credential_rate")
			if m == nil {
				t.Fatalf("credential rate rule missing: %+v", matches)
			}
			if m.Detector != "api_ratelimit" || m.Category != "RATE_LIMIT" || m.Severity != "HIGH" || m.ScoreDelta != 30 {
				t.Fatalf("bad match attributes: %+v", m)
			}
			wantEvidence := map[string]string{
				"credential_type": tc.credType,
				"window_count":    "3",
				"limit":           "2",
				"window":          "1m",
			}
			if !reflect.DeepEqual(m.Evidence, wantEvidence) {
				t.Fatalf("evidence must contain only the allowlisted fields: got %+v, want %+v", m.Evidence, wantEvidence)
			}
		})
	}
}

func TestCheckCredentialRate_NaturalMinuteReset(t *testing.T) {
	now := time.Date(2026, 11, 15, 10, 0, 59, 0, time.UTC)
	isolateCredentialRateTrackerForTest(t, 16, func() time.Time { return now })
	const credKey = "auth:window-reset-fingerprint"

	for hit := 1; hit <= 2; hit++ {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckCredentialRate(ctx, credKey, 1)
		if (hit == 1 && ctx.MatchCount() != 0) || (hit == 2 && ctx.MatchCount() != 1) {
			t.Fatalf("unexpected match count at hit %d: %+v", hit, ctx.CopyMatches())
		}
	}

	now = now.Add(2 * time.Second)
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckCredentialRate(ctx, credKey, 1)
	if ctx.MatchCount() != 0 {
		t.Fatalf("first request in next natural minute must not match: %+v", ctx.CopyMatches())
	}
	ctx = dsctx.New("t", dsctx.DefaultParseLimits())
	CheckCredentialRate(ctx, credKey, 1)
	m := findMatch(ctx, "ratelimit.credential_rate")
	if m == nil || m.Evidence["window_count"] != "2" {
		t.Fatalf("new window must restart counting from one: %+v", ctx.CopyMatches())
	}
}

func TestCheckCredentialRate_SkipsAnonymousUnknownAndDisabled(t *testing.T) {
	tracker := isolateCredentialRateTrackerForTest(t, 16, nil)
	CheckCredentialRate(nil, "auth:nil-context", 1)

	for _, credKey := range []string{"", "ip:192.0.2.1", "unknown:fingerprint", "authorization:fingerprint", "auth:", "key:", "sess:"} {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		for hit := 0; hit < 2; hit++ {
			CheckCredentialRate(ctx, credKey, 1)
		}
		if ctx.MatchCount() != 0 {
			t.Fatalf("anonymous or unsupported credential key %q must skip: %+v", credKey, ctx.CopyMatches())
		}
	}
	for _, limit := range []int{0, -1} {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		for hit := 0; hit < 2; hit++ {
			CheckCredentialRate(ctx, "auth:disabled", limit)
		}
		if ctx.MatchCount() != 0 {
			t.Fatalf("non-positive limit %d must disable detection: %+v", limit, ctx.CopyMatches())
		}
	}
	if got := len(tracker.entries.items); got != 0 {
		t.Fatalf("skipped requests must not create tracker state, got %d entries", got)
	}
}

func TestCheckCredentialRate_BoundedCapacity(t *testing.T) {
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	tracker := isolateCredentialRateTrackerForTest(t, 2, func() time.Time { return now })

	CheckCredentialRate(dsctx.New("t", dsctx.DefaultParseLimits()), "auth:a", 1)
	overLimit := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckCredentialRate(overLimit, "auth:a", 1)
	if overLimit.MatchCount() != 1 {
		t.Fatalf("second request for auth:a must exceed limit: %+v", overLimit.CopyMatches())
	}
	CheckCredentialRate(dsctx.New("t", dsctx.DefaultParseLimits()), "key:b", 1)
	CheckCredentialRate(dsctx.New("t", dsctx.DefaultParseLimits()), "sess:c", 1)
	if got := len(tracker.entries.items); got != 2 {
		t.Fatalf("tracker must remain bounded at capacity 2, got %d", got)
	}

	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckCredentialRate(ctx, "auth:a", 1)
	if ctx.MatchCount() != 0 {
		t.Fatalf("evicted credential must restart at count one: %+v", ctx.CopyMatches())
	}
}

func TestCheckCredentialRate_ConcurrentCounting(t *testing.T) {
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	tracker := isolateCredentialRateTrackerForTest(t, 16, func() time.Time { return now })
	const (
		workers       = 12
		hitsPerWorker = 20
		limit         = 100
		credKey       = "auth:concurrent-fingerprint"
	)
	contexts := make([]*dsctx.RequestContext, workers*hitsPerWorker)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for hit := 0; hit < hitsPerWorker; hit++ {
				index := worker*hitsPerWorker + hit
				ctx := dsctx.New("t", dsctx.DefaultParseLimits())
				contexts[index] = ctx
				CheckCredentialRate(ctx, credKey, limit)
			}
		}(worker)
	}
	wg.Wait()

	matched := 0
	for _, ctx := range contexts {
		if findMatch(ctx, "ratelimit.credential_rate") != nil {
			matched++
		} else if ctx.MatchCount() != 0 {
			t.Fatalf("unexpected match: %+v", ctx.CopyMatches())
		}
	}
	if want := workers*hitsPerWorker - limit; matched != want {
		t.Fatalf("concurrent counting lost or duplicated hits: got %d matches, want %d", matched, want)
	}
	if count, _ := tracker.add(credKey); count != workers*hitsPerWorker+1 {
		t.Fatalf("final count = %d, want %d", count, workers*hitsPerWorker+1)
	}
}
