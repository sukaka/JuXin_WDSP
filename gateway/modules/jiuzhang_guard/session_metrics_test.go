package jiuzhang_guard

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestSessionTrackerLifecycleAndBounds(t *testing.T) {
	tracker := newSessionTracker(time.Minute, 2)
	now := time.Now().UTC()
	names := map[string]struct{}{"JSESSIONID": {}}
	observe := func(value string, at time.Time) {
		r := httptest.NewRequest("GET", "http://example.com/", nil)
		r.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: value})
		tracker.observe(r, "app-1", names, at)
	}

	observe("session-a", now)
	observe("session-a", now.Add(time.Second))
	active, newTotal, overflow := tracker.snapshot(now.Add(2 * time.Second))
	if active != 1 || newTotal != 1 || overflow != 0 {
		t.Fatalf("duplicate session metrics = active %d, new %d, overflow %d", active, newTotal, overflow)
	}
	observe("session-b", now.Add(2*time.Second))
	observe("session-c", now.Add(3*time.Second))
	active, newTotal, overflow = tracker.snapshot(now.Add(4 * time.Second))
	if active != 2 || newTotal != 2 || overflow != 1 {
		t.Fatalf("bounded session metrics = active %d, new %d, overflow %d", active, newTotal, overflow)
	}

	active, _, _ = tracker.snapshot(now.Add(2 * time.Minute))
	if active != 0 {
		t.Fatalf("active after idle expiry = %d, want 0", active)
	}
	observe("session-a", now.Add(2*time.Minute))
	_, newTotal, _ = tracker.snapshot(now.Add(2 * time.Minute))
	if newTotal != 3 {
		t.Fatalf("new_total after expired session returns = %d, want 3", newTotal)
	}
}

func TestSessionTrackerScopesApplicationsAndIgnoresUnconfiguredCookies(t *testing.T) {
	tracker := newSessionTracker(time.Minute, 10)
	now := time.Now().UTC()
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: "shared-value"})
	r.AddCookie(&http.Cookie{Name: "OTHER", Value: "ignored"})
	names := map[string]struct{}{"JSESSIONID": {}}
	tracker.observe(r, "app-1", names, now)
	tracker.observe(r, "app-2", names, now)
	active, newTotal, _ := tracker.snapshot(now)
	if active != 2 || newTotal != 2 {
		t.Fatalf("application-scoped metrics = active %d, new %d, want 2/2", active, newTotal)
	}
}

func TestSessionTrackerHighCardinalityStaysBounded(t *testing.T) {
	const (
		capacity     = 128
		observations = 4096
	)
	tracker := newSessionTracker(time.Minute, capacity)
	now := time.Now().UTC()
	names := map[string]struct{}{"JSESSIONID": {}}
	for i := 0; i < observations; i++ {
		request := httptest.NewRequest("GET", "http://example.com/", nil)
		request.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: fmt.Sprintf("session-%d", i)})
		tracker.observe(request, "cardinal-app", names, now)
	}
	active, newTotal, overflow := tracker.snapshot(now)
	if active != capacity || newTotal != capacity || overflow != observations-capacity {
		t.Fatalf("high-cardinality metrics = active %d, new %d, overflow %d", active, newTotal, overflow)
	}
	if tracked := tracker.tracked.Load(); tracked != capacity {
		t.Fatalf("tracked entries = %d, want hard cap %d", tracked, capacity)
	}
}

func TestSessionTrackerNewSessionPruneWorkIsBounded(t *testing.T) {
	tracker := newSessionTracker(time.Minute, sessionTrackerShardCount)
	now := time.Now().UTC()
	for i := 0; i < sessionTrackerShardCount; i++ {
		tracker.track(sessionKey{1: byte(i)}, now)
	}
	tracker.track(sessionKey{1: 255}, now.Add(2*time.Minute))
	const wantTracked = sessionTrackerShardCount - sessionTrackerPruneBatchPerCall + 1
	if got := tracker.tracked.Load(); got != wantTracked {
		t.Fatalf("entries after bounded prune and admission = %d, want %d", got, wantTracked)
	}
	if got := tracker.overflowTotal.Load(); got != 0 {
		t.Fatalf("overflow_total = %d, want 0 after expired capacity was released", got)
	}
	active, _, _ := tracker.snapshot(now.Add(2 * time.Minute))
	if active != 1 || tracker.tracked.Load() != 1 {
		t.Fatalf("cold path must retain only the newly admitted session: active=%d tracked=%d", active, tracker.tracked.Load())
	}
}

func TestSessionTrackerConcurrentObservations(t *testing.T) {
	const (
		workers       = 16
		keysPerWorker = 200
		capacity      = 257
	)
	tracker := newSessionTracker(time.Minute, capacity)
	now := time.Now().UTC()
	names := map[string]struct{}{"JSESSIONID": {}}
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for round := 0; round < 2; round++ {
				for key := 0; key < keysPerWorker; key++ {
					request := httptest.NewRequest("GET", "http://example.com/", nil)
					request.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: fmt.Sprintf("session-%d-%d", worker, key)})
					tracker.observe(request, "concurrent-app", names, now)
				}
			}
		}(worker)
	}
	wg.Wait()
	active, newTotal, overflow := tracker.snapshot(now)
	uniqueKeys := workers * keysPerWorker
	if active != capacity || newTotal != capacity || tracker.tracked.Load() != capacity {
		t.Fatalf("concurrent bound = active %d, new %d, tracked %d, want %d", active, newTotal, tracker.tracked.Load(), capacity)
	}
	wantOverflow := uint64(2 * (uniqueKeys - capacity))
	if overflow != wantOverflow {
		t.Fatalf("overflow_total = %d, want %d (overflow is per observation)", overflow, wantOverflow)
	}
}
