package protectedaddresses

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeRefreshStore struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *fakeRefreshStore) Refresh(ctx context.Context) (int, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return 0, 0, f.err
}

func (f *fakeRefreshStore) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestRefreshIntervalFromEnv(t *testing.T) {
	if got := RefreshIntervalFromEnv(func(string) string { return "" }); got != DefaultRefreshInterval {
		t.Fatalf("empty env: got %v", got)
	}
	if got := RefreshIntervalFromEnv(func(string) string { return "not-a-duration" }); got != DefaultRefreshInterval {
		t.Fatalf("invalid env: got %v", got)
	}
	if got := RefreshIntervalFromEnv(func(string) string { return "-5m" }); got != DefaultRefreshInterval {
		t.Fatalf("non-positive env: got %v", got)
	}
	if got := RefreshIntervalFromEnv(func(string) string { return "30m" }); got != 30*time.Minute {
		t.Fatalf("valid env: got %v", got)
	}
}

func TestNewRefresherIntervalFallback(t *testing.T) {
	r := NewRefresher(&fakeRefreshStore{}, 0)
	if r.Interval() != DefaultRefreshInterval {
		t.Fatalf("zero interval: got %v", r.Interval())
	}
	r = NewRefresher(&fakeRefreshStore{}, 15*time.Minute)
	if r.Interval() != 15*time.Minute {
		t.Fatalf("explicit interval: got %v", r.Interval())
	}
}

func TestRefresherRunStartsStopsAndSurvivesFailure(t *testing.T) {
	store := &fakeRefreshStore{err: errors.New("db down")}
	r := NewRefresher(store, 10*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()

	// 启动时立即刷新一次，之后按周期刷新；即使每次失败循环也不退出
	deadline := time.Now().Add(2 * time.Second)
	for store.callCount() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := store.callCount(); got < 3 {
		t.Fatalf("refresh loop did not survive failures: calls=%d", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}
