package gatewayconfig

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakePublishLock struct {
	mu    sync.Mutex
	locks map[string]fakePublishLockEntry
}

type fakePublishLockEntry struct {
	token   string
	expires time.Time
}

func newFakePublishLock() *fakePublishLock {
	return &fakePublishLock{locks: make(map[string]fakePublishLockEntry)}
}

func (f *fakePublishLock) Acquire(_ context.Context, key, token string, ttl time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if current, ok := f.locks[key]; ok && time.Now().Before(current.expires) {
		return false, nil
	}
	f.locks[key] = fakePublishLockEntry{token: token, expires: time.Now().Add(ttl)}
	return true, nil
}

func (f *fakePublishLock) Renew(_ context.Context, key, token string, ttl time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	current, ok := f.locks[key]
	if !ok || current.token != token || !time.Now().Before(current.expires) {
		return false, nil
	}
	current.expires = time.Now().Add(ttl)
	f.locks[key] = current
	return true, nil
}

func (f *fakePublishLock) Release(_ context.Context, key, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if current, ok := f.locks[key]; ok && current.token == token {
		delete(f.locks, key)
	}
	return nil
}

func stopPublishLockLease(t *testing.T, lease *publishLockLease) {
	t.Helper()
	lease.stopOnce.Do(func() { close(lease.stop) })
	<-lease.done
}

func TestPublishLockLeaseRenewsBeyondTTLAndBlocksConcurrent(t *testing.T) {
	backend := newFakePublishLock()
	p := &Publisher{lockBackend: backend}
	ctx := context.Background()

	first, err := p.acquireLockWithTTL(ctx, "first", 30*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if first == nil {
		t.Fatal("first lease was not acquired")
	}
	defer first.release(ctx)

	time.Sleep(5 * 30 * time.Millisecond)
	second, err := p.acquireLockWithTTL(ctx, "second", 30*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if second != nil {
		second.release(ctx)
		t.Fatal("second publish acquired a lock while the first publish was still alive")
	}
	if err := first.ensure(ctx); err != nil {
		t.Fatalf("first lease lost ownership after its TTL elapsed: %v", err)
	}

	first.release(ctx)
	second, err = p.acquireLockWithTTL(ctx, "second", 30*time.Millisecond)
	if err != nil || second == nil {
		t.Fatalf("lock was not available after the first publish released it: lease=%v err=%v", second != nil, err)
	}
	second.release(ctx)
}

func TestPublishLockLeaseOldOwnerCannotReleaseNewOwner(t *testing.T) {
	backend := newFakePublishLock()
	p := &Publisher{lockBackend: backend}
	ctx := context.Background()

	old, err := p.acquireLockWithTTL(ctx, "old", 20*time.Millisecond)
	if err != nil || old == nil {
		t.Fatalf("old lock acquisition failed: lease=%v err=%v", old != nil, err)
	}
	// 模拟旧发布进程停止续租，等待其租约自然过期后由新发布接管。
	stopPublishLockLease(t, old)
	time.Sleep(25 * time.Millisecond)
	newLease, err := p.acquireLockWithTTL(ctx, "new", 20*time.Millisecond)
	if err != nil || newLease == nil {
		t.Fatalf("new lock acquisition failed after expiry: lease=%v err=%v", newLease != nil, err)
	}
	defer newLease.release(ctx)

	old.release(ctx)
	if err := newLease.ensure(ctx); err != nil {
		t.Fatalf("old owner release removed the new owner's lock: %v", err)
	}
}

func TestEnsureLeaseAfterConfigLoadRestoresAndStopsActivation(t *testing.T) {
	backend := newFakePublishLock()
	p := &Publisher{lockBackend: backend}
	ctx := context.Background()

	oldLease, err := p.acquireLockWithTTL(ctx, "old", 20*time.Millisecond)
	if err != nil || oldLease == nil {
		t.Fatalf("old lock acquisition failed: lease=%v err=%v", oldLease != nil, err)
	}
	stopPublishLockLease(t, oldLease)
	time.Sleep(25 * time.Millisecond)
	newLease, err := p.acquireLockWithTTL(ctx, "new", 20*time.Millisecond)
	if err != nil || newLease == nil {
		t.Fatalf("new lock acquisition failed after expiry: lease=%v err=%v", newLease != nil, err)
	}
	defer newLease.release(ctx)

	restored := false
	err = ensureLeaseAfterConfigLoad(ctx, oldLease, func(recoveryCtx context.Context) error {
		restored = true
		if recoveryCtx.Err() != nil {
			t.Fatalf("recovery context must remain usable: %v", recoveryCtx.Err())
		}
		return nil
	})
	if !errors.Is(err, ErrPublishLockLost) {
		t.Fatalf("post-load lease loss = %v, want ErrPublishLockLost", err)
	}
	if !restored {
		t.Fatal("post-load lease loss must restore the previous configuration")
	}
	if err == nil {
		t.Fatal("activation must not proceed after post-load lease loss")
	}
}

func TestLeaseLossAfterActivationRestoresGatewayAndDatabaseState(t *testing.T) {
	var gatewayRestored, databaseRestored bool
	restoreErr := restoreAfterPublishLockLoss(
		func(context.Context) error {
			gatewayRestored = true
			return nil
		},
		func(context.Context) error {
			databaseRestored = true
			return nil
		},
	)
	if restoreErr != nil {
		t.Fatalf("restore after activation lease loss: %v", restoreErr)
	}
	if !gatewayRestored || !databaseRestored {
		t.Fatalf("lease loss must restore gateway and database state: gateway=%v database=%v", gatewayRestored, databaseRestored)
	}
}

func TestLeaseLossAfterRollbackSetCurrentRestoresGatewayAndDatabaseState(t *testing.T) {
	var calls []string
	restoreErr := restoreAfterPublishLockLoss(
		func(context.Context) error {
			calls = append(calls, "gateway")
			return nil
		},
		func(context.Context) error {
			calls = append(calls, "database")
			return nil
		},
	)
	if restoreErr != nil {
		t.Fatalf("restore after rollback lease loss: %v", restoreErr)
	}
	if got, want := fmt.Sprint(calls), "[gateway database]"; got != want {
		t.Fatalf("restore order = %s, want %s", got, want)
	}
}
