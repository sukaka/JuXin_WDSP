package detectors

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestObjectEnumerationConcurrentWindow(t *testing.T) {
	store := NewMemoryObjectEnumerationStore(16, nil)
	var alerts atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if store.ObserveObject("key", fmt.Sprintf("ref-%d", i%16), "").Alert {
				alerts.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if got := alerts.Load(); got != 1 {
		t.Fatalf("one window must alert once under concurrency: %d", got)
	}
	result := store.ObserveObject("key", "ref-0", "")
	if result.RequestCount != 65 || result.DistinctObjects != 16 {
		t.Fatalf("concurrent observation count mismatch: %+v", result)
	}
}
