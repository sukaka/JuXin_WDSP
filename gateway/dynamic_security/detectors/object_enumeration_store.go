package detectors

import (
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

type memoryObjectEnumerationStore struct{ tracker *objectEnumerationTracker }

func (s memoryObjectEnumerationStore) ObserveObject(key, ref, nextRef string) ObjectEnumerationResult {
	return s.tracker.observe(key, ref, nextRef)
}

// NewMemoryObjectEnumerationStore returns a bounded, single-node observation window.
func NewMemoryObjectEnumerationStore(capacity int, now func() time.Time) ObjectEnumerationStore {
	if capacity <= 0 {
		capacity = DefaultStoreCapacity
	}
	return memoryObjectEnumerationStore{tracker: newObjectEnumerationTracker(capacity, now)}
}

func objectEnumerationObserve(ctx *dsctx.RequestContext, key, ref, nextRef string) ObjectEnumerationResult {
	if overrides := storeOverridesFor(ctx); overrides != nil && overrides.ObjectEnumeration != nil {
		return overrides.ObjectEnumeration.ObserveObject(key, ref, nextRef)
	}
	return defaultObjectEnumerationTracker.observe(key, ref, nextRef)
}
