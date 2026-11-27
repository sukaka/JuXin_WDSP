package xdpguard

// syncMapDiff reconciles kernel LPM Trie entries between current and desired sets.
// When adding new entries first would exceed maxEntries (causing deterministic E2BIG
// and triggering fail-open XDP detach at full map capacity), stale entries are deleted
// first; otherwise new entries are inserted first to keep live lookups gap-free.
// The current map is updated incrementally on every successful Put/Delete so partial
// failures leave caller state consistent with the kernel map.
func syncMapDiff[K comparable](
	current map[K]struct{},
	desired map[K]struct{},
	maxEntries int,
	putFn func(K) error,
	delFn func(K) error,
) error {
	newCount := 0
	for k := range desired {
		if _, exists := current[k]; !exists {
			newCount++
		}
	}
	deleteStale := func() error {
		for k := range current {
			if _, keep := desired[k]; keep {
				continue
			}
			if err := delFn(k); err != nil {
				return err
			}
			delete(current, k)
		}
		return nil
	}
	putNew := func() error {
		for k := range desired {
			if _, exists := current[k]; exists {
				continue
			}
			if err := putFn(k); err != nil {
				return err
			}
			current[k] = struct{}{}
		}
		return nil
	}
	if maxEntries > 0 && len(current)+newCount > maxEntries {
		if err := deleteStale(); err != nil {
			return err
		}
		return putNew()
	}
	if err := putNew(); err != nil {
		return err
	}
	return deleteStale()
}
