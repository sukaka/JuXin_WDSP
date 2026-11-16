package jiuzhang_guard

import (
	"container/list"
	"crypto/sha256"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultSessionIdleTimeout       = 5 * time.Minute
	defaultMaxTrackedSessions       = 10000
	sessionTrackerShardCount        = 64
	sessionTrackerPruneBatchPerCall = 16
)

type sessionKey [sha256.Size]byte

type sessionEntry struct {
	key      sessionKey
	lastSeen time.Time
	element  *list.Element
}

type sessionShard struct {
	mu         sync.Mutex
	entries    map[sessionKey]*sessionEntry
	byLastSeen list.List
	latestSeen time.Time
}

// sessionTracker keeps a process-wide, hard-bounded set of recently active sessions.
// sessions_active counts tracked, non-idle sessions; sessions_new_total counts admitted
// sessions (including readmission after idle expiry); sessions_overflow_total counts
// new-session observations rejected while the tracker is full. Overflow is therefore
// an observation count, not a distinct-session count.
type sessionTracker struct {
	shards        [sessionTrackerShardCount]sessionShard
	idleTimeout   time.Duration
	maxEntries    int
	tracked       atomic.Int64
	newTotal      atomic.Uint64
	overflowTotal atomic.Uint64
}

func newSessionTracker(idleTimeout time.Duration, maxEntries int) *sessionTracker {
	if idleTimeout <= 0 {
		idleTimeout = defaultSessionIdleTimeout
	}
	if maxEntries <= 0 {
		maxEntries = defaultMaxTrackedSessions
	}
	tracker := &sessionTracker{idleTimeout: idleTimeout, maxEntries: maxEntries}
	for i := range tracker.shards {
		tracker.shards[i].entries = make(map[sessionKey]*sessionEntry)
	}
	return tracker
}

func (t *sessionTracker) observe(r *http.Request, appID string, cookieNames map[string]struct{}, now time.Time) {
	if len(cookieNames) == 0 {
		return
	}
	for _, cookie := range r.Cookies() {
		if _, ok := cookieNames[cookie.Name]; !ok || cookie.Value == "" {
			continue
		}
		key := sha256.Sum256([]byte(appID + "\x00" + cookie.Name + "\x00" + cookie.Value))
		t.track(key, now)
	}
}

func (t *sessionTracker) track(key sessionKey, now time.Time) {
	shard := &t.shards[key[0]&(sessionTrackerShardCount-1)]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	// Requests can reach the shard lock in a different order than their timestamps.
	// Clamp timestamps to keep the intrusive expiry list ordered by last activity.
	if now.Before(shard.latestSeen) {
		now = shard.latestSeen
	} else {
		shard.latestSeen = now
	}
	if entry, ok := shard.entries[key]; ok {
		if now.Sub(entry.lastSeen) < t.idleTimeout {
			entry.lastSeen = now
			shard.byLastSeen.MoveToBack(entry.element)
			return
		}
		t.removeLocked(shard, entry)
	}

	if t.tracked.Load() >= int64(t.maxEntries) {
		// Never scan the whole table on the request path. The sampler and admin
		// snapshot perform full expiry passes; a full new-session observation only
		// does a small, bounded amount of cleanup in its own shard.
		t.pruneShardLocked(shard, now, sessionTrackerPruneBatchPerCall)
	}
	if !t.reserveSlot() {
		t.overflowTotal.Add(1)
		return
	}
	entry := &sessionEntry{key: key, lastSeen: now}
	entry.element = shard.byLastSeen.PushBack(entry)
	shard.entries[key] = entry
	t.newTotal.Add(1)
}

func (t *sessionTracker) reserveSlot() bool {
	for {
		current := t.tracked.Load()
		if current >= int64(t.maxEntries) {
			return false
		}
		if t.tracked.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (t *sessionTracker) removeLocked(shard *sessionShard, entry *sessionEntry) {
	delete(shard.entries, entry.key)
	shard.byLastSeen.Remove(entry.element)
	t.tracked.Add(-1)
}

func (t *sessionTracker) pruneShardLocked(shard *sessionShard, now time.Time, limit int) {
	removed := 0
	for front := shard.byLastSeen.Front(); front != nil; front = shard.byLastSeen.Front() {
		entry := front.Value.(*sessionEntry)
		if now.Sub(entry.lastSeen) < t.idleTimeout {
			return
		}
		t.removeLocked(shard, entry)
		removed++
		if limit > 0 && removed >= limit {
			return
		}
	}
}

func (t *sessionTracker) prune(now time.Time) {
	for i := range t.shards {
		shard := &t.shards[i]
		shard.mu.Lock()
		t.pruneShardLocked(shard, now, 0)
		shard.mu.Unlock()
	}
}

func (t *sessionTracker) snapshot(now time.Time) (active int, newTotal, overflowTotal uint64) {
	for i := range t.shards {
		shard := &t.shards[i]
		shard.mu.Lock()
		t.pruneShardLocked(shard, now, 0)
		active += len(shard.entries)
		shard.mu.Unlock()
	}
	return active, t.newTotal.Load(), t.overflowTotal.Load()
}
