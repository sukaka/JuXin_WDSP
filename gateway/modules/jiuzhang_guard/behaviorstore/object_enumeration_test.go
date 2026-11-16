package behaviorstore

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

var objectEnumerationKey = regexp.MustCompile(`^jiuzhang:guard:api:objenum:[0-9a-f]{32}$`)

func enumerationRef(i int) string {
	return fmt.Sprintf("objref:%064x", i)
}

func (f *fakeValkey) evalObjectEnumeration(key string, args []string) []interface{} {
	now, _ := strconv.ParseInt(args[0], 10, 64)
	window, _ := strconv.ParseInt(args[4], 10, 64)
	start, _ := strconv.ParseInt(f.strs[key+":start"], 10, 64)
	h, ok := f.hashes[key]
	if !ok || now < start || now-start >= window {
		h = map[string]int64{}
		f.hashes[key] = h
		f.sets[key] = map[string]struct{}{}
		f.strs[key+":start"] = args[0]
		delete(f.strs, key+":expected")
	}
	objects := f.sets[key]
	ref, nextRef := args[1], args[2]
	_, seen := objects[ref]
	if !seen {
		capN, _ := strconv.Atoi(args[5])
		if len(objects) < capN {
			objects[ref] = struct{}{}
			h["distinct"]++
		}
		if nextRef != "" && f.strs[key+":expected"] == ref {
			h["sequence_steps"]++
		}
	}
	f.strs[key+":expected"] = nextRef
	h["requests"]++
	minObjects, _ := strconv.Atoi(args[6])
	minSequence, _ := strconv.Atoi(args[7])
	highCardinality, _ := strconv.Atoi(args[8])
	alert := int64(0)
	if h["reported"] == 0 && ((h["distinct"] >= int64(minObjects) && h["sequence_steps"] >= int64(minSequence)) || h["distinct"] >= int64(highCardinality)) {
		alert = 1
		h["reported"] = 1
	}
	f.ttls[key], _ = strconv.ParseInt(args[3], 10, 64)
	return []interface{}{h["distinct"], h["requests"], h["sequence_steps"], alert}
}

func TestObjectEnumerationSharedWindowAcrossStores(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	nodeA, _ := newTestStore(f, clk, 0)
	nodeB, _ := newTestStore(f, clk, 0)
	var last detectors.ObjectEnumerationResult
	for i := 0; i < detectors.ObjectEnumerationMinObjects; i++ {
		node := nodeA
		if i >= detectors.ObjectEnumerationMinObjects/2 {
			node = nodeB
		}
		last = node.ObserveObject(rawKeyLeak, enumerationRef(i), enumerationRef(i+1))
		if i < detectors.ObjectEnumerationMinObjects-1 && last.Alert {
			t.Fatalf("alert before shared threshold at %d: %+v", i, last)
		}
	}
	want := detectors.ObjectEnumerationResult{DistinctObjects: 8, RequestCount: 8, SequentialSteps: 7, Alert: true}
	if last != want {
		t.Fatalf("two stores must share one atomic window: got=%+v want=%+v", last, want)
	}
	if next := nodeA.ObserveObject(rawKeyLeak, enumerationRef(8), enumerationRef(9)); next.Alert {
		t.Fatalf("reported window must not alert twice: %+v", next)
	}
	for key := range f.hashes {
		if !objectEnumerationKey.MatchString(key) || strings.Contains(key, rawKeyLeak) {
			t.Fatalf("raw or malformed key: %q", key)
		}
		if f.ttls[key] != objectEnumerationTTLFloor.Milliseconds() {
			t.Fatalf("ttl=%d want=%d", f.ttls[key], objectEnumerationTTLFloor.Milliseconds())
		}
	}
}

func TestObjectEnumerationExpiryAndBounds(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	s, _ := newTestStore(f, clk, 3*time.Minute)
	for i := 0; i < 40; i++ {
		s.ObserveObject("bounded", enumerationRef(i), "")
	}
	for key, objects := range f.sets {
		if len(objects) != detectors.ObjectEnumerationMaxObjects {
			t.Fatalf("object set is not bounded: %d", len(objects))
		}
		if f.ttls[key] != (3 * time.Minute).Milliseconds() {
			t.Fatalf("configured TTL must override floor: %d", f.ttls[key])
		}
	}
	clk.Advance(detectors.ObjectEnumerationWindow)
	result := s.ObserveObject("bounded", enumerationRef(40), "")
	if result.Alert || result.DistinctObjects != 1 || result.RequestCount != 1 || result.SequentialSteps != 0 {
		t.Fatalf("expired window must reset: %+v", result)
	}
	clk.Advance(-2 * detectors.ObjectEnumerationWindow)
	result = s.ObserveObject("bounded", enumerationRef(41), "")
	if result.Alert || result.DistinctObjects != 1 || result.RequestCount != 1 {
		t.Fatalf("clock regression must reset safely: %+v", result)
	}
}

func TestObjectEnumerationFailOpen(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	s, logs := newTestStore(f, clk, 0)
	f.fail = true
	var last detectors.ObjectEnumerationResult
	for i := 0; i < detectors.ObjectEnumerationMinObjects; i++ {
		last = s.ObserveObject("fallback", enumerationRef(i), enumerationRef(i+1))
	}
	if !last.Alert || last.DistinctObjects != 8 || last.SequentialSteps != 7 {
		t.Fatalf("memory fallback must preserve detection semantics: %+v", last)
	}
	if logs.Len() != 1 {
		t.Fatalf("warnings must be throttled: %d", logs.Len())
	}
	f.fail = false
	if recovered := s.ObserveObject("fallback", enumerationRef(8), enumerationRef(9)); recovered.Alert || recovered.DistinctObjects != 1 {
		t.Fatalf("recovery must use shared state without replaying fallback memory: %+v", recovered)
	}
}

func TestObjectEnumerationConcurrentStores(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	nodeA, _ := newTestStore(f, clk, 0)
	nodeB, _ := newTestStore(f, clk, 0)
	var alerts atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			node := nodeA
			if i%2 == 1 {
				node = nodeB
			}
			if node.ObserveObject("concurrent", enumerationRef(i%detectors.ObjectEnumerationHighCardinality), "").Alert {
				alerts.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if alerts.Load() != 1 {
		t.Fatalf("concurrent shared window must alert once: %d", alerts.Load())
	}
	result := nodeA.ObserveObject("concurrent", enumerationRef(0), "")
	if result.RequestCount != 65 || result.DistinctObjects != detectors.ObjectEnumerationHighCardinality {
		t.Fatalf("concurrent count mismatch: %+v", result)
	}
}
