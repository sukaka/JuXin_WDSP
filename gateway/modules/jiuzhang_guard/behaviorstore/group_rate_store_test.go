package behaviorstore

import (
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
)

const groupRateTestRawKey = "app-group-secret|ORDER_QUERY"

func TestGroupRateWindow_SharedNamespaceWindowTTLAndKeys(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	nodeA, _ := newTestStore(f, clk, 0)
	nodeB, _ := newTestStore(f, clk, 0)
	a := nodeA.Overrides()
	b := nodeB.Overrides()

	if count, history := a.GroupRateWindow.AddAndCount(groupRateTestRawKey); count != 1 || len(history) != 0 {
		t.Fatalf("first group hit: count=%d history=%v", count, history)
	}
	if count, history := b.GroupRateWindow.AddAndCount(groupRateTestRawKey); count != 2 || len(history) != 0 {
		t.Fatalf("two stores must share group count: count=%d history=%v", count, history)
	}
	if count, _ := a.BehaviorWindow.AddAndCount(groupRateTestRawKey); count != 1 {
		t.Fatalf("behavior namespace must be independent: %d", count)
	}
	if count, _ := a.APIWriteWindow.AddAndCount(groupRateTestRawKey); count != 1 {
		t.Fatalf("apiwrite namespace must be independent: %d", count)
	}
	if count, _ := a.CredentialRateWindow.AddAndCount(groupRateTestRawKey); count != 1 {
		t.Fatalf("credrate namespace must be independent: %d", count)
	}
	if count, _ := a.ObjectRateWindow.AddAndCount(groupRateTestRawKey); count != 1 {
		t.Fatalf("objrate namespace must be independent: %d", count)
	}
	if count, _ := a.TenantRateWindow.AddAndCount(groupRateTestRawKey); count != 1 {
		t.Fatalf("tenrate namespace must be independent: %d", count)
	}
	if count, _ := a.ActionRateWindow.AddAndCount(groupRateTestRawKey); count != 1 {
		t.Fatalf("actionrate namespace must be independent: %d", count)
	}
	mcpCtx := dsctx.New("t", dsctx.DefaultParseLimits())
	mcpCtx.BindDetectorStoreOverrides(a)
	if count, _ := detectors.MCPCallCounts(mcpCtx, "mcpcall|tool-hash|"+groupRateTestRawKey); count != 1 {
		t.Fatalf("mcpcall key must be independent: %d", count)
	}

	if len(f.hashes) != 8 {
		t.Fatalf("want grouprate plus seven isolated window keys, got %d: %v", len(f.hashes), f.hashes)
	}
	groupStoreKey := DefaultKeyPrefix + ":" + nsGroupRate + ":" + counters.HashParts(groupRateTestRawKey)
	if _, ok := f.hashes[groupStoreKey]; !ok {
		t.Fatalf("group key must use grouprate namespace and HashParts: %v", f.hashes)
	}
	for key := range f.hashes {
		if strings.Contains(key, groupRateTestRawKey) || strings.Contains(key, "app-group-secret") {
			t.Fatalf("raw group material leaked into Valkey key: %q", key)
		}
		if f.ttls[key] != windowTTLFloor.Milliseconds() {
			t.Fatalf("group window ttl=%d want=%d", f.ttls[key], windowTTLFloor.Milliseconds())
		}
	}

	clk.Advance(time.Minute)
	if count, history := b.GroupRateWindow.AddAndCount(groupRateTestRawKey); count != 1 || len(history) != 1 || history[0] != 2 {
		t.Fatalf("natural minute roll: count=%d history=%v", count, history)
	}
	customFake := newFakeValkey()
	custom, _ := newTestStore(customFake, clk, time.Hour)
	custom.Overrides().GroupRateWindow.AddAndCount(groupRateTestRawKey)
	for key := range customFake.hashes {
		if customFake.ttls[key] != time.Hour.Milliseconds() {
			t.Fatalf("configured group ttl=%d want=%d", customFake.ttls[key], time.Hour.Milliseconds())
		}
	}
}

func TestGroupRateWindow_FailOpenUsesIndependentMemory(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	s, logs := newTestStore(f, clk, 0)
	o := s.Overrides()
	f.fail = true

	if count, history := o.GroupRateWindow.AddAndCount(groupRateTestRawKey); count != 1 || len(history) != 0 {
		t.Fatalf("fail-open first hit: count=%d history=%v", count, history)
	}
	if count, _ := o.GroupRateWindow.AddAndCount(groupRateTestRawKey); count != 2 {
		t.Fatalf("fail-open group continuity: %d", count)
	}
	if count, _ := o.BehaviorWindow.AddAndCount(groupRateTestRawKey); count != 1 {
		t.Fatalf("behavior fallback must not share group memory: %d", count)
	}
	if count, _ := o.ActionRateWindow.AddAndCount(groupRateTestRawKey); count != 1 {
		t.Fatalf("action fallback must not share group memory: %d", count)
	}
	if count := o.HourlyQuota.AddAndCount(groupRateTestRawKey); count != 1 {
		t.Fatalf("quota fallback must not share group memory: %d", count)
	}
	if logs.Len() != 1 {
		t.Fatalf("fail-open warnings must be throttled to one per minute: %d", logs.Len())
	}
	clk.Advance(time.Minute)
	if count, history := o.GroupRateWindow.AddAndCount(groupRateTestRawKey); count != 1 || len(history) != 1 || history[0] != 2 {
		t.Fatalf("fail-open natural minute roll: count=%d history=%v", count, history)
	}
	if logs.Len() != 2 {
		t.Fatalf("warn throttle must allow another warning after one minute: %d", logs.Len())
	}
	f.fail = false
	if count, _ := o.GroupRateWindow.AddAndCount(groupRateTestRawKey); count != 1 {
		t.Fatalf("recovery must resume Valkey without replaying fallback memory: %d", count)
	}
}
