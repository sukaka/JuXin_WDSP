package behaviorstore

import (
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
)

const actionRateTestRawKey = "app-action-secret|READ_DETAIL"

func TestActionRateWindow_SharedNamespaceWindowTTLAndKeys(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	nodeA, _ := newTestStore(f, clk, 0)
	nodeB, _ := newTestStore(f, clk, 0)
	a := nodeA.Overrides()
	b := nodeB.Overrides()

	if count, history := a.ActionRateWindow.AddAndCount(actionRateTestRawKey); count != 1 || len(history) != 0 {
		t.Fatalf("first action hit: count=%d history=%v", count, history)
	}
	if count, history := b.ActionRateWindow.AddAndCount(actionRateTestRawKey); count != 2 || len(history) != 0 {
		t.Fatalf("two stores must share action count: count=%d history=%v", count, history)
	}
	if count, _ := a.BehaviorWindow.AddAndCount(actionRateTestRawKey); count != 1 {
		t.Fatalf("behavior namespace must be independent: %d", count)
	}
	if count, _ := a.APIWriteWindow.AddAndCount(actionRateTestRawKey); count != 1 {
		t.Fatalf("apiwrite namespace must be independent: %d", count)
	}
	if count, _ := a.CredentialRateWindow.AddAndCount(actionRateTestRawKey); count != 1 {
		t.Fatalf("credrate namespace must be independent: %d", count)
	}
	if count, _ := a.ObjectRateWindow.AddAndCount(actionRateTestRawKey); count != 1 {
		t.Fatalf("objrate namespace must be independent: %d", count)
	}
	if count, _ := a.TenantRateWindow.AddAndCount(actionRateTestRawKey); count != 1 {
		t.Fatalf("tenrate namespace must be independent: %d", count)
	}
	mcpCtx := dsctx.New("t", dsctx.DefaultParseLimits())
	mcpCtx.BindDetectorStoreOverrides(a)
	if count, _ := detectors.MCPCallCounts(mcpCtx, "mcpcall|tool-hash|"+actionRateTestRawKey); count != 1 {
		t.Fatalf("mcpcall key must be independent: %d", count)
	}

	if len(f.hashes) != 7 {
		t.Fatalf("want actionrate plus six isolated window keys, got %d: %v", len(f.hashes), f.hashes)
	}
	actionStoreKey := DefaultKeyPrefix + ":" + nsActionRate + ":" + counters.HashParts(actionRateTestRawKey)
	if _, ok := f.hashes[actionStoreKey]; !ok {
		t.Fatalf("action key must use actionrate namespace and HashParts: %v", f.hashes)
	}
	for key := range f.hashes {
		if strings.Contains(key, actionRateTestRawKey) || strings.Contains(key, "app-action-secret") {
			t.Fatalf("raw action material leaked into Valkey key: %q", key)
		}
		if f.ttls[key] != windowTTLFloor.Milliseconds() {
			t.Fatalf("action window ttl=%d want=%d", f.ttls[key], windowTTLFloor.Milliseconds())
		}
	}

	clk.Advance(time.Minute)
	if count, history := b.ActionRateWindow.AddAndCount(actionRateTestRawKey); count != 1 || len(history) != 1 || history[0] != 2 {
		t.Fatalf("natural minute roll: count=%d history=%v", count, history)
	}
	customFake := newFakeValkey()
	custom, _ := newTestStore(customFake, clk, time.Hour)
	custom.Overrides().ActionRateWindow.AddAndCount(actionRateTestRawKey)
	for key := range customFake.hashes {
		if customFake.ttls[key] != time.Hour.Milliseconds() {
			t.Fatalf("configured action ttl=%d want=%d", customFake.ttls[key], time.Hour.Milliseconds())
		}
	}
}

func TestActionRateWindow_FailOpenUsesIndependentMemory(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	s, logs := newTestStore(f, clk, 0)
	o := s.Overrides()
	f.fail = true

	if count, history := o.ActionRateWindow.AddAndCount(actionRateTestRawKey); count != 1 || len(history) != 0 {
		t.Fatalf("fail-open first hit: count=%d history=%v", count, history)
	}
	if count, _ := o.ActionRateWindow.AddAndCount(actionRateTestRawKey); count != 2 {
		t.Fatalf("fail-open action continuity: %d", count)
	}
	if count, _ := o.BehaviorWindow.AddAndCount(actionRateTestRawKey); count != 1 {
		t.Fatalf("behavior fallback must not share action memory: %d", count)
	}
	if count, _ := o.TenantRateWindow.AddAndCount(actionRateTestRawKey); count != 1 {
		t.Fatalf("tenant fallback must not share action memory: %d", count)
	}
	if count := o.HourlyQuota.AddAndCount(actionRateTestRawKey); count != 1 {
		t.Fatalf("quota fallback must not share action memory: %d", count)
	}
	if logs.Len() != 1 {
		t.Fatalf("fail-open warnings must be throttled to one per minute: %d", logs.Len())
	}
	clk.Advance(time.Minute)
	if count, history := o.ActionRateWindow.AddAndCount(actionRateTestRawKey); count != 1 || len(history) != 1 || history[0] != 2 {
		t.Fatalf("fail-open natural minute roll: count=%d history=%v", count, history)
	}
	if logs.Len() != 2 {
		t.Fatalf("warn throttle must allow another warning after one minute: %d", logs.Len())
	}
	f.fail = false
	if count, _ := o.ActionRateWindow.AddAndCount(actionRateTestRawKey); count != 1 {
		t.Fatalf("recovery must resume Valkey without replaying fallback memory: %d", count)
	}
}
