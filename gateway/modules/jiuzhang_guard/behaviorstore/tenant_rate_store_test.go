package behaviorstore

import (
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
)

const tenantRateTestRawKey = "tenant:raw-tenant-secret|GET /v1/orders"

func TestTenantRateWindow_SharedNamespaceWindowTTLAndKeys(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	nodeA, _ := newTestStore(f, clk, 0)
	nodeB, _ := newTestStore(f, clk, 0)
	a := nodeA.Overrides()
	b := nodeB.Overrides()

	if count, history := a.TenantRateWindow.AddAndCount(tenantRateTestRawKey); count != 1 || len(history) != 0 {
		t.Fatalf("first tenant hit: count=%d history=%v", count, history)
	}
	if count, history := b.TenantRateWindow.AddAndCount(tenantRateTestRawKey); count != 2 || len(history) != 0 {
		t.Fatalf("two stores must share tenant count: count=%d history=%v", count, history)
	}
	if count, _ := a.BehaviorWindow.AddAndCount(tenantRateTestRawKey); count != 1 {
		t.Fatalf("behavior namespace must be independent: %d", count)
	}
	if count, _ := a.APIWriteWindow.AddAndCount(tenantRateTestRawKey); count != 1 {
		t.Fatalf("apiwrite namespace must be independent: %d", count)
	}
	if count, _ := a.CredentialRateWindow.AddAndCount(tenantRateTestRawKey); count != 1 {
		t.Fatalf("credrate namespace must be independent: %d", count)
	}
	if count, _ := a.ObjectRateWindow.AddAndCount(tenantRateTestRawKey); count != 1 {
		t.Fatalf("objrate namespace must be independent: %d", count)
	}
	mcpCtx := dsctx.New("t", dsctx.DefaultParseLimits())
	mcpCtx.BindDetectorStoreOverrides(a)
	if count, _ := detectors.MCPCallCounts(mcpCtx, "mcpcall|tool-hash|"+tenantRateTestRawKey); count != 1 {
		t.Fatalf("mcpcall key must be independent: %d", count)
	}
	if count := a.HourlyQuota.AddAndCount(tenantRateTestRawKey); count != 1 {
		t.Fatalf("hourly quota namespace must be independent: %d", count)
	}
	if count := a.DailyQuota.AddAndCount(tenantRateTestRawKey); count != 1 {
		t.Fatalf("daily quota namespace must be independent: %d", count)
	}

	if len(f.hashes) != 6 {
		t.Fatalf("want tenrate and five isolated window keys, got %d: %v", len(f.hashes), f.hashes)
	}
	tenantStoreKey := DefaultKeyPrefix + ":" + nsTenantRate + ":" + counters.HashParts(tenantRateTestRawKey)
	if _, ok := f.hashes[tenantStoreKey]; !ok {
		t.Fatalf("tenant key must use tenrate namespace and HashParts: %v", f.hashes)
	}
	for key := range f.hashes {
		if strings.Contains(key, tenantRateTestRawKey) || strings.Contains(key, "raw-tenant-secret") {
			t.Fatalf("raw tenant material leaked into Valkey key: %q", key)
		}
		if f.ttls[key] != windowTTLFloor.Milliseconds() {
			t.Fatalf("tenant window ttl=%d want=%d", f.ttls[key], windowTTLFloor.Milliseconds())
		}
	}

	clk.Advance(time.Minute)
	if count, history := b.TenantRateWindow.AddAndCount(tenantRateTestRawKey); count != 1 || len(history) != 1 || history[0] != 2 {
		t.Fatalf("natural minute roll: count=%d history=%v", count, history)
	}

	customFake := newFakeValkey()
	custom, _ := newTestStore(customFake, clk, time.Hour)
	custom.Overrides().TenantRateWindow.AddAndCount(tenantRateTestRawKey)
	for key := range customFake.hashes {
		if customFake.ttls[key] != time.Hour.Milliseconds() {
			t.Fatalf("configured tenant ttl=%d want=%d", customFake.ttls[key], time.Hour.Milliseconds())
		}
	}
}

func TestTenantRateWindow_FailOpenUsesIndependentMemory(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	s, logs := newTestStore(f, clk, 0)
	o := s.Overrides()
	f.fail = true

	if count, history := o.TenantRateWindow.AddAndCount(tenantRateTestRawKey); count != 1 || len(history) != 0 {
		t.Fatalf("fail-open first hit: count=%d history=%v", count, history)
	}
	if count, _ := o.TenantRateWindow.AddAndCount(tenantRateTestRawKey); count != 2 {
		t.Fatalf("fail-open tenant continuity: %d", count)
	}
	if count, _ := o.BehaviorWindow.AddAndCount(tenantRateTestRawKey); count != 1 {
		t.Fatalf("behavior fallback must not share tenant memory: %d", count)
	}
	if count, _ := o.CredentialRateWindow.AddAndCount(tenantRateTestRawKey); count != 1 {
		t.Fatalf("credrate fallback must not share tenant memory: %d", count)
	}
	if count := o.HourlyQuota.AddAndCount(tenantRateTestRawKey); count != 1 {
		t.Fatalf("quota fallback must not share tenant memory: %d", count)
	}
	if logs.Len() != 1 {
		t.Fatalf("fail-open warnings must be throttled to one per minute: %d", logs.Len())
	}

	clk.Advance(time.Minute)
	if count, history := o.TenantRateWindow.AddAndCount(tenantRateTestRawKey); count != 1 || len(history) != 1 || history[0] != 2 {
		t.Fatalf("fail-open natural minute roll: count=%d history=%v", count, history)
	}
	if logs.Len() != 2 {
		t.Fatalf("warn throttle must allow another warning after one minute: %d", logs.Len())
	}
	f.fail = false
	if count, _ := o.TenantRateWindow.AddAndCount(tenantRateTestRawKey); count != 1 {
		t.Fatalf("recovery must resume Valkey without replaying fallback memory: %d", count)
	}
}
