package behaviorstore

import (
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
)

const quotaTestRawMaterial = "auth:quota-sensitive-fingerprint|GET /v1/orders"

func TestQuotaStore_SharedNamespacesWindowResetTTLAndKeys(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	nodeA, _ := newTestStore(f, clk, 0)
	nodeB, _ := newTestStore(f, clk, 0)
	a := nodeA.Overrides()
	b := nodeB.Overrides()

	if count := a.HourlyQuota.AddAndCount(quotaTestRawMaterial); count != 1 {
		t.Fatalf("first hourly hit: %d", count)
	}
	if count := b.HourlyQuota.AddAndCount(quotaTestRawMaterial); count != 2 {
		t.Fatalf("two stores must share hourly quota: %d", count)
	}
	if count := a.DailyQuota.AddAndCount(quotaTestRawMaterial); count != 1 {
		t.Fatalf("daily namespace must be independent: %d", count)
	}
	if count, _ := a.BehaviorWindow.AddAndCount(quotaTestRawMaterial); count != 1 {
		t.Fatalf("behavior namespace must be independent: %d", count)
	}
	if count, _ := a.APIWriteWindow.AddAndCount(quotaTestRawMaterial); count != 1 {
		t.Fatalf("apiwrite namespace must be independent: %d", count)
	}
	if count, _ := a.CredentialRateWindow.AddAndCount(quotaTestRawMaterial); count != 1 {
		t.Fatalf("credrate namespace must be independent: %d", count)
	}
	if count, _ := a.ObjectRateWindow.AddAndCount(quotaTestRawMaterial); count != 1 {
		t.Fatalf("objrate namespace must be independent: %d", count)
	}
	mcpCtx := dsctx.New("t", dsctx.DefaultParseLimits())
	mcpCtx.BindDetectorStoreOverrides(a)
	if count, _ := detectors.MCPCallCounts(mcpCtx, "mcpcall|tool-hash|"+quotaTestRawMaterial); count != 1 {
		t.Fatalf("mcpcall key must be independent: %d", count)
	}

	hourStart := clk.Now().UTC().Truncate(time.Hour).Unix()
	dayStart := clk.Now().UTC().Truncate(24 * time.Hour).Unix()
	hourKey := DefaultKeyPrefix + ":" + nsHourlyQuota + ":" + counters.HashParts(quotaTestRawMaterial, strconv.FormatInt(hourStart, 10))
	dayKey := DefaultKeyPrefix + ":" + nsDailyQuota + ":" + counters.HashParts(quotaTestRawMaterial, strconv.FormatInt(dayStart, 10))
	if _, ok := f.strs[hourKey]; !ok {
		t.Fatalf("hourly key must hash material with natural hour start: %v", f.strs)
	}
	if _, ok := f.strs[dayKey]; !ok {
		t.Fatalf("daily key must hash material with UTC day start: %v", f.strs)
	}
	if len(f.strs) != 2 {
		t.Fatalf("want independent hourly/daily keys, got %d: %v", len(f.strs), f.strs)
	}
	for key := range f.strs {
		if strings.Contains(key, quotaTestRawMaterial) {
			t.Fatalf("raw quota material leaked into Valkey key: %q", key)
		}
	}
	if f.ttls[hourKey] != hourlyQuotaTTLFloor.Milliseconds() {
		t.Fatalf("hourly ttl=%d want=%d", f.ttls[hourKey], hourlyQuotaTTLFloor.Milliseconds())
	}
	if f.ttls[dayKey] != dailyQuotaTTLFloor.Milliseconds() {
		t.Fatalf("daily ttl=%d want=%d", f.ttls[dayKey], dailyQuotaTTLFloor.Milliseconds())
	}

	clk.Advance(time.Hour)
	if count := b.HourlyQuota.AddAndCount(quotaTestRawMaterial); count != 1 {
		t.Fatalf("natural hour rollover must reset hourly quota: %d", count)
	}
	if count := b.DailyQuota.AddAndCount(quotaTestRawMaterial); count != 2 {
		t.Fatalf("hour rollover must not reset daily quota: %d", count)
	}
	clk.Advance(24 * time.Hour)
	if count := a.HourlyQuota.AddAndCount(quotaTestRawMaterial); count != 1 {
		t.Fatalf("new natural hour must use a new key: %d", count)
	}
	if count := a.DailyQuota.AddAndCount(quotaTestRawMaterial); count != 1 {
		t.Fatalf("UTC day rollover must reset daily quota: %d", count)
	}

	customFake := newFakeValkey()
	custom, _ := newTestStore(customFake, clk, 72*time.Hour)
	custom.Overrides().HourlyQuota.AddAndCount(quotaTestRawMaterial)
	custom.Overrides().DailyQuota.AddAndCount(quotaTestRawMaterial)
	for key := range customFake.strs {
		if customFake.ttls[key] != (72 * time.Hour).Milliseconds() {
			t.Fatalf("configured quota ttl=%d want=%d", customFake.ttls[key], (72 * time.Hour).Milliseconds())
		}
	}
}

func TestQuotaStore_FailOpenUsesIndependentMemory(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	s, logs := newTestStore(f, clk, 0)
	o := s.Overrides()
	f.fail = true

	if count := o.HourlyQuota.AddAndCount(quotaTestRawMaterial); count != 1 {
		t.Fatalf("fail-open first hourly hit: %d", count)
	}
	if count := o.HourlyQuota.AddAndCount(quotaTestRawMaterial); count != 2 {
		t.Fatalf("fail-open hourly continuity: %d", count)
	}
	if count := o.DailyQuota.AddAndCount(quotaTestRawMaterial); count != 1 {
		t.Fatalf("daily fallback must not share hourly memory: %d", count)
	}
	if count, _ := o.BehaviorWindow.AddAndCount(quotaTestRawMaterial); count != 1 {
		t.Fatalf("behavior fallback must not share quota memory: %d", count)
	}
	if logs.Len() != 1 {
		t.Fatalf("fail-open warnings must be throttled to one per minute: %d", logs.Len())
	}

	clk.Advance(time.Hour)
	if count := o.HourlyQuota.AddAndCount(quotaTestRawMaterial); count != 1 {
		t.Fatalf("fail-open hour rollover must reset: %d", count)
	}
	if count := o.DailyQuota.AddAndCount(quotaTestRawMaterial); count != 2 {
		t.Fatalf("fail-open hour rollover must retain daily count: %d", count)
	}
	if logs.Len() != 2 {
		t.Fatalf("warn throttle must allow another warning after one minute: %d", logs.Len())
	}
	f.fail = false
	if count := o.HourlyQuota.AddAndCount(quotaTestRawMaterial); count != 1 {
		t.Fatalf("hourly recovery must not replay fallback memory: %d", count)
	}
	if count := o.DailyQuota.AddAndCount(quotaTestRawMaterial); count != 1 {
		t.Fatalf("daily recovery must not replay fallback memory: %d", count)
	}
}

func TestQuotaStore_ConcurrentStores(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	nodeA, _ := newTestStore(f, clk, 0)
	nodeB, _ := newTestStore(f, clk, 0)
	a := nodeA.Overrides()
	b := nodeB.Overrides()
	const workers = 64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stores := a
			if i%2 == 1 {
				stores = b
			}
			stores.HourlyQuota.AddAndCount(quotaTestRawMaterial)
			stores.DailyQuota.AddAndCount(quotaTestRawMaterial)
		}(i)
	}
	wg.Wait()
	if count := a.HourlyQuota.AddAndCount(quotaTestRawMaterial); count != workers+1 {
		t.Fatalf("atomic hourly count=%d want=%d", count, workers+1)
	}
	if count := a.DailyQuota.AddAndCount(quotaTestRawMaterial); count != workers+1 {
		t.Fatalf("atomic daily count=%d want=%d", count, workers+1)
	}
}
