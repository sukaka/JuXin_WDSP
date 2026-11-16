package behaviorstore

import (
	"net/http"
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
)

func credentialRateTestKey(t *testing.T) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://example.test/v1/orders", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer credential-rate-store-secret")
	key := detectors.CredentialKey(req, "credential-rate-store-test-salt")
	if key == "" {
		t.Fatal("salted credential key must not be empty")
	}
	return key
}

func TestCredentialRateWindow_SharedNamespaceTTLAndKeyDiscipline(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	nodeA, _ := newTestStore(f, clk, 0)
	nodeB, _ := newTestStore(f, clk, 0)
	a := nodeA.Overrides()
	b := nodeB.Overrides()
	credKey := credentialRateTestKey(t)

	if count, history := a.CredentialRateWindow.AddAndCount(credKey); count != 1 || len(history) != 0 {
		t.Fatalf("first credential hit: count=%d history=%v", count, history)
	}
	if count, history := b.CredentialRateWindow.AddAndCount(credKey); count != 2 || len(history) != 0 {
		t.Fatalf("two stores must share credential count: count=%d history=%v", count, history)
	}
	if count, _ := a.BehaviorWindow.AddAndCount(credKey); count != 1 {
		t.Fatalf("behavior namespace must be independent: count=%d", count)
	}
	if count, _ := a.APIWriteWindow.AddAndCount(credKey); count != 1 {
		t.Fatalf("apiwrite namespace must be independent: count=%d", count)
	}
	mcpCtx := dsctx.New("t", dsctx.DefaultParseLimits())
	mcpCtx.BindDetectorStoreOverrides(a)
	if count, _ := detectors.MCPCallCounts(mcpCtx, "mcpcall|tool-hash|"+credKey); count != 1 {
		t.Fatalf("mcpcall key must be independent: count=%d", count)
	}

	if len(f.hashes) != 4 {
		t.Fatalf("want credrate/behavior/apiwrite/mcpcall keys, got %d: %v", len(f.hashes), f.hashes)
	}
	credentialStoreKey := DefaultKeyPrefix + ":" + nsCredentialRate + ":" + counters.HashParts(credKey)
	if _, ok := f.hashes[credentialStoreKey]; !ok {
		t.Fatalf("credential key must use credrate namespace and HashParts: %v", f.hashes)
	}
	for key := range f.hashes {
		if strings.Contains(key, credKey) || strings.Contains(key, "credential-rate-store-secret") {
			t.Fatalf("sensitive credential material leaked into Valkey key: %q", key)
		}
		if f.ttls[key] != windowTTLFloor.Milliseconds() {
			t.Fatalf("window ttl=%d want=%d", f.ttls[key], windowTTLFloor.Milliseconds())
		}
	}

	clk.Advance(time.Minute)
	if count, history := b.CredentialRateWindow.AddAndCount(credKey); count != 1 || len(history) != 1 || history[0] != 2 {
		t.Fatalf("natural minute roll: count=%d history=%v", count, history)
	}

	customFake := newFakeValkey()
	custom, _ := newTestStore(customFake, clk, time.Hour)
	custom.Overrides().CredentialRateWindow.AddAndCount(credKey)
	for key := range customFake.hashes {
		if customFake.ttls[key] != time.Hour.Milliseconds() {
			t.Fatalf("configured credential ttl=%d want=%d", customFake.ttls[key], time.Hour.Milliseconds())
		}
	}
}

func TestCredentialRateWindow_FailOpenUsesIndependentMemory(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	s, logs := newTestStore(f, clk, 0)
	o := s.Overrides()
	const credKey = "auth:salted-credential-fingerprint"
	f.fail = true

	if count, history := o.CredentialRateWindow.AddAndCount(credKey); count != 1 || len(history) != 0 {
		t.Fatalf("fail-open first hit: count=%d history=%v", count, history)
	}
	if count, _ := o.CredentialRateWindow.AddAndCount(credKey); count != 2 {
		t.Fatalf("fail-open credential continuity: count=%d", count)
	}
	if count, _ := o.BehaviorWindow.AddAndCount(credKey); count != 1 {
		t.Fatalf("behavior fallback must not share credential memory: count=%d", count)
	}
	if count, _ := o.APIWriteWindow.AddAndCount(credKey); count != 1 {
		t.Fatalf("apiwrite fallback must not share credential memory: count=%d", count)
	}
	mcpCtx := dsctx.New("t", dsctx.DefaultParseLimits())
	mcpCtx.BindDetectorStoreOverrides(o)
	if count, _ := detectors.MCPCallCounts(mcpCtx, "mcpcall|tool-hash|"+credKey); count != 1 {
		t.Fatalf("mcpcall fallback must not share credential memory: count=%d", count)
	}
	if logs.Len() != 1 {
		t.Fatalf("fail-open warnings must be throttled to one per minute: %d", logs.Len())
	}

	clk.Advance(time.Minute)
	if count, history := o.CredentialRateWindow.AddAndCount(credKey); count != 1 || len(history) != 1 || history[0] != 2 {
		t.Fatalf("fail-open natural minute roll: count=%d history=%v", count, history)
	}
	if logs.Len() != 2 {
		t.Fatalf("warn throttle must allow another warning after one minute: %d", logs.Len())
	}
	f.fail = false
	if count, _ := o.CredentialRateWindow.AddAndCount(credKey); count != 1 {
		t.Fatalf("recovery must resume Valkey without replaying fallback memory: count=%d", count)
	}
}
