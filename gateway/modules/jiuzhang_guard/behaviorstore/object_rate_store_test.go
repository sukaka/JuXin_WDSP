package behaviorstore

import (
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
)

const objectRateRawValue = "918273645501"

type objectRateFixture struct {
	parsed   *parser.Parsed
	identity string
	endpoint string
	salt     string
	key      string
}

func newObjectRateFixture(t *testing.T) objectRateFixture {
	t.Helper()
	fixture := objectRateFixture{
		parsed: &parser.Parsed{
			Method:         "GET",
			RawPath:        "/v1/orders/" + objectRateRawValue,
			NormalizedPath: "/v1/orders/{id}",
			Query:          map[string]string{},
		},
		identity: "auth:object-rate-subject-fingerprint",
		endpoint: "GET /v1/orders/{id}",
		salt:     "object-rate-store-test-salt",
	}
	ids := parser.ExtractObjectIdentifiers(fixture.parsed, fixture.salt)
	if len(ids) != 1 || ids[0].ValueHash == "" {
		t.Fatalf("want one hashed object identifier, got %+v", ids)
	}
	fixture.key = fixture.identity + "|" + fixture.endpoint + "|" + ids[0].Source + ":" + ids[0].Param + "|" + ids[0].ValueHash
	return fixture
}

func TestObjectRateWindow_SharedNamespaceTTLAndKeyDiscipline(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	nodeA, _ := newTestStore(f, clk, 0)
	nodeB, _ := newTestStore(f, clk, 0)
	a := nodeA.Overrides()
	b := nodeB.Overrides()
	fixture := newObjectRateFixture(t)

	const limit = 3
	for hit := 1; hit <= limit+1; hit++ {
		stores := a
		if hit%2 == 0 {
			stores = b
		}
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		ctx.BindDetectorStoreOverrides(stores)
		detectors.CheckObjectRate(ctx, fixture.parsed, fixture.identity, fixture.endpoint, fixture.salt, limit)
		matches := ctx.CopyMatches()
		if hit <= limit {
			if len(matches) != 0 {
				t.Fatalf("hit %d at/below limit must not match: %+v", hit, matches)
			}
			continue
		}
		if len(matches) != 1 || matches[0].RuleID != "ratelimit.object_rate" || matches[0].Evidence["window_count"] != "4" {
			t.Fatalf("two stores must share object count: %+v", matches)
		}
		for name, value := range matches[0].Evidence {
			if value == objectRateRawValue {
				t.Fatalf("raw object value leaked into evidence %s", name)
			}
		}
	}

	if count, _ := a.BehaviorWindow.AddAndCount(fixture.key); count != 1 {
		t.Fatalf("behavior namespace must be independent: count=%d", count)
	}
	if count, _ := a.APIWriteWindow.AddAndCount(fixture.key); count != 1 {
		t.Fatalf("apiwrite namespace must be independent: count=%d", count)
	}
	if count, _ := a.CredentialRateWindow.AddAndCount(fixture.key); count != 1 {
		t.Fatalf("credrate namespace must be independent: count=%d", count)
	}
	mcpCtx := dsctx.New("t", dsctx.DefaultParseLimits())
	mcpCtx.BindDetectorStoreOverrides(a)
	if count, _ := detectors.MCPCallCounts(mcpCtx, "mcpcall|tool-hash|"+fixture.key); count != 1 {
		t.Fatalf("mcpcall key must be independent: count=%d", count)
	}

	if len(f.hashes) != 5 {
		t.Fatalf("want objrate/behavior/apiwrite/credrate/mcpcall keys, got %d: %v", len(f.hashes), f.hashes)
	}
	objectStoreKey := DefaultKeyPrefix + ":" + nsObjectRate + ":" + counters.HashParts(fixture.key)
	if _, ok := f.hashes[objectStoreKey]; !ok {
		t.Fatalf("object key must use objrate namespace and HashParts: %v", f.hashes)
	}
	for key := range f.hashes {
		if strings.Contains(key, fixture.key) || strings.Contains(key, objectRateRawValue) {
			t.Fatalf("object key material leaked into Valkey key: %q", key)
		}
		if f.ttls[key] != windowTTLFloor.Milliseconds() {
			t.Fatalf("window ttl=%d want=%d", f.ttls[key], windowTTLFloor.Milliseconds())
		}
	}

	clk.Advance(time.Minute)
	if count, history := b.ObjectRateWindow.AddAndCount(fixture.key); count != 1 || len(history) != 1 || history[0] != limit+1 {
		t.Fatalf("natural minute roll: count=%d history=%v", count, history)
	}

	customFake := newFakeValkey()
	custom, _ := newTestStore(customFake, clk, time.Hour)
	custom.Overrides().ObjectRateWindow.AddAndCount(fixture.key)
	for key := range customFake.hashes {
		if customFake.ttls[key] != time.Hour.Milliseconds() {
			t.Fatalf("configured object ttl=%d want=%d", customFake.ttls[key], time.Hour.Milliseconds())
		}
	}
}

func TestObjectRateWindow_FailOpenUsesIndependentMemory(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	s, logs := newTestStore(f, clk, 0)
	o := s.Overrides()
	fixture := newObjectRateFixture(t)
	f.fail = true

	if count, history := o.ObjectRateWindow.AddAndCount(fixture.key); count != 1 || len(history) != 0 {
		t.Fatalf("fail-open first hit: count=%d history=%v", count, history)
	}
	if count, _ := o.ObjectRateWindow.AddAndCount(fixture.key); count != 2 {
		t.Fatalf("fail-open object continuity: count=%d", count)
	}
	if count, _ := o.BehaviorWindow.AddAndCount(fixture.key); count != 1 {
		t.Fatalf("behavior fallback must not share object memory: count=%d", count)
	}
	if count, _ := o.APIWriteWindow.AddAndCount(fixture.key); count != 1 {
		t.Fatalf("apiwrite fallback must not share object memory: count=%d", count)
	}
	if count, _ := o.CredentialRateWindow.AddAndCount(fixture.key); count != 1 {
		t.Fatalf("credrate fallback must not share object memory: count=%d", count)
	}
	mcpCtx := dsctx.New("t", dsctx.DefaultParseLimits())
	mcpCtx.BindDetectorStoreOverrides(o)
	if count, _ := detectors.MCPCallCounts(mcpCtx, "mcpcall|tool-hash|"+fixture.key); count != 1 {
		t.Fatalf("mcpcall fallback must not share object memory: count=%d", count)
	}
	if logs.Len() != 1 {
		t.Fatalf("fail-open warnings must be throttled to one per minute: %d", logs.Len())
	}

	clk.Advance(time.Minute)
	if count, history := o.ObjectRateWindow.AddAndCount(fixture.key); count != 1 || len(history) != 1 || history[0] != 2 {
		t.Fatalf("fail-open natural minute roll: count=%d history=%v", count, history)
	}
	if logs.Len() != 2 {
		t.Fatalf("warn throttle must allow another warning after one minute: %d", logs.Len())
	}
	f.fail = false
	if count, _ := o.ObjectRateWindow.AddAndCount(fixture.key); count != 1 {
		t.Fatalf("recovery must resume Valkey without replaying fallback memory: count=%d", count)
	}
}
