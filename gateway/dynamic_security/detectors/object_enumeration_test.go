package detectors

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func enumerationFixture(principal string) (*dsctx.RequestContext, *jwtverify.VerificationResult) {
	ctx := dsctx.New("object-enumeration", dsctx.DefaultParseLimits())
	ctx.BindDetectorStoreOverrides(&StoreOverrides{ObjectEnumeration: NewMemoryObjectEnumerationStore(100, nil)})
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: principal}
	return ctx, jwt
}

func enumerationParsed(id string) *parser.Parsed {
	return &parser.Parsed{
		Method: "GET", RawPath: "/v1/cases/" + id, NormalizedPath: "/v1/cases/{id}",
		Headers: map[string]string{"authorization": "[redacted]"},
	}
}

func TestObjectEnumerationSequentialDistinctObjects(t *testing.T) {
	ids := make([]string, 0, objectEnumerationMinObjects)
	for i := 0; i < objectEnumerationMinObjects; i++ {
		ids = append(ids, strconv.Itoa(4100+i))
	}
	store := NewMemoryObjectEnumerationStore(100, nil)
	var last *dsctx.RequestContext
	for _, id := range ids {
		ctx, jwt := enumerationFixture("principal-fingerprint")
		ctx.BindDetectorStoreOverrides(&StoreOverrides{ObjectEnumeration: store})
		CheckObjectEnumeration(ctx, enumerationParsed(id), jwt, "test-salt", "GET /v1/cases/{id}", nil)
		last = ctx
	}
	matches := findAllMatches(last, "resource.object_enumeration")
	if len(matches) != 1 {
		t.Fatalf("want one threshold alert, got %+v", last.CopyMatches())
	}
	match := matches[0]
	if match.Category != "OBSERVE" || match.Severity != "HIGH" || match.Evidence["distinct_objects"] != "8" || match.Evidence["sequential_steps"] != "7" {
		t.Fatalf("unexpected match: %+v", match)
	}
	if !strings.HasPrefix(match.Evidence["object_ref"], "objref:") || len(match.Evidence["object_ref"]) != len("objref:")+64 {
		t.Fatalf("object reference is not a full HMAC: %+v", match.Evidence)
	}
	serialized := fmt.Sprintf("%+v", match)
	for _, id := range ids {
		if strings.Contains(serialized, id) {
			t.Fatalf("raw object identifier %q leaked: %s", id, serialized)
		}
	}
}

func TestObjectEnumerationSingleAndRepeatedObjectsDoNotAlert(t *testing.T) {
	store := NewMemoryObjectEnumerationStore(100, nil)
	for i := 0; i < 30; i++ {
		ctx, jwt := enumerationFixture("same-subject")
		ctx.BindDetectorStoreOverrides(&StoreOverrides{ObjectEnumeration: store})
		CheckObjectEnumeration(ctx, enumerationParsed("4100"), jwt, "test-salt", "GET /v1/cases/{id}", nil)
		if findMatch(ctx, "resource.object_enumeration") != nil {
			t.Fatalf("repeated access to one object is not enumeration: %+v", ctx.CopyMatches())
		}
	}
}

func TestObjectEnumerationNonSequentialBelowCardinalityDoesNotAlert(t *testing.T) {
	store := NewMemoryObjectEnumerationStore(100, nil)
	for i := 0; i < objectEnumerationMinObjects; i++ {
		ctx, jwt := enumerationFixture("non-sequential-subject")
		ctx.BindDetectorStoreOverrides(&StoreOverrides{ObjectEnumeration: store})
		CheckObjectEnumeration(ctx, enumerationParsed(strconv.Itoa(4100+i*100)), jwt, "test-salt", "GET /v1/cases/{id}", nil)
		if findMatch(ctx, "resource.object_enumeration") != nil {
			t.Fatalf("numeric identifiers alone are not enumeration evidence: %+v", ctx.CopyMatches())
		}
	}
}

func TestObjectEnumerationLegitimateListAndPaginationIgnored(t *testing.T) {
	store := NewMemoryObjectEnumerationStore(100, nil)
	for i := 0; i < 20; i++ {
		ctx, jwt := enumerationFixture("list-reader")
		ctx.BindDetectorStoreOverrides(&StoreOverrides{ObjectEnumeration: store})
		p := &parser.Parsed{
			Method: "GET", RawPath: "/v1/cases", NormalizedPath: "/v1/cases",
			Query: map[string]string{"page": strconv.Itoa(i + 1), "page_size": "50", "filter": "4100"},
		}
		CheckObjectEnumeration(ctx, p, jwt, "test-salt", "GET /v1/cases", nil)
		if ctx.MatchCount() != 0 {
			t.Fatalf("ordinary list/pagination must not alert: %+v", ctx.CopyMatches())
		}
	}
}

func TestObjectEnumerationRequiresVerifiedPrincipal(t *testing.T) {
	store := NewMemoryObjectEnumerationStore(100, nil)
	for _, jwt := range []*jwtverify.VerificationResult{
		nil,
		{Status: jwtverify.StatusUnverified, VerifiedPrincipalID: "untrusted-claim"},
		{Status: jwtverify.StatusVerified, VerifiedPrincipalID: ""},
	} {
		for i := 0; i < objectEnumerationMinObjects; i++ {
			ctx, _ := enumerationFixture("ignored")
			ctx.BindDetectorStoreOverrides(&StoreOverrides{ObjectEnumeration: store})
			CheckObjectEnumeration(ctx, enumerationParsed(strconv.Itoa(4100+i)), jwt, "test-salt", "GET /v1/cases/{id}", nil)
			if ctx.MatchCount() != 0 {
				t.Fatalf("untrusted identity must not contribute evidence: %+v", ctx.CopyMatches())
			}
		}
	}
}

func TestObjectEnumerationHighCardinalityUUID(t *testing.T) {
	store := NewMemoryObjectEnumerationStore(100, nil)
	var last *dsctx.RequestContext
	for i := 0; i < objectEnumerationHighCardinality; i++ {
		ctx, jwt := enumerationFixture("uuid-reader")
		ctx.BindDetectorStoreOverrides(&StoreOverrides{ObjectEnumeration: store})
		id := fmt.Sprintf("550e8400-e29b-41d4-a716-%012d", i)
		p := &parser.Parsed{Method: "GET", RawPath: "/v1/documents/" + id, NormalizedPath: "/v1/documents/{uuid}"}
		CheckObjectEnumeration(ctx, p, jwt, "test-salt", "GET /v1/documents/{uuid}", nil)
		last = ctx
	}
	match := findMatch(last, "resource.object_enumeration")
	if match == nil || match.Severity != "MEDIUM" || match.Evidence["pattern"] != "high_cardinality_object_access" || match.Evidence["sequential_steps"] != "0" {
		t.Fatalf("unexpected high-cardinality result: %+v", last.CopyMatches())
	}
}

func TestObjectEnumerationSemanticQueryOnly(t *testing.T) {
	store := NewMemoryObjectEnumerationStore(100, nil)
	constraints := SemanticIDPathsFromConstraints([]ParamConstraint{{Location: "QUERY", Name: "case_id", SemanticType: "resource_id"}})
	var last *dsctx.RequestContext
	for i := 0; i < objectEnumerationMinObjects; i++ {
		ctx, jwt := enumerationFixture("query-reader")
		ctx.BindDetectorStoreOverrides(&StoreOverrides{ObjectEnumeration: store})
		p := &parser.Parsed{
			Method: "GET", RawPath: "/v1/cases:lookup", NormalizedPath: "/v1/cases:lookup",
			Query: map[string]string{"case_id": strconv.Itoa(4100 + i)},
		}
		CheckObjectEnumeration(ctx, p, jwt, "test-salt", "GET /v1/cases:lookup", constraints)
		last = ctx
	}
	match := findMatch(last, "resource.object_enumeration")
	if match == nil || match.Evidence["param"] != "case_id" {
		t.Fatalf("semantic object query should be tracked: %+v", last.CopyMatches())
	}
}

func TestObjectEnumerationIsolatesPrincipalsAndSuppressesRepeatedAlert(t *testing.T) {
	store := NewMemoryObjectEnumerationStore(100, nil)
	visit := func(principal string, id int) *dsctx.RequestContext {
		ctx, jwt := enumerationFixture(principal)
		ctx.BindDetectorStoreOverrides(&StoreOverrides{ObjectEnumeration: store})
		CheckObjectEnumeration(ctx, enumerationParsed(strconv.Itoa(id)), jwt, "test-salt", "GET /v1/cases/{id}", nil)
		return ctx
	}
	for i := 0; i < objectEnumerationMinObjects-1; i++ {
		visit("subject-a", 4100+i)
	}
	if match := findMatch(visit("subject-b", 4107), "resource.object_enumeration"); match != nil {
		t.Fatalf("another subject must have an independent window: %+v", match)
	}
	if match := findMatch(visit("subject-a", 4107), "resource.object_enumeration"); match == nil {
		t.Fatal("original subject should reach the threshold")
	}
	if match := findMatch(visit("subject-a", 4108), "resource.object_enumeration"); match != nil {
		t.Fatalf("same window must emit only one alert: %+v", match)
	}
}

func TestObjectEnumerationWindowResetAndBoundedState(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	tracker := newObjectEnumerationTracker(1, func() time.Time { return now })
	for i := 0; i < objectEnumerationMinObjects-1; i++ {
		tracker.observe("key", fmt.Sprintf("ref-%d", i), fmt.Sprintf("ref-%d", i+1))
	}
	now = now.Add(objectEnumerationWindow)
	result := tracker.observe("key", "ref-7", "ref-8")
	if result.Alert || result.DistinctObjects != 1 || result.SequentialSteps != 0 {
		t.Fatalf("expired window must reset: %+v", result)
	}
	for i := 0; i < 40; i++ {
		tracker.observe("bounded", fmt.Sprintf("ref-%d", i), "")
	}
	entryValue, ok := tracker.entries.get("bounded")
	if !ok || len(tracker.entries.items) != 1 {
		t.Fatal("tracker must retain its LRU bound")
	}
	entry := entryValue.(*objectEnumerationEntry)
	if len(entry.objects) != objectEnumerationMaxObjects {
		t.Fatalf("object set must be bounded: %d", len(entry.objects))
	}
}
