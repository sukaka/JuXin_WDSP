package apisecurity

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNormalizeGraphEdgeLimit(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{-10, DefaultGraphEdgeLimit},
		{0, DefaultGraphEdgeLimit},
		{1, 1},
		{500, 500},
		{DefaultGraphEdgeLimit, DefaultGraphEdgeLimit},
		{MaxGraphEdgeLimit, MaxGraphEdgeLimit},
		{MaxGraphEdgeLimit + 1, MaxGraphEdgeLimit},
		{999999, MaxGraphEdgeLimit},
	}
	for _, tc := range cases {
		if got := normalizeGraphEdgeLimit(tc.in); got != tc.want {
			t.Errorf("normalizeGraphEdgeLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestBuildGraphNodeWhere(t *testing.T) {
	where, args, hasNode, needsApp := buildGraphNodeWhere(GraphFilter{
		Status:  "   ",
		Keyword: "\t  ",
	})
	if where != "TRUE" || len(args) != 0 || hasNode || needsApp {
		t.Fatalf("empty/whitespace filter got (%q, %v, %v, %v), want (TRUE, [], false, false)",
			where, args, hasNode, needsApp)
	}

	appID := uuid.New()
	where, args, hasNode, needsApp = buildGraphNodeWhere(GraphFilter{
		ApplicationID:  &appID,
		Status:         " confirmed ",
		Keyword:        "  100%_Orders\\网关  ",
		ExcludeStatic:  true,
		ExcludeIgnored: true,
	})
	if !hasNode || !needsApp {
		t.Fatalf("expected hasNode=true and needsApp=true, got (%v, %v)", hasNode, needsApp)
	}
	wantSubstrs := []string{
		"e.asset_status <> 'IGNORED'",
		"(e.asset_status = 'CONFIRMED' OR e.is_api = TRUE)",
		"e.application_id = $1",
		"e.asset_status = $2",
		"strpos(lower(COALESCE(e.endpoint_key, '') || ' ' || COALESCE(e.normalized_path, '') || ' ' || COALESCE(a.name, '') || ' ' || COALESCE(e.host, '')), $3) > 0",
	}
	for _, sub := range wantSubstrs {
		if !strings.Contains(where, sub) {
			t.Errorf("where %q missing %q", where, sub)
		}
	}
	if len(args) != 3 {
		t.Fatalf("len(args) = %d, want 3", len(args))
	}
	if gotApp, ok := args[0].(uuid.UUID); !ok || gotApp != appID {
		t.Errorf("args[0] = %#v, want %s", args[0], appID)
	}
	if args[1] != "CONFIRMED" {
		t.Errorf("args[1] = %#v, want CONFIRMED", args[1])
	}
	if args[2] != "100%_orders\\网关" {
		t.Errorf("args[2] = %#v, want 100%%_orders\\网关", args[2])
	}
}

func TestBuildListEdgesQuery(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	start := now.Add(-time.Hour)
	end := now

	// 0. Unfiltered / MinCount-only uses single-phase index scan (idOnly = false)
	q0, a0, idOnly0 := buildListEdgesQuery(EdgeFilter{MinCount: 5, Limit: 250}, edgeQueryScope{})
	if idOnly0 {
		t.Fatalf("q0 expected idOnly=false for MinCount-only query, got true")
	}
	for _, sub := range []string{
		"caller_fingerprint",
		"call_count >= $1",
		"ORDER BY call_count DESC, id",
		"LIMIT $2",
	} {
		if !strings.Contains(q0, sub) {
			t.Errorf("q0 missing %q: %s", sub, q0)
		}
	}
	if len(a0) != 2 || a0[0] != int64(5) || a0[1] != 250 {
		t.Fatalf("a0 = %#v, want [5, 250]", a0)
	}

	// 1. Time-windowed query uses narrow two-phase ID-only sort (idOnly = true)
	q1, a1, idOnly1 := buildListEdgesQuery(EdgeFilter{Start: &start, End: &end, MinCount: 5, Limit: 250}, edgeQueryScope{})
	if !idOnly1 {
		t.Fatalf("q1 expected idOnly=true for time-windowed query, got false")
	}
	if strings.Contains(q1, "caller_fingerprint") {
		t.Fatalf("q1 phase-1 ID query must not select wide caller_fingerprint: %s", q1)
	}
	for _, sub := range []string{
		"SELECT id",
		"last_seen_at >= $1",
		"first_seen_at <= $2",
		"call_count >= $3",
		"ORDER BY call_count DESC, id",
		"LIMIT $4",
	} {
		if !strings.Contains(q1, sub) {
			t.Errorf("q1 missing %q: %s", sub, q1)
		}
	}
	if len(a1) != 4 || a1[3] != 250 {
		t.Fatalf("a1 = %#v, want 4 args ending with 250", a1)
	}

	// 2. Small candidateIDs array pushdown uses narrow two-phase ID-only sort (preserves source_endpoint_id IS NULL)
	smallIDs := []uuid.UUID{uuid.New(), uuid.New()}
	q2, a2, idOnly2 := buildListEdgesQuery(EdgeFilter{MinCount: 1}, edgeQueryScope{candidateIDs: smallIDs})
	if !idOnly2 {
		t.Fatalf("q2 expected idOnly=true for candidateIDs scope, got false")
	}
	if strings.Contains(q2, "caller_fingerprint") {
		t.Fatalf("q2 phase-1 ID query must not select wide caller_fingerprint: %s", q2)
	}
	for _, sub := range []string{
		"SELECT id",
		"call_count >= $1",
		"target_endpoint_id = ANY($2::uuid[])",
		"(source_endpoint_id IS NULL OR source_endpoint_id = ANY($2::uuid[]))",
		"ORDER BY call_count DESC, id",
		"LIMIT $3",
	} {
		if !strings.Contains(q2, sub) {
			t.Errorf("q2 missing %q: %s", sub, q2)
		}
	}
	if len(a2) != 3 || a2[2] != DefaultGraphEdgeLimit {
		t.Fatalf("a2 = %#v, want 3 args ending with %d", a2, DefaultGraphEdgeLimit)
	}

	// 3. Large candidateIDs (> graphCandidateArrayThreshold) switches to JOIN api_endpoints + excludedStaticIDs + narrow ID-only sort
	largeIDs := make([]uuid.UUID, graphCandidateArrayThreshold+1)
	for i := range largeIDs {
		largeIDs[i] = uuid.New()
	}
	exclStatic := []uuid.UUID{uuid.New()}
	gf := GraphFilter{
		EdgeFilter:     EdgeFilter{Limit: MaxGraphEdgeLimit + 50},
		ExcludeStatic:  true,
		ExcludeIgnored: true,
		Keyword:        "orders",
	}
	q3, a3, idOnly3 := buildListEdgesQuery(gf.EdgeFilter, edgeQueryScope{
		candidateIDs:      largeIDs,
		excludedStaticIDs: exclStatic,
		nodeFilter:        &gf,
	})
	if !idOnly3 {
		t.Fatalf("q3 expected idOnly=true for large candidateIDs JOIN, got false")
	}
	if strings.Contains(q3, "caller_fingerprint") {
		t.Fatalf("q3 phase-1 ID query must not select wide caller_fingerprint: %s", q3)
	}
	for _, sub := range []string{
		"SELECT e.id",
		"JOIN api_endpoints te ON te.id = e.target_endpoint_id",
		"LEFT JOIN api_endpoints se ON se.id = e.source_endpoint_id",
		"LEFT JOIN applications ta ON ta.id = te.application_id",
		"LEFT JOIN applications sa ON sa.id = se.application_id",
		"te.asset_status <> 'IGNORED'",
		"se.asset_status <> 'IGNORED'",
		"NOT (e.target_endpoint_id = ANY($2::uuid[]))",
		"(e.source_endpoint_id IS NULL OR NOT (e.source_endpoint_id = ANY($2::uuid[])))",
		"ORDER BY e.call_count DESC, e.id",
		"LIMIT $3",
	} {
		if !strings.Contains(q3, sub) {
			t.Errorf("q3 missing %q: %s", sub, q3)
		}
	}
	if len(a3) != 3 || a3[0] != "orders" || a3[2] != MaxGraphEdgeLimit {
		t.Fatalf("a3 = %#v, want [orders, exclStatic, %d]", a3, MaxGraphEdgeLimit)
	}
}

func TestBuildListEdgesByIDsQueryAndRestoreOrder(t *testing.T) {
	q := buildListEdgesByIDsQuery()
	for _, sub := range []string{
		"id, caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count, identity_count, first_seen_at, last_seen_at",
		"FROM api_call_edges WHERE id = ANY($1::uuid[])",
	} {
		if !strings.Contains(q, sub) {
			t.Fatalf("buildListEdgesByIDsQuery missing %q: %s", sub, q)
		}
	}
	if strings.Contains(strings.ToUpper(q), "ORDER BY") {
		t.Fatalf("buildListEdgesByIDsQuery must not include ORDER BY: %s", q)
	}

	id1, id2, id3, idMissing := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	byID := map[uuid.UUID]GraphEdge{
		id3: {ID: id3, CallerFingerprint: "fp-3", CallCount: 10},
		id1: {ID: id1, CallerFingerprint: "fp-1", CallCount: 100},
		id2: {ID: id2, CallerFingerprint: "fp-2", CallCount: 50},
	}
	got := restoreGraphEdgeOrder([]uuid.UUID{id1, idMissing, id2, id3}, byID)
	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3", len(got))
	}
	if got[0].ID != id1 || got[1].ID != id2 || got[2].ID != id3 {
		t.Fatalf("restored order = [%s, %s, %s], want [%s, %s, %s]", got[0].ID, got[1].ID, got[2].ID, id1, id2, id3)
	}
	if empty := restoreGraphEdgeOrder(nil, byID); len(empty) != 0 {
		t.Fatalf("empty ids returned %d edges, want 0", len(empty))
	}
}

func TestHandlerGraphAndTopologyLimitValidation(t *testing.T) {
	repo := &stubGraphRepo{}
	h := NewHandler(nil, nil)
	h.SetGraphRepository(repo)

	badLimits := []string{"0", "-1", "10001", "abc"}
	for _, lim := range badLimits {
		for _, base := range []string{"/api/v1/api-security/graph", "/api/v1/api-security/topology"} {
			req := httptest.NewRequest(http.MethodGet, base+"?limit="+lim, nil)
			rec := httptest.NewRecorder()
			if strings.HasSuffix(base, "/graph") {
				h.Graph(rec, req)
			} else {
				h.Topology(rec, req)
			}
			if rec.Code != http.StatusBadRequest {
				t.Errorf("GET %s?limit=%s status = %d, want 400", base, lim, rec.Code)
			}
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-security/graph?limit=1200", nil)
	rec := httptest.NewRecorder()
	h.Graph(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid limit GET /graph status = %d, want 200", rec.Code)
	}
	if repo.lastFilter.Limit != 1200 {
		t.Fatalf("parsed Limit = %d, want 1200", repo.lastFilter.Limit)
	}

	reqEmpty := httptest.NewRequest(http.MethodGet, "/api/v1/api-security/graph", nil)
	recEmpty := httptest.NewRecorder()
	h.Graph(recEmpty, reqEmpty)
	if recEmpty.Code != http.StatusOK || repo.lastFilter.Limit != 0 {
		t.Fatalf("omitted limit got status=%d limit=%d, want 200 / 0", recEmpty.Code, repo.lastFilter.Limit)
	}
}
