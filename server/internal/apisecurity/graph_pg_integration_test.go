package apisecurity

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func openAPISecurityGraphTestPG(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("APISECURITY_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("APISECURITY_TEST_PG_DSN not set, skipping apisecurity graph PG integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping pg: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	return pool, ctx
}

// bruteForceGraphParityOracle 读取测试隔离前全表原始数据并在内存中用 applyGraphFilter 计算基准真值。
func bruteForceGraphParityOracle(ctx context.Context, t *testing.T, pool *pgxpool.Pool, f GraphFilter) *Graph {
	t.Helper()
	rows, err := pool.Query(ctx, `
SELECT e.id, e.endpoint_key, e.http_method, e.normalized_path, e.application_id,
       COALESCE(a.name, ''), COALESCE(e.host, ''), COALESCE(e.protocol_type, 'REST'), e.is_api,
       e.asset_status, e.learning_status, e.hit_count, COALESCE(fc.open_count, 0)
FROM api_endpoints e
LEFT JOIN applications a ON a.id = e.application_id
LEFT JOIN (
    SELECT endpoint_id, count(*) AS open_count
    FROM api_runtime_findings
    WHERE endpoint_id IS NOT NULL AND status IN ('NEW','CONFIRMED','IN_PROGRESS')
    GROUP BY endpoint_id
) fc ON fc.endpoint_id = e.id
ORDER BY e.endpoint_key, e.host, e.id`)
	if err != nil {
		t.Fatalf("oracle query nodes: %v", err)
	}
	defer rows.Close()
	nodes := []GraphNode{}
	for rows.Next() {
		var n GraphNode
		if err := rows.Scan(&n.ID, &n.EndpointKey, &n.HTTPMethod, &n.NormalizedPath,
			&n.ApplicationID, &n.ApplicationName, &n.Host, &n.ProtocolType, &n.IsAPI,
			&n.AssetStatus, &n.LearningStatus, &n.HitCount, &n.OpenFindingsCount); err != nil {
			t.Fatalf("oracle scan node: %v", err)
		}
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("oracle nodes err: %v", err)
	}

	where, args := buildEdgeWhere("", f.EdgeFilter, 1)
	edgeRows, err := pool.Query(ctx, `
SELECT id, caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count, identity_count, first_seen_at, last_seen_at
FROM api_call_edges WHERE `+where+` ORDER BY call_count DESC, id`, args...)
	if err != nil {
		t.Fatalf("oracle query edges: %v", err)
	}
	defer edgeRows.Close()
	edges := []GraphEdge{}
	for edgeRows.Next() {
		var e GraphEdge
		if err := edgeRows.Scan(&e.ID, &e.CallerFingerprint, &e.SourceEndpointID,
			&e.TargetEndpointID, &e.CallCount, &e.IdentityCount, &e.FirstSeenAt, &e.LastSeenAt); err != nil {
			t.Fatalf("oracle scan edge: %v", err)
		}
		edges = append(edges, e)
	}
	if err := edgeRows.Err(); err != nil {
		t.Fatalf("oracle edges err: %v", err)
	}

	return applyGraphFilter(&Graph{Nodes: nodes, Edges: edges}, f)
}

func TestGraphSQLPushdownParityPG(t *testing.T) {
	pool, ctx := openAPISecurityGraphTestPG(t)

	// 确保隔离测试库无残余脏数据干扰全局 Summary
	if _, err := pool.Exec(ctx, `TRUNCATE TABLE api_runtime_findings, api_call_edges, api_endpoints, applications CASCADE`); err != nil {
		t.Fatalf("truncate tables: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `TRUNCATE TABLE api_runtime_findings, api_call_edges, api_endpoints, applications CASCADE`)
	})

	appA := uuid.New()
	appB := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO applications (id, code, name, status) VALUES ($1, 'app-a', '订单100%_系统', 'ONLINE'), ($2, 'app-b', '网关\\Alpha', 'ONLINE')`, appA, appB); err != nil {
		t.Fatalf("insert applications: %v", err)
	}

	type epSeed struct {
		id     uuid.UUID
		appID  *uuid.UUID
		method string
		path   string
		host   string
		isAPI  bool
		status string
		hits   int64
	}
	eps := []epSeed{
		{uuid.New(), &appA, "POST", "/api/v1/orders", "orders.local", true, "DISCOVERED", 100},
		{uuid.New(), &appA, "POST", "/api/v1/pay", "orders.local", true, "CONFIRMED", 200},
		{uuid.New(), &appA, "GET", "/favicon_128x128.ico", "orders.local", true, "DISCOVERED", 50},
		{uuid.New(), &appA, "GET", "/.well-known/acme-challenge/tok", "orders.local", true, "DISCOVERED", 12},
		{uuid.New(), &appA, "GET", "/static/badge.png", "orders.local", false, "CONFIRMED", 30},
		{uuid.New(), &appA, "GET", "/portal/nonapi", "orders.local", false, "DISCOVERED", 10},
		{uuid.New(), &appA, "GET", "/api/v1/old", "orders.local", true, "IGNORED", 5},
		{uuid.New(), &appA, "POST", "/api/v1/upload.png", "orders.local", true, "DISCOVERED", 40},
		{uuid.New(), &appA, "GET", "/.png", "orders.local", true, "DISCOVERED", 15},
		{uuid.New(), &appA, "GET", "/api/v1/items/{id}", "orders.local", true, "DISCOVERED", 22},
		{uuid.New(), &appB, "GET", "/api/v1/health_check", "gw.local", true, "DISCOVERED", 80},
		{uuid.New(), &appB, "GET", "/api/v1/100%_rate", "gw.local", true, "CONFIRMED", 60},
		{uuid.New(), nil, "GET", "/unassigned/ping", "raw.local", true, "DEPRECATED", 8},
	}
	for _, ep := range eps {
		key := ep.method + " " + ep.path
		if _, err := pool.Exec(ctx, `
INSERT INTO api_endpoints (id, application_id, http_method, normalized_path, endpoint_key, is_api, asset_status, hit_count, host)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			ep.id, ep.appID, ep.method, ep.path, key, ep.isAPI, ep.status, ep.hits, ep.host); err != nil {
			t.Fatalf("insert endpoint %s: %v", key, err)
		}
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	type edgeSeed struct {
		src   *uuid.UUID
		dst   uuid.UUID
		fp    string
		cnt   int64
		first time.Time
		last  time.Time
	}
	edges := []edgeSeed{
		// appA 高流量边
		{&eps[0].id, eps[1].id, "fp-1", 500, now.Add(-3 * time.Hour), now.Add(-10 * time.Minute)},
		// 外部调用方 (source_endpoint_id IS NULL)
		{nil, eps[1].id, "fp-ext", 400, now.Add(-2 * time.Hour), now.Add(-5 * time.Minute)},
		// 指向 is_api=true 静态图标的边
		{&eps[0].id, eps[2].id, "fp-static", 300, now.Add(-2 * time.Hour), now.Add(-20 * time.Minute)},
		// 指向 IGNORED 节点的边
		{&eps[6].id, eps[1].id, "fp-ign", 250, now.Add(-2 * time.Hour), now.Add(-30 * time.Minute)},
		// POST 到 .png 与 dotfile 与占位符边
		{&eps[7].id, eps[8].id, "fp-post-png", 120, now.Add(-90 * time.Minute), now.Add(-15 * time.Minute)},
		{nil, eps[9].id, "fp-tmpl", 90, now.Add(-50 * time.Hour), now.Add(-48 * time.Hour)},
		// appB 低流量边（验证 candidateIDs 在 LIMIT 前下推，不被 appA 高流量边挤掉）
		{&eps[10].id, eps[11].id, "fp-appb-1", 7, now.Add(-1 * time.Hour), now.Add(-2 * time.Minute)},
		{nil, eps[11].id, "fp-appb-ext", 3, now.Add(-1 * time.Hour), now.Add(-1 * time.Minute)},
		// 跨应用边（appA -> appB）
		{&eps[0].id, eps[10].id, "fp-cross", 50, now.Add(-1 * time.Hour), now.Add(-5 * time.Minute)},
	}
	for _, ed := range edges {
		if _, err := pool.Exec(ctx, `
INSERT INTO api_call_edges (caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count, identity_count, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, $4, 3, $5, $6)`,
			ed.fp, ed.src, ed.dst, ed.cnt, ed.first, ed.last); err != nil {
			t.Fatalf("insert edge %s: %v", ed.fp, err)
		}
	}

	// 插入 findings（含活动状态、关闭状态及 endpoint_id IS NULL 行）
	if _, err := pool.Exec(ctx, `
INSERT INTO api_runtime_findings (endpoint_id, request_id, finding_type, severity, status, title) VALUES
($1, 'r1', 'BOLA', 'HIGH', 'NEW', 'open-1'),
($1, 'r2', 'BOLA', 'HIGH', 'CONFIRMED', 'open-2'),
($1, 'r3', 'BOLA', 'LOW', 'RESOLVED', 'closed-1'),
($2, 'r4', 'SCHEMA_DEVIATION', 'MEDIUM', 'IN_PROGRESS', 'open-3'),
(NULL, 'r5', 'SCHEMA_DEVIATION', 'LOW', 'NEW', 'null-ep-finding')`,
		eps[0].id, eps[11].id); err != nil {
		t.Fatalf("insert findings: %v", err)
	}

	store := NewStore(pool)
	startRecent := now.Add(-4 * time.Hour)
	endRecent := now

	filters := []struct {
		name string
		f    GraphFilter
	}{
		{"zero_filter", GraphFilter{}},
		{"only_connected_no_node_filter", GraphFilter{OnlyConnected: true}},
		{"frontend_default", GraphFilter{ExcludeStatic: true, ExcludeIgnored: true, OnlyConnected: true}},
		{"exclude_static_only", GraphFilter{ExcludeStatic: true}},
		{"exclude_ignored_only", GraphFilter{ExcludeIgnored: true}},
		{"appA_all", GraphFilter{ApplicationID: &appA}},
		{"appB_only_connected", GraphFilter{ApplicationID: &appB, OnlyConnected: true}},
		{"status_confirmed", GraphFilter{Status: "CONFIRMED", ExcludeStatic: true}},
		{"keyword_percent_underscore", GraphFilter{Keyword: "100%_"}},
		{"keyword_backslash_cjk", GraphFilter{Keyword: "网关\\"}},
		{"keyword_space_cross_field", GraphFilter{Keyword: "orders /api/v1"}},
		{"keyword_no_match", GraphFilter{Keyword: "nonexistent_endpoint_xyz", OnlyConnected: true}},
		{"time_window_and_min_count", GraphFilter{
			EdgeFilter:     EdgeFilter{Start: &startRecent, End: &endRecent, MinCount: 50},
			ExcludeStatic:  true,
			ExcludeIgnored: true,
			OnlyConnected:  true,
		}},
		{"edge_limit_scoped_appB", GraphFilter{
			EdgeFilter:    EdgeFilter{Limit: 2},
			ApplicationID: &appB,
			OnlyConnected: true,
		}},
	}

	for _, tc := range filters {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.ListGraphWithFilter(ctx, tc.f)
			if err != nil {
				t.Fatalf("ListGraphWithFilter(%+v): %v", tc.f, err)
			}
			want := bruteForceGraphParityOracle(ctx, t, pool, tc.f)
			if !reflect.DeepEqual(got.Summary, want.Summary) {
				t.Fatalf("summary mismatch:\n got: %+v\nwant: %+v", got.Summary, want.Summary)
			}
			if !reflect.DeepEqual(got.Nodes, want.Nodes) {
				t.Fatalf("nodes mismatch:\n got(%d): %+v\nwant(%d): %+v", len(got.Nodes), got.Nodes, len(want.Nodes), want.Nodes)
			}
			if !reflect.DeepEqual(got.Edges, want.Edges) {
				t.Fatalf("edges mismatch:\n got(%d): %+v\nwant(%d): %+v", len(got.Edges), got.Edges, len(want.Edges), want.Edges)
			}
		})
	}

	// 验证全局 Limit 截断下的 Summary 语义：TotalEdges 保持全量，VisibleEdges == len(Edges) == 3
	gLimited, err := store.ListGraphWithFilter(ctx, GraphFilter{
		EdgeFilter: EdgeFilter{Limit: 3},
	})
	if err != nil {
		t.Fatalf("ListGraphWithFilter limit=3: %v", err)
	}
	if len(gLimited.Edges) != 3 || gLimited.Summary.VisibleEdges != 3 || gLimited.Summary.TotalEdges != len(edges) {
		t.Fatalf("limited graph edges=%d summary=%+v, want len=3 visible=3 total=%d",
			len(gLimited.Edges), gLimited.Summary, len(edges))
	}
	if gLimited.Summary.VisibleNodes != len(gLimited.Nodes) {
		t.Fatalf("VisibleNodes=%d != len(Nodes)=%d", gLimited.Summary.VisibleNodes, len(gLimited.Nodes))
	}

	// 验证 ListTopologyFiltered 的 Limit 与 open_findings_count
	topo, err := store.ListTopologyFiltered(ctx, EdgeFilter{Limit: 4, MinCount: 10})
	if err != nil {
		t.Fatalf("ListTopologyFiltered: %v", err)
	}
	if len(topo.Edges) != 4 {
		t.Fatalf("topology edges = %d, want 4", len(topo.Edges))
	}
	for i := 1; i < len(topo.Edges); i++ {
		if topo.Edges[i].CallCount > topo.Edges[i-1].CallCount {
			t.Fatalf("topology edges not sorted desc by call_count at %d", i)
		}
	}
}

func TestGraphLargeCandidateBranchPG(t *testing.T) {
	pool, ctx := openAPISecurityGraphTestPG(t)

	if _, err := pool.Exec(ctx, `TRUNCATE TABLE api_runtime_findings, api_call_edges, api_endpoints, applications CASCADE`); err != nil {
		t.Fatalf("truncate tables: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `TRUNCATE TABLE api_runtime_findings, api_call_edges, api_endpoints, applications CASCADE`)
	})

	appBig := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO applications (id, code, name, status) VALUES ($1, 'app-big', 'LargeApp', 'ONLINE')`, appBig); err != nil {
		t.Fatalf("insert appBig: %v", err)
	}

	const total = graphCandidateArrayThreshold + 120
	if _, err := pool.Exec(ctx, `
INSERT INTO api_endpoints (application_id, http_method, normalized_path, endpoint_key, is_api, asset_status, hit_count, host)
SELECT $1,
       'GET',
       CASE WHEN g <= 5 THEN '/static/img_' || g || '.png' ELSE '/api/v1/ep/' || g END,
       'GET ' || CASE WHEN g <= 5 THEN '/static/img_' || g || '.png' ELSE '/api/v1/ep/' || g END,
       true,
       'DISCOVERED',
       g,
       'big.local'
FROM generate_series(1, $2) g`, appBig, total); err != nil {
		t.Fatalf("seed endpoints: %v", err)
	}

	// 给静态噪声端点插超高 call_count 边，给正常端点插中等 call_count 边
	if _, err := pool.Exec(ctx, `
WITH eps AS (
    SELECT id, normalized_path, row_number() OVER (ORDER BY normalized_path) AS rn
    FROM api_endpoints WHERE application_id = $1
)
INSERT INTO api_call_edges (caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count, identity_count)
SELECT 'fp-' || e.rn, NULL, e.id,
       CASE WHEN e.normalized_path LIKE '/static/%' THEN 900000 + e.rn ELSE 1000 + e.rn END,
       1
FROM eps e
WHERE e.normalized_path LIKE '/static/%' OR e.rn <= 40`, appBig); err != nil {
		t.Fatalf("seed edges: %v", err)
	}

	store := NewStore(pool)
	f := GraphFilter{
		EdgeFilter:     EdgeFilter{Limit: 10},
		ApplicationID:  &appBig,
		ExcludeStatic:  true,
		ExcludeIgnored: true,
		OnlyConnected:  true,
	}
	got, err := store.ListGraphWithFilter(ctx, f)
	if err != nil {
		t.Fatalf("ListGraphWithFilter large branch: %v", err)
	}
	if len(got.Edges) != 10 || len(got.Nodes) != 10 {
		t.Fatalf("got nodes=%d edges=%d, want 10/10", len(got.Nodes), len(got.Edges))
	}
	for _, n := range got.Nodes {
		if isGraphStaticNoiseNode(n) {
			t.Fatalf("static noise node leaked into large branch result: %+v", n)
		}
	}
	// 验证与 bruteForceGraphParityOracle top-10 边（含排序）完全一致（静态超高流量边已在 SQL LIMIT 前被 excludedStaticIDs 排除）
	want := bruteForceGraphParityOracle(ctx, t, pool, f)
	if len(want.Edges) > 10 {
		want.Edges = want.Edges[:10]
	}
	if !reflect.DeepEqual(got.Edges, want.Edges) {
		t.Fatalf("large branch edges mismatch vs oracle:\n got: %+v\nwant: %+v", got.Edges, want.Edges)
	}
	if got.Summary.StaticNoiseNodes != 5 || got.Summary.TotalNodes != total {
		t.Fatalf("summary = %+v, want StaticNoiseNodes=5 TotalNodes=%d", got.Summary, total)
	}
	_ = fmt.Sprintf("verified %d nodes", len(got.Nodes))
}

func TestGraphMaxEdgeLimitTwoPhaseOrderingPG(t *testing.T) {
	pool, ctx := openAPISecurityGraphTestPG(t)

	if _, err := pool.Exec(ctx, `TRUNCATE TABLE api_runtime_findings, api_call_edges, api_endpoints, applications CASCADE`); err != nil {
		t.Fatalf("truncate tables: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `TRUNCATE TABLE api_runtime_findings, api_call_edges, api_endpoints, applications CASCADE`)
	})

	appSmall := uuid.New()
	appLarge := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO applications (id, code, name, status) VALUES ($1, 'app-sm', 'SmallApp', 'ONLINE'), ($2, 'app-lg', 'LargeApp', 'ONLINE')`, appSmall, appLarge); err != nil {
		t.Fatalf("insert apps: %v", err)
	}

	const smallEpCount = 50
	const largeEpCount = graphCandidateArrayThreshold + 50
	if _, err := pool.Exec(ctx, `
INSERT INTO api_endpoints (application_id, http_method, normalized_path, endpoint_key, is_api, asset_status, hit_count, host)
SELECT $1, 'GET', '/api/v1/sm/' || g, 'GET /api/v1/sm/' || g, true, 'DISCOVERED', g, 'sm.local'
FROM generate_series(1, $2) g`, appSmall, smallEpCount); err != nil {
		t.Fatalf("seed small endpoints: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO api_endpoints (application_id, http_method, normalized_path, endpoint_key, is_api, asset_status, hit_count, host)
SELECT $1, 'GET', '/api/v1/lg/' || g, 'GET /api/v1/lg/' || g, true, 'DISCOVERED', g, 'lg.local'
FROM generate_series(1, $2) g`, appLarge, largeEpCount); err != nil {
		t.Fatalf("seed large endpoints: %v", err)
	}

	// 写入 10,500 条含 128 字符宽 UTF-8 caller_fingerprint 且刻意制造 call_count 相等平局的边，
	// 验证两阶段窄排序在 MaxGraphEdgeLimit=10000 下的完整列回表与 (call_count DESC, id ASC) 严格序。
	const edgeCountPerApp = MaxGraphEdgeLimit + 500
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `
WITH eps AS (
    SELECT id, row_number() OVER (ORDER BY id) AS rn FROM api_endpoints WHERE application_id = $1
)
INSERT INTO api_call_edges (caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count, identity_count, first_seen_at, last_seen_at)
SELECT repeat('测', 110) || lpad(g::text, 18, '0'),
       s.id,
       t.id,
       (g % 2500) + 10,
       2,
       $3::timestamptz - interval '30 minutes',
       $3::timestamptz - interval '5 minutes'
FROM generate_series(1, $2) g
JOIN eps s ON s.rn = ((g * 7) % $4) + 1
JOIN eps t ON t.rn = ((g * 13) % $4) + 1`, appSmall, edgeCountPerApp, now, smallEpCount); err != nil {
		t.Fatalf("seed small edges: %v", err)
	}
	if _, err := pool.Exec(ctx, `
WITH eps AS (
    SELECT id, row_number() OVER (ORDER BY id) AS rn FROM api_endpoints WHERE application_id = $1
)
INSERT INTO api_call_edges (caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count, identity_count, first_seen_at, last_seen_at)
SELECT repeat('网', 110) || lpad(g::text, 18, '0'),
       s.id,
       t.id,
       (g % 2500) + 10,
       2,
       $3::timestamptz - interval '30 minutes',
       $3::timestamptz - interval '5 minutes'
FROM generate_series(1, $2) g
JOIN eps s ON s.rn = ((g * 7) % $4) + 1
JOIN eps t ON t.rn = ((g * 13) % $4) + 1`, appLarge, edgeCountPerApp, now, largeEpCount); err != nil {
		t.Fatalf("seed large edges: %v", err)
	}

	store := NewStore(pool)
	winStart := now.Add(-1 * time.Hour)
	winEnd := now

	cases := []struct {
		name string
		f    GraphFilter
	}{
		{
			name: "small_candidates_max_limit",
			f: GraphFilter{
				EdgeFilter:    EdgeFilter{Limit: MaxGraphEdgeLimit},
				ApplicationID: &appSmall,
				OnlyConnected: true,
			},
		},
		{
			name: "large_candidates_join_max_limit",
			f: GraphFilter{
				EdgeFilter:    EdgeFilter{Limit: MaxGraphEdgeLimit},
				ApplicationID: &appLarge,
				OnlyConnected: true,
			},
		},
		{
			name: "time_window_max_limit",
			f: GraphFilter{
				EdgeFilter: EdgeFilter{Start: &winStart, End: &winEnd, Limit: MaxGraphEdgeLimit},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.ListGraphWithFilter(ctx, tc.f)
			if err != nil {
				t.Fatalf("ListGraphWithFilter: %v", err)
			}
			if len(got.Edges) != MaxGraphEdgeLimit {
				t.Fatalf("len(got.Edges) = %d, want %d", len(got.Edges), MaxGraphEdgeLimit)
			}
			for i := 1; i < len(got.Edges); i++ {
				prev, curr := got.Edges[i-1], got.Edges[i]
				if curr.CallCount > prev.CallCount || (curr.CallCount == prev.CallCount && curr.ID.String() <= prev.ID.String()) {
					t.Fatalf("edge order broken at %d: prev=(%d,%s) curr=(%d,%s)", i, prev.CallCount, prev.ID, curr.CallCount, curr.ID)
				}
			}
			want := bruteForceGraphParityOracle(ctx, t, pool, tc.f)
			if len(want.Edges) > MaxGraphEdgeLimit {
				want.Edges = want.Edges[:MaxGraphEdgeLimit]
			}
			if !reflect.DeepEqual(got.Edges, want.Edges) {
				t.Fatalf("edges mismatch vs oracle (first diff around len %d vs %d)", len(got.Edges), len(want.Edges))
			}
			if got.Summary.VisibleEdges != MaxGraphEdgeLimit {
				t.Fatalf("Summary.VisibleEdges = %d, want %d", got.Summary.VisibleEdges, MaxGraphEdgeLimit)
			}
		})
	}
}
