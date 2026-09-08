// stage8_api_call_edges_test.go 调用边生产方与图谱/拓扑读接口增强（WDSP P1-09/P1-10，W6-A）集成测试。
// 覆盖：aggregations.RunCallEdges 从 api_runtime_events 派生 from→to 调用边 upsert
// api_call_edges（同身份 10 分钟会话窗口内连续调用成边；匿名整体排除；端点未解析截断
// 序列；自环不成边）；水位幂等（重跑不重复计数）与增量推进（新事件只加新观测）；
// GET /api/v1/api-security/graph|topology 真实返回边 + start/end/min_count 过滤
// （非法值 400）+ 节点 open_findings_count（活动态 findings 计数）。
// 真实 PostgreSQL/Valkey，无口令环境 t.Skip（纪律同 stage8_api_security_test.go）。
package tests

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// callEdgeEventSeed 造数用事件种子。
type callEdgeEventSeed struct {
	reqID    string
	identity string // 空串 = 匿名
	at       time.Time
}

// s8CallEdgeSaveEvents 批量落运行时事件（经真实 SavePrimary；endpoint_key 归属指定端点）。
func s8CallEdgeSaveEvents(t *testing.T, env *testEnv, endpointKey string, seeds []callEdgeEventSeed) {
	t.Helper()
	rt := apiruntime.NewStore(env.db)
	for _, s := range seeds {
		err := rt.SavePrimary(context.Background(), &apiruntime.PrimaryEvent{
			PrimaryEvent: events.PrimaryEvent{
				RequestID: s.reqID, EndpointKey: endpointKey,
				RiskScore: 10, RiskLevel: "LOW", FinalAction: "LOG",
				OccurredAt: s.at,
			},
			IdentityFingerprint: s.identity,
			AuthType:            "api_key",
			ResponseStatus:      200,
		})
		if err != nil {
			t.Fatalf("SavePrimary %s: %v", s.reqID, err)
		}
	}
}

// s8EdgeRow 从库内读回一条调用边的核心字段（断言用）。
func s8EdgeRow(t *testing.T, env *testEnv, caller string, sourceID, targetID uuid.UUID) (count int64, first, last time.Time) {
	t.Helper()
	err := env.db.QueryRow(context.Background(), `
SELECT call_count, first_seen_at, last_seen_at FROM api_call_edges
WHERE caller_fingerprint=$1 AND source_endpoint_id=$2 AND target_endpoint_id=$3`,
		caller, sourceID, targetID).Scan(&count, &first, &last)
	if err != nil {
		t.Fatalf("read edge %s %s->%s: %v", caller, sourceID, targetID, err)
	}
	return count, first, last
}

// s8GraphEdges 解析 graph/topology 响应中的边数组。
func s8GraphEdges(t *testing.T, data map[string]interface{}, what string) []interface{} {
	t.Helper()
	edges, ok := data["edges"].([]interface{})
	if !ok {
		t.Fatalf("%s: edges 字段缺失或非数组: %v", what, data)
	}
	return edges
}

func TestStage8ApiCallEdges(t *testing.T) {
	env := setupStage8Env(t)
	cookies, _ := env.s5Login(t, "s8ce", "SECURITY_ADMIN")
	ctx := context.Background()
	kw := "s8ce" + s5Rand()
	jobs := aggregations.NewJobs(aggregations.NewStore(env.db))

	// 空表安全：无任何事件时派生返回零值、不报错；首轮无水位不写任务记录
	res, err := jobs.RunCallEdges(ctx)
	if err != nil {
		t.Fatalf("RunCallEdges on empty tables: %v", err)
	}
	if res.EventsScanned != 0 || res.EdgesUpserted != 0 || res.HasMore {
		t.Errorf("empty sweep = %+v, want all zero", res)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM aggregation_jobs WHERE job_type='CALL_EDGES'`); n != 0 {
		t.Fatalf("first empty sweep job rows = %d, want 0（无水位不记录，下轮仍全量回填）", n)
	}

	// 造数：三个端点
	epA := s8SeedEndpoint(t, env, "GET", "/"+kw+"/users/{id}", 0.9)
	epB := s8SeedEndpoint(t, env, "POST", "/"+kw+"/orders", 0.9)
	epC := s8SeedEndpoint(t, env, "GET", "/"+kw+"/orders/{id}", 0.9)

	fp1 := "fp1-" + s5Rand()
	fp2 := "fp2-" + s5Rand()
	t0 := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)

	// fp1 序列：A(0) → B(+2m) → C(+4m) → 未知端点(+5m，截断) → A(+6m) → B(+8m)
	s8CallEdgeSaveEvents(t, env, epA.EndpointKey, []callEdgeEventSeed{
		{kw + "-a1", fp1, t0},
		{kw + "-a2", fp1, t0.Add(6 * time.Minute)},
	})
	s8CallEdgeSaveEvents(t, env, epB.EndpointKey, []callEdgeEventSeed{
		{kw + "-b1", fp1, t0.Add(2 * time.Minute)},
		{kw + "-b2", fp1, t0.Add(8 * time.Minute)},
		{kw + "-b3", fp2, t0.Add(1 * time.Minute)}, // fp2: B(+1m)
	})
	s8CallEdgeSaveEvents(t, env, epC.EndpointKey, []callEdgeEventSeed{
		{kw + "-c1", fp1, t0.Add(4 * time.Minute)},
		{kw + "-c2", fp2, t0.Add(3 * time.Minute)}, // fp2: → C(+3m)
	})
	// 端点未解析事件（endpoint_key 不在 api_endpoints）：fp1 序列截断点（C→A 不成边）
	s8CallEdgeSaveEvents(t, env, "GET /"+kw+"-unknown/{id}", []callEdgeEventSeed{
		{kw + "-x1", fp1, t0.Add(5 * time.Minute)},
	})
	// 匿名事件：即使构成 A→B 序列也不产边（§2.2 边界规则：匿名身份维度不可信）
	s8CallEdgeSaveEvents(t, env, epA.EndpointKey, []callEdgeEventSeed{{kw + "-n1", "", t0.Add(2 * time.Minute)}})
	s8CallEdgeSaveEvents(t, env, epB.EndpointKey, []callEdgeEventSeed{{kw + "-n2", "", t0.Add(3 * time.Minute)}})

	// 首轮派生：扫描 8 条非匿名事件（fp1 六条含未解析一条 + fp2 两条；匿名两条被 SQL 排除）
	res, err = jobs.RunCallEdges(ctx)
	if err != nil {
		t.Fatalf("RunCallEdges: %v", err)
	}
	if res.EventsScanned != 8 || res.SkippedNoEndpoint != 1 {
		t.Errorf("sweep scanned/skipped = %d/%d, want 8/1", res.EventsScanned, res.SkippedNoEndpoint)
	}
	if res.EdgesUpserted != 3 || res.Watermark == nil {
		t.Errorf("sweep edges = %d watermark = %v, want 3 条边且水位推进", res.EdgesUpserted, res.Watermark)
	}

	// 边明细：fp1 A→B 观测 2 次（+2m/+8m）；fp1 B→C、fp2 B→C 各 1 次
	if n := s8Count(t, env, `SELECT count(*) FROM api_call_edges`); n != 3 {
		t.Fatalf("edge rows = %d, want 3", n)
	}
	cnt, first, last := s8EdgeRow(t, env, fp1, epA.ID, epB.ID)
	if cnt != 2 || !first.Equal(t0.Add(2*time.Minute)) || !last.Equal(t0.Add(8*time.Minute)) {
		t.Errorf("fp1 A→B = count %d first %v last %v, want 2 / +2m / +8m", cnt, first, last)
	}
	if cnt, _, _ = s8EdgeRow(t, env, fp1, epB.ID, epC.ID); cnt != 1 {
		t.Errorf("fp1 B→C count = %d, want 1", cnt)
	}
	if cnt, _, _ = s8EdgeRow(t, env, fp2, epB.ID, epC.ID); cnt != 1 {
		t.Errorf("fp2 B→C count = %d, want 1", cnt)
	}
	// 匿名不产边；截断点前后不连边（无 C→A）
	if n := s8Count(t, env, `SELECT count(*) FROM api_call_edges WHERE caller_fingerprint=''`); n != 0 {
		t.Errorf("anonymous edges = %d, want 0", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_call_edges WHERE source_endpoint_id=$1 AND target_endpoint_id=$2`,
		epC.ID, epA.ID); n != 0 {
		t.Errorf("C→A edge across unresolved event = %d, want 0", n)
	}
	// 任务记录：CALL_EDGES SUCCESS 一条，rows_written=3
	if n := s8Count(t, env,
		`SELECT count(*) FROM aggregation_jobs WHERE job_type='CALL_EDGES' AND status='SUCCESS' AND rows_written=3`); n != 1 {
		t.Errorf("CALL_EDGES SUCCESS(3) job rows = %d, want 1", n)
	}

	// 水位幂等：立即重跑不回填计数（回看事件全部 ≤ 水位被过滤）
	res, err = jobs.RunCallEdges(ctx)
	if err != nil {
		t.Fatalf("RunCallEdges rerun: %v", err)
	}
	if res.EdgesUpserted != 0 {
		t.Errorf("rerun edges upserted = %d, want 0（水位幂等）", res.EdgesUpserted)
	}
	if cnt, _, _ = s8EdgeRow(t, env, fp1, epA.ID, epB.ID); cnt != 2 {
		t.Errorf("rerun fp1 A→B count = %d, want 2（不重复计数）", cnt)
	}

	// 增量推进：fp1 新事件 C(+10m)（距 B(+8m) 在窗口内）→ fp1 B→C 观测 +1，其余不变
	s8CallEdgeSaveEvents(t, env, epC.EndpointKey, []callEdgeEventSeed{{kw + "-c3", fp1, t0.Add(10 * time.Minute)}})
	res, err = jobs.RunCallEdges(ctx)
	if err != nil {
		t.Fatalf("RunCallEdges incremental: %v", err)
	}
	if res.EdgesUpserted != 1 {
		t.Errorf("incremental edges upserted = %d, want 1（仅 fp1 B→C 新观测）", res.EdgesUpserted)
	}
	if cnt, _, last = s8EdgeRow(t, env, fp1, epB.ID, epC.ID); cnt != 2 || !last.Equal(t0.Add(10*time.Minute)) {
		t.Errorf("incremental fp1 B→C = count %d last %v, want 2 / +10m", cnt, last)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_call_edges`); n != 3 {
		t.Errorf("incremental edge rows = %d, want 3（不产生新边键）", n)
	}

	// 未闭环 findings 造数：epA 一条 NEW（活动态，计入），epB 一条 RESOLVED（不计入）
	s8Exec(t, env, `INSERT INTO api_runtime_findings (endpoint_id, finding_type, severity, status, title)
		VALUES ($1, 'BOLA', 'HIGH', 'NEW', 'w6a 测试发现')`, epA.ID)
	s8Exec(t, env, `INSERT INTO api_runtime_findings (endpoint_id, finding_type, severity, status, title)
		VALUES ($1, 'SHADOW', 'LOW', 'RESOLVED', 'w6a 已闭环发现')`, epB.ID)

	// 图谱读接口：真实返回 3 条边；节点带 open_findings_count
	result := s5OK(t, env.get(t, "/api/v1/api-security/graph", cookies), "graph with edges")
	edges := s8GraphEdges(t, result.Data, "graph")
	if len(edges) != 3 {
		t.Fatalf("graph edges = %d, want 3", len(edges))
	}
	edge0, _ := edges[0].(map[string]interface{})
	if edge0["caller_fingerprint"] == "" || edge0["target_endpoint_id"] == "" || edge0["call_count"] == nil ||
		edge0["first_seen_at"] == "" || edge0["last_seen_at"] == "" {
		t.Errorf("edge item fields incomplete: %v", edge0)
	}
	nodeFound := false
	for _, nv := range result.Data["nodes"].([]interface{}) {
		n, _ := nv.(map[string]interface{})
		if n["id"] == epA.ID.String() {
			nodeFound = true
			if n["open_findings_count"] != float64(1) {
				t.Errorf("epA open_findings_count = %v, want 1（仅活动态 NEW 计入）", n["open_findings_count"])
			}
		}
		if n["id"] == epB.ID.String() && n["open_findings_count"] != float64(0) {
			t.Errorf("epB open_findings_count = %v, want 0（RESOLVED 不计入）", n["open_findings_count"])
		}
	}
	if !nodeFound {
		t.Error("graph nodes missing epA")
	}

	// 边过滤：min_count=2 → fp1 的两条边（A→B、B→C 各观测 2 次），fp2 B→C(1 次) 被滤掉
	result = s5OK(t, env.get(t, "/api/v1/api-security/graph?min_count=2", cookies), "graph min_count=2")
	if edges = s8GraphEdges(t, result.Data, "graph min_count"); len(edges) != 2 {
		t.Errorf("min_count=2 edges = %d, want 2", len(edges))
	}
	// 时间窗：start=+5m → last_seen_at >= +5m 的边（fp1 A→B +8m、fp1 B→C +10m）
	start := t0.Add(5 * time.Minute).Format(time.RFC3339)
	result = s5OK(t, env.get(t, "/api/v1/api-security/graph?start="+start, cookies), "graph start")
	if edges = s8GraphEdges(t, result.Data, "graph start"); len(edges) != 2 {
		t.Errorf("start=+5m edges = %d, want 2", len(edges))
	}
	// end=+3m → first_seen_at <= +3m 的边（fp1 A→B +2m、fp2 B→C +3m）
	end := t0.Add(3 * time.Minute).Format(time.RFC3339)
	result = s5OK(t, env.get(t, "/api/v1/api-security/graph?end="+end, cookies), "graph end")
	if edges = s8GraphEdges(t, result.Data, "graph end"); len(edges) != 2 {
		t.Errorf("end=+3m edges = %d, want 2", len(edges))
	}
	// 组合：start=+9m（last_seen_at >= +9m 只剩 fp1 B→C +10m）& min_count=2 → 恰好 1 条
	result = s5OK(t, env.get(t,
		fmt.Sprintf("/api/v1/api-security/graph?start=%s&min_count=2",
			t0.Add(9*time.Minute).Format(time.RFC3339)), cookies), "graph combined")
	if edges = s8GraphEdges(t, result.Data, "graph combined"); len(edges) != 1 {
		t.Errorf("combined filter edges = %d, want 1", len(edges))
	}
	// 非法过滤值：一律 400（不静默忽略）
	for _, q := range []string{"start=not-a-time", "end=2026-13-99", "min_count=-1", "min_count=abc",
		"start=" + t0.Add(9*time.Minute).Format(time.RFC3339) + "&end=" + start} {
		resp := env.get(t, "/api/v1/api-security/graph?"+q, cookies)
		s5Expect(t, resp, http.StatusBadRequest, "graph filter "+q)
	}

	// 拓扑读接口：边真实返回 + 过滤生效；节点（应用分组内）带 open_findings_count
	result = s5OK(t, env.get(t, "/api/v1/api-security/topology", cookies), "topology with edges")
	if edges = s8GraphEdges(t, result.Data, "topology"); len(edges) != 3 {
		t.Errorf("topology edges = %d, want 3", len(edges))
	}
	topoNodeFound := false
	for _, av := range result.Data["applications"].([]interface{}) {
		app, _ := av.(map[string]interface{})
		for _, nv := range app["endpoints"].([]interface{}) {
			n, _ := nv.(map[string]interface{})
			if n["id"] == epA.ID.String() {
				topoNodeFound = true
				if n["open_findings_count"] != float64(1) {
					t.Errorf("topology epA open_findings_count = %v, want 1", n["open_findings_count"])
				}
			}
		}
	}
	if !topoNodeFound {
		t.Error("topology endpoints missing epA")
	}
	result = s5OK(t, env.get(t, "/api/v1/api-security/topology?min_count=2", cookies), "topology min_count=2")
	if edges = s8GraphEdges(t, result.Data, "topology min_count"); len(edges) != 2 {
		t.Errorf("topology min_count=2 edges = %d, want 2", len(edges))
	}

	// 权限底线：未登录访问 401
	resp := env.do(t, http.MethodGet, "/api/v1/api-security/graph", "", nil, "")
	s5Expect(t, resp, http.StatusUnauthorized, "unauthenticated graph query")
}
