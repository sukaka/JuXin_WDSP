// stage8_api_call_edges_identity_count_test.go 调用边身份计数（W11-GRAPH，迁移 000067）集成测试。
// 覆盖：
//  1. 派生侧 identity_count 近似口径（近似下界）：新身份指纹首见该边插入计 1；
//     同身份批内重复经过、跨批增量重复经过均只累 call_count、不增 identity_count；
//  2. 读接口 GET /api/v1/api-security/graph|topology 边响应带 identity_count；
//  3. 迁移 000067 up/down：down 去列去索引；存量重复行（无唯一约束期间遗留，
//     含 NULL 源行）在 up 时按自然键 (caller, source, target) 合并去重
//     （call_count 求和、首末观测取极值、identity_count 保持 1）；
//     唯一索引重建后同键直插被拒（派生侧 ON CONFLICT 的兜底）。
//
// 迁移执行方式说明：database.Migrate("down") 只回滚当前最高版本，同波其他分片
// 新增迁移编号后回滚目标会漂移，故本用例直接执行 000067 的 down/up 文件
// （测试库每用例重建，直接执行不污染 schema_migrations 之外的任何状态）。
// 真实 PostgreSQL/Valkey，无口令环境 t.Skip（纪律同 stage8_api_call_edges_test.go）。
package tests

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aggregations"
)

// s8icEdgeRow 读回一条调用边的计数字段（断言用）。
func s8icEdgeRow(t *testing.T, env *testEnv, caller string, sourceID, targetID uuid.UUID) (callCount, identityCount int64, first, last time.Time) {
	t.Helper()
	err := env.db.QueryRow(context.Background(), `
SELECT call_count, identity_count, first_seen_at, last_seen_at FROM api_call_edges
WHERE caller_fingerprint=$1 AND source_endpoint_id=$2 AND target_endpoint_id=$3`,
		caller, sourceID, targetID).Scan(&callCount, &identityCount, &first, &last)
	if err != nil {
		t.Fatalf("read edge %s %s->%s: %v", caller, sourceID, targetID, err)
	}
	return callCount, identityCount, first, last
}

// s8icExecMigrationFile 直接执行指定迁移文件（up/down 全流程用例专用，见文件头说明）。
func s8icExecMigrationFile(t *testing.T, env *testEnv, path string) {
	t.Helper()
	sql, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration %s: %v", path, err)
	}
	if _, err := env.db.Exec(context.Background(), string(sql)); err != nil {
		t.Fatalf("exec migration %s: %v", path, err)
	}
}

func TestStage8ApiCallEdgesIdentityCount(t *testing.T) {
	env := setupStage8Env(t)
	cookies, _ := env.s5Login(t, "s8ic", "SECURITY_ADMIN")
	ctx := context.Background()
	kw := "s8ic" + s5Rand()
	jobs := aggregations.NewJobs(aggregations.NewStore(env.db))

	epA := s8SeedEndpoint(t, env, "GET", "/"+kw+"/users/{id}", 0.9)
	epB := s8SeedEndpoint(t, env, "POST", "/"+kw+"/orders", 0.9)

	fp1 := "ic-fp1-" + s5Rand()
	fp2 := "ic-fp2-" + s5Rand()
	t0 := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)

	// ---- 派生侧 identity_count 近似口径 ----
	// fp1 同批两趟 A→B（t0→+2m、+5m→+7m；中间 +4m 未解析事件截断序列，
	// 避免 B(+2m)→A(+5m) 另产反向边）；fp2 一趟 A→B（+1m→+3m）
	s8CallEdgeSaveEvents(t, env, epA.EndpointKey, []callEdgeEventSeed{
		{kw + "-a1", fp1, t0},
		{kw + "-a2", fp1, t0.Add(5 * time.Minute)},
		{kw + "-a3", fp2, t0.Add(1 * time.Minute)},
	})
	s8CallEdgeSaveEvents(t, env, epB.EndpointKey, []callEdgeEventSeed{
		{kw + "-b1", fp1, t0.Add(2 * time.Minute)},
		{kw + "-b2", fp1, t0.Add(7 * time.Minute)},
		{kw + "-b3", fp2, t0.Add(3 * time.Minute)},
	})
	// 端点未解析事件：fp1 序列截断点（口径同 W6-A，A→未知→A 不断言连边）
	s8CallEdgeSaveEvents(t, env, "GET /"+kw+"-unknown/{id}", []callEdgeEventSeed{
		{kw + "-x1", fp1, t0.Add(4 * time.Minute)},
	})
	res, err := jobs.RunCallEdges(ctx)
	if err != nil {
		t.Fatalf("RunCallEdges: %v", err)
	}
	if res.EventsScanned != 7 || res.SkippedNoEndpoint != 1 || res.EdgesUpserted != 2 {
		t.Fatalf("sweep = scanned %d skipped %d edges %d, want 7/1/2（fp1/fp2 各一条 A→B）",
			res.EventsScanned, res.SkippedNoEndpoint, res.EdgesUpserted)
	}
	// fp1 批内重复经过：call_count=2，identity_count=1（批内 distinct，同身份不增）
	if call, idc, _, _ := s8icEdgeRow(t, env, fp1, epA.ID, epB.ID); call != 2 || idc != 1 {
		t.Errorf("fp1 A→B = call %d identity %d, want 2/1", call, idc)
	}
	if call, idc, _, _ := s8icEdgeRow(t, env, fp2, epA.ID, epB.ID); call != 1 || idc != 1 {
		t.Errorf("fp2 A→B = call %d identity %d, want 1/1", call, idc)
	}

	// 跨批增量：fp1 再一趟 A→B（+18m→+20m，ON CONFLICT 路径；距上一批 B(+7m)
	// 超窗，不产 B→A 反向边）——call_count 照累，identity_count 不增
	s8CallEdgeSaveEvents(t, env, epA.EndpointKey, []callEdgeEventSeed{{kw + "-a4", fp1, t0.Add(18 * time.Minute)}})
	s8CallEdgeSaveEvents(t, env, epB.EndpointKey, []callEdgeEventSeed{{kw + "-b4", fp1, t0.Add(20 * time.Minute)}})
	if res, err = jobs.RunCallEdges(ctx); err != nil {
		t.Fatalf("RunCallEdges incremental: %v", err)
	}
	if res.EdgesUpserted != 1 {
		t.Errorf("incremental edges upserted = %d, want 1", res.EdgesUpserted)
	}
	call, idc, _, last := s8icEdgeRow(t, env, fp1, epA.ID, epB.ID)
	if call != 3 || idc != 1 || !last.Equal(t0.Add(20*time.Minute)) {
		t.Errorf("incremental fp1 A→B = call %d identity %d last %v, want 3/1/+20m（同身份重复经过不增）", call, idc, last)
	}

	// ---- 读接口：graph/topology 边带 identity_count ----
	result := s5OK(t, env.get(t, "/api/v1/api-security/graph", cookies), "graph identity_count")
	edges := s8GraphEdges(t, result.Data, "graph")
	if len(edges) != 2 {
		t.Fatalf("graph edges = %d, want 2", len(edges))
	}
	for _, ev := range edges {
		e, _ := ev.(map[string]interface{})
		if e["identity_count"] != float64(1) {
			t.Errorf("graph edge identity_count = %v, want 1: %v", e["identity_count"], e)
		}
	}
	result = s5OK(t, env.get(t, "/api/v1/api-security/topology", cookies), "topology identity_count")
	edges = s8GraphEdges(t, result.Data, "topology")
	if len(edges) != 2 {
		t.Fatalf("topology edges = %d, want 2", len(edges))
	}
	for _, ev := range edges {
		e, _ := ev.(map[string]interface{})
		if _, ok := e["identity_count"]; !ok {
			t.Errorf("topology edge missing identity_count: %v", e)
		}
	}

	// ---- 迁移 000067 down：列/索引回滚 ----
	s8icExecMigrationFile(t, env, "../migrations/000067_api_call_edges_identity_count.down.sql")
	if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
		WHERE table_name='api_call_edges' AND column_name='identity_count'`); n != 0 {
		t.Errorf("after down identity_count columns = %d, want 0", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM pg_indexes
		WHERE tablename='api_call_edges' AND indexname='uq_api_call_edges_caller_source_target'`); n != 0 {
		t.Errorf("after down unique index = %d, want 0", n)
	}
	// 派生的两条边数据保留（down 只还原结构，不动数据）
	if n := s8Count(t, env, `SELECT count(*) FROM api_call_edges`); n != 2 {
		t.Fatalf("after down edge rows = %d, want 2（结构回滚不动数据）", n)
	}

	// ---- 存量重复行（无唯一约束期间可写，含 NULL 源行）----
	fpL := "ic-fpl-" + s5Rand()
	d1a := t0.Add(30 * time.Minute) // 全场最早 first（行1）
	d1b := t0.Add(31 * time.Minute)
	d2a := t0.Add(33 * time.Minute)
	d2b := t0.Add(35 * time.Minute) // 全场最晚 last（行2）
	s8Exec(t, env, `INSERT INTO api_call_edges (caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, 2, $4, $5)`, fpL, epA.ID, epB.ID, d1a, d1b)
	s8Exec(t, env, `INSERT INTO api_call_edges (caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, 3, $4, $5)`, fpL, epA.ID, epB.ID, d2a, d2b)
	s8Exec(t, env, `INSERT INTO api_call_edges (caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count, first_seen_at, last_seen_at)
		VALUES ($1, NULL, $2, 1, $3, $3)`, fpL, epB.ID, d1a)
	s8Exec(t, env, `INSERT INTO api_call_edges (caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count, first_seen_at, last_seen_at)
		VALUES ($1, NULL, $2, 4, $3, $4)`, fpL, epB.ID, d2a, d2b)
	if n := s8Count(t, env, `SELECT count(*) FROM api_call_edges`); n != 6 {
		t.Fatalf("seeded legacy rows = %d, want 6（2 派生 + 4 存量重复）", n)
	}

	// ---- 迁移 000067 up：去重合并 + 加列 + 建唯一索引 ----
	s8icExecMigrationFile(t, env, "../migrations/000067_api_call_edges_identity_count.up.sql")
	if n := s8Count(t, env, `SELECT count(*) FROM api_call_edges`); n != 4 {
		t.Errorf("after re-up edge rows = %d, want 4（两键各合并为一行）", n)
	}
	// (fpL, A, B)：2+3=5 次，first/last 取两行极值（分属不同行），identity_count=1（同键即同身份，不求和）
	call, idc, first, last := s8icEdgeRow(t, env, fpL, epA.ID, epB.ID)
	if call != 5 || idc != 1 || !first.Equal(d1a) || !last.Equal(d2b) {
		t.Errorf("merged fpL A→B = call %d identity %d first %v last %v, want 5/1/%v/%v", call, idc, first, last, d1a, d2b)
	}
	// (fpL, NULL, B)：1+4=5 次，同样合并（NULLS NOT DISTINCT 口径下 NULL 源同键）
	var nullCnt int
	var nullCall, nullIDc int64
	if err := env.db.QueryRow(ctx, `SELECT count(*), COALESCE(sum(call_count),0), COALESCE(max(identity_count),0)
		FROM api_call_edges WHERE caller_fingerprint=$1 AND source_endpoint_id IS NULL AND target_endpoint_id=$2`,
		fpL, epB.ID).Scan(&nullCnt, &nullCall, &nullIDc); err != nil {
		t.Fatalf("read merged NULL-source edge: %v", err)
	}
	if nullCnt != 1 || nullCall != 5 || nullIDc != 1 {
		t.Errorf("merged fpL NULL→B = rows %d call %d identity %d, want 1/5/1", nullCnt, nullCall, nullIDc)
	}
	// 列/索引重建
	if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
		WHERE table_name='api_call_edges' AND column_name='identity_count'`); n != 1 {
		t.Errorf("after re-up identity_count columns = %d, want 1", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM pg_indexes
		WHERE tablename='api_call_edges' AND indexname='uq_api_call_edges_caller_source_target'`); n != 1 {
		t.Errorf("after re-up unique index = %d, want 1", n)
	}
	// 唯一索引兜底：同键直插被拒（派生侧 ON CONFLICT 依赖该约束）
	if _, err := env.db.Exec(ctx, `INSERT INTO api_call_edges (caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count)
		VALUES ($1, $2, $3, 1)`, fpL, epA.ID, epB.ID); err == nil ||
		!strings.Contains(err.Error(), "uq_api_call_edges_caller_source_target") {
		t.Errorf("duplicate natural-key insert err = %v, want unique violation", err)
	}
	// 重新迁移后派生链路健康：无新事件空跑不报错、不产边
	if res, err = jobs.RunCallEdges(ctx); err != nil {
		t.Fatalf("RunCallEdges after re-up: %v", err)
	}
	if res.EdgesUpserted != 0 {
		t.Errorf("after re-up rerun edges upserted = %d, want 0（水位幂等）", res.EdgesUpserted)
	}
}
