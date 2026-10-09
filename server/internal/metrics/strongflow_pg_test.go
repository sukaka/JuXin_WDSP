// strongflow_pg_test.go 强流程运行指标 PG 契约（NG-FLOW-04 §1.9，Opt-in
// AUTHZ_TEST_PG_DSN）：种实例（五态/双应用/INDETERMINATE 滞留）与 step_events
// （RESERVE OK/CONFLICT/REJECTED，24h 窗口内外）→ CollectOnce → 快照行集逐项断言
// （分桶/积压/比率/时延>0/冲突率窗口口径/无数据应用缺席）。
package metrics

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func openStrongFlowMetricsPG(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("AUTHZ_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_PG_DSN not set, skipping strongflow metrics PG test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("create pg pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping pg: %v", err)
	}
	return pool, ctx
}

func TestStrongFlowMetricsPostgresContract(t *testing.T) {
	pool, ctx := openStrongFlowMetricsPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	var appA, appB, defA, defB string
	code := fmt.Sprintf("sfmx-%d", time.Now().UnixNano())
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&appA); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code+"b", code+"b").Scan(&appB); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_strong_flow_definitions(application_id,name,version,status,binding_path_prefix,instance_key_param) VALUES ($1,'f',1,'ACTIVE','/','query:o') RETURNING id`, appA).Scan(&defA); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_strong_flow_definitions(application_id,name,version,status,binding_path_prefix,instance_key_param) VALUES ($1,'f',1,'ACTIVE','/','query:o') RETURNING id`, appB).Scan(&defB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_step_events WHERE instance_id IN (SELECT id FROM api_strong_flow_instances WHERE application_id IN ($1,$2))`, appA, appB)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_instances WHERE application_id IN ($1,$2)`, appA, appB)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_steps WHERE definition_id IN ($1,$2)`, defA, defB)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_definitions WHERE id IN ($1,$2)`, defA, defB)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id IN ($1,$2)`, appA, appB)
	})
	mkInst := func(appID, defID, status string, version int, updatedAgo time.Duration) string {
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO api_strong_flow_instances(application_id,definition_id,definition_version,instance_key,status,updated_at)
			VALUES ($1,$2,1,$3,$4, now() - $5::interval) RETURNING id`,
			appID, defID, fmt.Sprintf("sfref:%064x", version), status, fmt.Sprintf("%d seconds", int(updatedAgo.Seconds()))).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	// appA：ACTIVE×2 / CONFIRMED×3 / INDETERMINATE×1（滞留 1h）
	i1 := mkInst(appA, defA, "ACTIVE", 1, 0)
	mkInst(appA, defA, "ACTIVE", 2, 0)
	mkInst(appA, defA, "CONFIRMED", 3, 0)
	mkInst(appA, defA, "CONFIRMED", 4, 0)
	mkInst(appA, defA, "CONFIRMED", 5, 0)
	i6 := mkInst(appA, defA, "INDETERMINATE", 6, time.Hour)
	// appB：CONFIRMED×1（无积压无冲突）
	mkInst(appB, defB, "CONFIRMED", 7, 0)
	// appA step_events（24h 内：RESERVE OK×3 / CONFLICT×1 / REJECTED×1；24h 外 REJECTED×9 不计）
	evSeq := 0
	mkEv := func(instID, action, result string, ago time.Duration) {
		evSeq++
		if _, err := pool.Exec(ctx, `INSERT INTO api_strong_flow_step_events(instance_id,step_key,action,fencing_token,result,reason_code,occurred_at)
			VALUES ($1,'pay',$2,$3,$4,'', now() - $5::interval)`,
			instID, action, evSeq, result, fmt.Sprintf("%d seconds", int(ago.Seconds()))); err != nil {
			t.Fatal(err)
		}
	}
	mkEv(i1, "RESERVE", "OK", 0)
	mkEv(i1, "RESERVE", "OK", 0)
	mkEv(i1, "RESERVE", "OK", 0)
	mkEv(i1, "RESERVE", "CONFLICT", 0)
	mkEv(i6, "RESERVE", "REJECTED", 0)
	mkEv(i6, "RESERVE", "REJECTED", 48*time.Hour) // 窗口外不计
	mkEv(i6, "COMMIT", "REJECTED", 0)             // 非 RESERVE 动作不计

	c := NewAPICollector(pool)
	if err := c.CollectOnce(ctx); err != nil {
		t.Fatalf("collect: %v", err)
	}
	snap := c.Snapshot()
	byApp := map[string]StrongFlowAppMetrics{}
	for _, m := range snap.StrongFlow {
		byApp[m.ApplicationID] = m
	}
	a, ok := byApp[appA]
	if !ok {
		t.Fatalf("appA 行集缺席: %+v", snap.StrongFlow)
	}
	if a.InstancesByStatus["ACTIVE"] != 2 || a.InstancesByStatus["CONFIRMED"] != 3 ||
		a.InstancesByStatus["INDETERMINATE"] != 1 || a.InstancesByStatus["CANCELLED"] != 0 {
		t.Fatalf("appA 分桶: %+v", a.InstancesByStatus)
	}
	if a.IndeterminateBacklog != 1 {
		t.Fatalf("积压: %d", a.IndeterminateBacklog)
	}
	if got := a.IndeterminateRatio; got < 0.166 || got > 0.167 {
		t.Fatalf("比率: %v（want ≈1/6）", got)
	}
	if a.IndeterminateAgeAvgSeconds < 3500 || a.IndeterminateAgeMaxSeconds < 3500 {
		t.Fatalf("滞留时延应 ≈3600s: avg=%v max=%v", a.IndeterminateAgeAvgSeconds, a.IndeterminateAgeMaxSeconds)
	}
	// 冲突率：窗口内 RESERVE 5（OK3+CONFLICT1+REJECTED1）→ 2/5=0.4；窗口外与非 RESERVE 不计
	if a.ReserveTotal24h != 5 || a.ReserveConflict24h != 2 || a.ReserveConflictRatio != 0.4 {
		t.Fatalf("冲突率: %d/%d/%v", a.ReserveTotal24h, a.ReserveConflict24h, a.ReserveConflictRatio)
	}
	// appB：有行集（实例存在）但积压/冲突全 0
	b, ok := byApp[appB]
	if !ok {
		t.Fatalf("appB 行集缺席")
	}
	if b.InstancesByStatus["CONFIRMED"] != 1 || b.IndeterminateBacklog != 0 ||
		b.IndeterminateRatio != 0 || b.ReserveConflictRatio != 0 || b.IndeterminateAgeMaxSeconds != 0 {
		t.Fatalf("appB 零值口径: %+v", b)
	}
	// 渲染段端到端（含 label 形状）
	out := c.Render()
	if got := len(out); got == 0 || !containsAll(out, []string{
		`strong_flow_instances{application_id="` + appA + `",status="INDETERMINATE"} 1`,
		`strong_flow_reserve_conflict_ratio{application_id="` + appA + `"} 0.4`,
	}) {
		t.Fatalf("渲染段:\n%s", out)
	}
}

func containsAll(s string, subs []string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
