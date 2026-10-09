// strongflow_pg_test.go 强流程发布面育龄窗 PG 契约（联调裁决 §8.4-1 闭环）：
// 发布面 = ACTIVE ∪ 存在非终态实例（ACTIVE/INDETERMINATE）的 RETIRED 版本；
// DRAFT 不入、RETIRED 无非终态实例自然掉出、终态实例（CONFIRMED）不带回；
// status 原文透传（网关「ACTIVE 才可建实例」闸的消费输入）。
// Opt-in（AUTHZ_TEST_PG_DSN）——单元运行不需要活动数据库。
package guardconfig

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func openStrongFlowPublishPG(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("AUTHZ_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_PG_DSN not set, skipping strongflow publish PG test")
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

func TestStrongFlowPublishWindowPostgresContract(t *testing.T) {
	pool, ctx := openStrongFlowPublishPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	code := fmt.Sprintf("sfpw-%d", time.Now().UnixNano())
	var appID string
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&appID); err != nil {
		t.Fatalf("insert application: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_step_events WHERE instance_id IN (SELECT id FROM api_strong_flow_instances WHERE application_id=$1)`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_instances WHERE application_id=$1`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_steps WHERE definition_id IN (SELECT id FROM api_strong_flow_definitions WHERE application_id=$1)`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_definitions WHERE application_id=$1`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, appID)
	})
	mkDef := func(version int, status string) string {
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO api_strong_flow_definitions(application_id,name,version,status,binding_path_prefix,instance_key_param)
			VALUES ($1,'f',$2,$3,'/','query:o') RETURNING id`, appID, version, status).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO api_strong_flow_steps(definition_id,step_key,endpoint_key,sequence,success_rule,timeout_seconds,retry_semantics,lease_seconds)
			VALUES ($1,'s1','POST /a',1,'{"status_codes":[200]}',30,'IDEMPOTENT',60)`, id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	mkInst := func(defID string, version int, instStatus string, refSeed int) {
		if _, err := pool.Exec(ctx, `INSERT INTO api_strong_flow_instances(application_id,definition_id,definition_version,instance_key,status)
			VALUES ($1,$2,$3,$4,$5)`, appID, defID, version, fmt.Sprintf("sfref:%064x", refSeed), instStatus); err != nil {
			t.Fatal(err)
		}
	}
	mkDef(1, "ACTIVE")        // ACTIVE 恒入
	mkDef(2, "DRAFT")         // DRAFT 不入
	mkDef(3, "RETIRED")       // RETIRED 无实例 → 掉出
	v4 := mkDef(4, "RETIRED") // RETIRED + ACTIVE 实例 → 育龄窗入
	v5 := mkDef(5, "RETIRED") // RETIRED + INDETERMINATE 实例 → 育龄窗入
	v6 := mkDef(6, "RETIRED") // RETIRED + CONFIRMED（终态）实例 → 掉出
	mkInst(v4, 4, "ACTIVE", 41)
	mkInst(v5, 5, "INDETERMINATE", 51)
	mkInst(v6, 6, "CONFIRMED", 61)

	flows, err := NewStrongFlowStore(pool).ListPublishableStrongFlows(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	got := map[int]string{}
	for _, f := range flows {
		if f.ApplicationID != appID {
			continue
		}
		got[f.Version] = f.Status
		if len(f.Steps) != 1 || f.Steps[0].StepKey != "s1" {
			t.Fatalf("步骤透传: %+v", f.Steps)
		}
	}
	want := map[int]string{1: "ACTIVE", 4: "RETIRED", 5: "RETIRED"}
	if len(got) != len(want) {
		t.Fatalf("发布面集合: got=%v want=%v", got, want)
	}
	for v, s := range want {
		if got[v] != s {
			t.Fatalf("v%d status=%q want %q（发布面=%v）", v, got[v], s, got)
		}
	}
	// 育龄窗自然关闭：v4 实例走完后 v4 掉出
	if _, err := pool.Exec(ctx, `UPDATE api_strong_flow_instances SET status='CONFIRMED' WHERE definition_id=$1`, v4); err != nil {
		t.Fatal(err)
	}
	flows2, err := NewStrongFlowStore(pool).ListPublishableStrongFlows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range flows2 {
		if f.ApplicationID == appID && f.Version == 4 {
			t.Fatal("非终态实例消失后 RETIRED v4 应自然掉出发布面")
		}
	}
}
