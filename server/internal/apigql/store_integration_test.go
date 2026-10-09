// store_integration_test.go GraphQL 策略存储真实 PG 集成测试（迁移 000171 契约）。
// 依赖一次性 PostgreSQL：APIGQL_TEST_PG_DSN 未设置时 t.Skip（环境不可用如实跳过）。
// 覆盖：默认视图/upsert 版本递增/ListForGuard 只带 enabled 行/删除归位/FK 不存在应用。
package apigql

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/gateway/dynamic_security/gqlast"
	"github.com/jiuzhang-waf/server/internal/database"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func openGQLPostgres(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("APIGQL_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("APIGQL_TEST_PG_DSN not set, skipping apigql PG integration test")
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
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	var applied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version = 171`).Scan(&applied); err != nil {
		t.Fatalf("check migration record: %v", err)
	}
	if applied != 1 {
		t.Fatalf("migration 171 records=%d, want 1", applied)
	}
	return pool, ctx
}

// createTestApp 建一行测试应用（外键前提；字段取 applications 表 NOT NULL 最小集）。
func createTestApp(t *testing.T, ctx context.Context, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var appID uuid.UUID
	err := pool.QueryRow(ctx, `
INSERT INTO applications (code, name, status, protection_mode)
VALUES ($1, 'gql-it-app', 'ACTIVE', 'OFF')
RETURNING id`, "gqlit"+uuid.NewString()[:8]).Scan(&appID)
	if err != nil {
		t.Fatalf("create test application: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM applications WHERE id = $1`, appID)
	})
	return appID
}

func TestGQLPolicyStorePostgres(t *testing.T) {
	pool, ctx := openGQLPostgres(t)
	s := NewStore(pool)
	appID := createTestApp(t, ctx, pool)

	// 默认视图（无行 enabled=false version=0）
	view, err := s.GetPolicy(ctx, appID)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if view.Enabled || view.Version != 0 {
		t.Fatalf("默认视图不符: %+v", view)
	}

	// upsert 两次：version 1 → 2；config 回读完整
	p := Policy{
		Enabled:           true,
		Limits:            gatewayconfig.GuardGraphQLLimits{MaxDocBytes: 131072, MaxDepth: 8},
		Weights:           gqlast.WeightsConfig{DefaultFieldWeight: 2, Fields: map[string]gqlast.FieldWeight{"Query.users": {Weight: 5, ListBound: 50}}},
		Budget:            gqlast.BudgetConfig{PerRequest: 100, WindowSeconds: 60, WindowBudget: 1000, AnonymousBudget: 200},
		TrustedDocDigests: []string{"0123456789abcdef0123456789abcdef"},
	}
	view, err = s.UpsertPolicy(ctx, appID, p, uuid.New())
	if err != nil {
		t.Fatalf("UpsertPolicy: %v", err)
	}
	if !view.Enabled || view.Version != 1 {
		t.Fatalf("首次 upsert: %+v", view)
	}
	view, err = s.UpsertPolicy(ctx, appID, p, uuid.New())
	if err != nil {
		t.Fatalf("UpsertPolicy 2: %v", err)
	}
	if view.Version != 2 {
		t.Fatalf("version 应递增: %+v", view)
	}
	view, err = s.GetPolicy(ctx, appID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Limits.MaxDocBytes != 131072 || view.Weights.Fields["Query.users"].ListBound != 50 ||
		view.Budget.AnonymousBudget != 200 || len(view.TrustedDocDigests) != 1 {
		t.Fatalf("config 回读不符: %+v", view.Policy)
	}

	// ListForGuard 只带 enabled 行
	guard, err := s.ListForGuard(ctx)
	if err != nil {
		t.Fatalf("ListForGuard: %v", err)
	}
	gp := guard[appID.String()]
	if gp == nil || !gp.Enabled || gp.Budget.PerRequest != 100 || gp.TrustedDocDigests[0] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("ListForGuard 不符: %+v", gp)
	}

	// 禁用后不下发
	p.Enabled = false
	if _, err := s.UpsertPolicy(ctx, appID, p, uuid.New()); err != nil {
		t.Fatal(err)
	}
	guard, err = s.ListForGuard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := guard[appID.String()]; ok {
		t.Fatal("enabled=false 不得下发")
	}

	// 删除归位
	if err := s.DeletePolicy(ctx, appID, uuid.New()); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	view, _ = s.GetPolicy(ctx, appID)
	if view.Enabled || view.Version != 0 {
		t.Fatalf("删除后应默认视图: %+v", view)
	}

	// 不存在应用 upsert → ErrAppNotFound
	if _, err := s.UpsertPolicy(ctx, uuid.New(), p, uuid.New()); err == nil {
		t.Fatal("不存在应用应 ErrAppNotFound")
	}
}

// updated_at 单调（审计/对账口径）。
func TestGQLPolicyStoreUpdatedAt(t *testing.T) {
	pool, ctx := openGQLPostgres(t)
	s := NewStore(pool)
	appID := createTestApp(t, ctx, pool)
	p := Policy{Enabled: true}
	v1, err := s.UpsertPolicy(ctx, appID, p, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	v2, err := s.UpsertPolicy(ctx, appID, p, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if v1.UpdatedAt == "" || v2.UpdatedAt == "" || v2.UpdatedAt <= v1.UpdatedAt {
		t.Fatalf("updated_at 应推进: %q → %q", v1.UpdatedAt, v2.UpdatedAt)
	}
}
