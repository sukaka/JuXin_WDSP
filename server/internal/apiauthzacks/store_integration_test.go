// store_integration_test.go 节点授权 ACK 视图仓储真实 PG 集成测试（NG-AZ-02 D6；
// 迁移 000173 由并行实现方落地，本测试内自建同形四表）。
// 依赖一次性 PostgreSQL：AUTHZACKS_TEST_PG_DSN 未设置时 t.Skip（环境不可用如实跳过）。
// 覆盖：ListNodeAcks 联查（有/无 ACK 行两臂、水位 jsonb 解码、租约 int4→int64、
// node_name 升序）与 ManagementWatermark（manual_seq 单行 + 逐来源合并、
// 空表零水位、sources 非 nil）。
package apiauthzacks

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func acksTestDSN() string { return os.Getenv("AUTHZACKS_TEST_PG_DSN") }

// openAcksPostgres 建池并自建四表（api_gateway_nodes 取 000069 同形；
// api_node_authz_acks / api_authz_manual_revocation_seq 取 000173 冻结列形；
// api_authority_watermarks 取 000172 列形（测试库不建 sources 表，省略外键））。
func openAcksPostgres(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := acksTestDSN()
	if dsn == "" {
		t.Skip("AUTHZACKS_TEST_PG_DSN not set, skipping apiauthzacks PG integration test")
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
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS api_gateway_nodes (
		    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    node_name           VARCHAR(128) NOT NULL UNIQUE,
		    first_seen_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
		    last_seen_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
		    last_policy_version TEXT         NOT NULL DEFAULT '',
		    last_model_version  TEXT         NOT NULL DEFAULT '',
		    event_count         BIGINT       NOT NULL DEFAULT 0,
		    status              VARCHAR(16)  NOT NULL DEFAULT 'SILENT',
		    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
		    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS api_node_authz_acks (
		    node_name                  TEXT PRIMARY KEY,
		    last_ack_at                TIMESTAMPTZ NOT NULL,
		    authz_policy_version       TEXT NOT NULL DEFAULT '',
		    authz_watermark            JSONB,
		    authz_snapshot_expires_at  TIMESTAMPTZ,
		    authz_applied_at           TIMESTAMPTZ,
		    authz_lease_seconds        INTEGER,
		    clock_skew_seconds         BIGINT,
		    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS api_authz_manual_revocation_seq (
		    id  SMALLINT PRIMARY KEY CHECK (id = 1),
		    seq BIGINT NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS api_authority_watermarks (
		    source_id            UUID PRIMARY KEY,
		    last_sequence        BIGINT NOT NULL DEFAULT 0,
		    last_event_id        VARCHAR(128) NOT NULL DEFAULT '',
		    revocation_watermark BIGINT NOT NULL DEFAULT 0,
		    gap_from             BIGINT,
		    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
	}
	for _, q := range stmts {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("create test table: %v", err)
		}
	}
	// 测试间隔离：本套件独占清空（一次性测试库，节点名/来源 ID 另加唯一后缀双保险）
	for _, q := range []string{
		`DELETE FROM api_node_authz_acks`, `DELETE FROM api_gateway_nodes`,
		`DELETE FROM api_authz_manual_revocation_seq`, `DELETE FROM api_authority_watermarks`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("clean test tables: %v", err)
		}
	}
	return pool, ctx
}

// 管理面向量水位：空表 → 零水位（sources 空 map 非 nil）；单行 manual_seq +
// 两来源 revocation_watermark → §1.1 形状合并（键为来源 UUID 字符串）。
func TestManagementWatermarkIntegration(t *testing.T) {
	pool, ctx := openAcksPostgres(t)
	store := NewStore(pool)

	zero, err := store.ManagementWatermark(ctx)
	if err != nil {
		t.Fatalf("empty ManagementWatermark: %v", err)
	}
	if zero.ManualSeq != 0 || zero.Sources == nil || len(zero.Sources) != 0 {
		t.Fatalf("empty watermark = %+v, want zero with non-nil empty sources", zero)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO api_authz_manual_revocation_seq (id, seq) VALUES (1, 41)`); err != nil {
		t.Fatalf("insert manual seq: %v", err)
	}
	src1, src2 := uuid.New(), uuid.New()
	for _, s := range []struct {
		id uuid.UUID
		wm int64
	}{{src1, 17}, {src2, 9}} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO api_authority_watermarks (source_id, last_sequence, revocation_watermark) VALUES ($1, $2, $3)`,
			s.id, s.wm, s.wm); err != nil {
			t.Fatalf("insert watermark: %v", err)
		}
	}

	mgmt, err := store.ManagementWatermark(ctx)
	if err != nil {
		t.Fatalf("ManagementWatermark: %v", err)
	}
	if mgmt.ManualSeq != 41 || mgmt.Sources[src1.String()] != 17 || mgmt.Sources[src2.String()] != 9 ||
		len(mgmt.Sources) != 2 {
		t.Fatalf("merged watermark = %+v", mgmt)
	}
}

// 节点联查：有 ACK 行节点（水位 jsonb 解码、租约 int4→int64、漂移/时间列带出）+
// 无 ACK 行节点（HasAck=false、ACK 列全空）+ node_name 升序。
func TestListNodeAcksIntegration(t *testing.T) {
	pool, ctx := openAcksPostgres(t)
	store := NewStore(pool)
	suffix := uuid.NewString()[:8]
	nodeA, nodeB := "it-a-"+suffix, "it-b-"+suffix // 字母序 a < b
	now := time.Now().UTC().Truncate(time.Microsecond)
	applied := now.Add(-90 * time.Second)
	lastAck := now.Add(-3 * time.Second)

	for _, n := range []string{nodeB, nodeA} { // 逆序插入，断言读出升序
		if _, err := pool.Exec(ctx,
			`INSERT INTO api_gateway_nodes (node_name, status) VALUES ($1, 'ACTIVE')`, n); err != nil {
			t.Fatalf("insert node: %v", err)
		}
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO api_node_authz_acks
(node_name, last_ack_at, authz_policy_version, authz_watermark, authz_applied_at,
 authz_lease_seconds, clock_skew_seconds)
VALUES ($1,$2,'az-v42','{"manual_seq":41,"sources":{"src-a":17}}',$3,$4,$5)`,
		nodeA, lastAck, applied, 60, int64(-120)); err != nil {
		t.Fatalf("insert ack row: %v", err)
	}

	rows, err := store.ListNodeAcks(ctx)
	if err != nil {
		t.Fatalf("ListNodeAcks: %v", err)
	}
	if len(rows) != 2 || rows[0].NodeName != nodeA || rows[1].NodeName != nodeB {
		t.Fatalf("rows order/content = %+v", rows)
	}
	a := rows[0]
	if !a.HasAck || a.AuthzPolicyVersion != "az-v42" || a.Status != "ACTIVE" {
		t.Fatalf("acked row = %+v", a)
	}
	if a.AuthzWatermark == nil || a.AuthzWatermark.ManualSeq != 41 ||
		a.AuthzWatermark.Sources["src-a"] != 17 {
		t.Fatalf("decoded watermark = %+v", a.AuthzWatermark)
	}
	if a.AuthzLeaseSeconds == nil || *a.AuthzLeaseSeconds != 60 {
		t.Fatalf("lease = %+v", a.AuthzLeaseSeconds)
	}
	if a.ClockSkewSeconds == nil || *a.ClockSkewSeconds != -120 {
		t.Fatalf("skew = %+v", a.ClockSkewSeconds)
	}
	if a.LastAckAt == nil || !a.LastAckAt.Equal(lastAck) ||
		a.AuthzAppliedAt == nil || !a.AuthzAppliedAt.Equal(applied) {
		t.Fatalf("times = (%v,%v)", a.LastAckAt, a.AuthzAppliedAt)
	}
	b := rows[1]
	if b.HasAck || b.AuthzWatermark != nil || b.AuthzLeaseSeconds != nil ||
		b.ClockSkewSeconds != nil || b.LastAckAt != nil || b.AuthzAppliedAt != nil ||
		b.AuthzPolicyVersion != "" {
		t.Fatalf("never-acked row must carry empty ack fields: %+v", b)
	}
}
