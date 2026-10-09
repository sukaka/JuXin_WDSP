// store_heartbeat_integration_test.go RecordHeartbeat 两表事务 upsert 真实 PG 集成测试
// （NG-AZ-02 D6；迁移 000173 契约由并行实现方落地，本测试内自建同形两表）。
// 依赖一次性 PostgreSQL：APINODES_TEST_PG_DSN 未设置时 t.Skip（环境不可用如实跳过）。
// 覆盖：v1 心跳零变化（不写 ACK 表）→ v2 心跳两表各一行（skew/水位/租约落列）→
// 重放幂等 → 合并不回退（last_seen_at 取最大、ACK 覆盖为新拍）→ v1 拍不清 ACK 行 →
// 事务原子性（ACK 写失败整拍回滚，节点行不产生）。
package apinodes

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

func apinodesTestDSN() string { return os.Getenv("APINODES_TEST_PG_DSN") }

// openHeartbeatPostgres 建池并自建两表（api_gateway_nodes 取 000069 同形、
// api_node_authz_acks 取 000173 冻结列形——与并行实现方迁移契约一致）。
func openHeartbeatPostgres(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := apinodesTestDSN()
	if dsn == "" {
		t.Skip("APINODES_TEST_PG_DSN not set, skipping apinodes heartbeat PG integration test")
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
	}
	for _, q := range stmts {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("create test table: %v", err)
		}
	}
	return pool, ctx
}

func uniqNode(prefix string) string { return prefix + "-" + uuid.NewString()[:8] }

func countAckRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, node string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM api_node_authz_acks WHERE node_name=$1`, node).Scan(&n); err != nil {
		t.Fatalf("count ack rows: %v", err)
	}
	return n
}

// v1 心跳（无授权 ACK 字段）：节点表照常 upsert（零变化），ACK 表零行——
// 纯 v1 节点在 ACK 视图如实 NEVER_ACKED，不伪造零值 ACK 行。
func TestRecordHeartbeatV1SkipsAckTable(t *testing.T) {
	pool, ctx := openHeartbeatPostgres(t)
	store := NewStore(pool)
	node := uniqNode("hb-v1")
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_gateway_nodes WHERE node_name=$1`, node)
	})

	occurred := time.Now().UTC()
	if err := store.RecordHeartbeat(ctx, apiruntime.Heartbeat{
		RequestID: "r1", NodeName: node, OccurredAt: occurred, PolicyVersion: "v1.0",
	}); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}
	var status, pv string
	var lastSeen time.Time
	if err := pool.QueryRow(ctx,
		`SELECT status, last_policy_version, last_seen_at FROM api_gateway_nodes WHERE node_name=$1`, node).
		Scan(&status, &pv, &lastSeen); err != nil {
		t.Fatalf("read node row: %v", err)
	}
	if status != StatusActive || pv != "v1.0" || !lastSeen.Equal(occurred) {
		t.Fatalf("node row = (%s,%s,%v)", status, pv, lastSeen)
	}
	if n := countAckRows(t, ctx, pool, node); n != 0 {
		t.Fatalf("v1 heartbeat must not write ack table, got %d rows", n)
	}
}

// v2 心跳：同事务两表各一行；clock_skew_seconds = 收拍时刻 − 心跳时刻（含负漂移臂）；
// 水位 jsonb 原样落列；重放幂等；last_seen_at 合并不回退；ACK 覆盖为新拍；
// 后续 v1 拍不清除 ACK 行（保留最近一次已知 ACK 事实）。
func TestRecordHeartbeatAuthzAckTwoTables(t *testing.T) {
	pool, ctx := openHeartbeatPostgres(t)
	store := NewStore(pool)
	node := uniqNode("hb-v2")
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_gateway_nodes WHERE node_name=$1`, node)
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_node_authz_acks WHERE node_name=$1`, node)
	})

	applied := time.Now().UTC().Add(-45 * time.Second)
	expires := time.Now().UTC().Add(24 * time.Hour)
	lease := 60
	wm := &apiruntime.VectorWatermark{ManualSeq: 41, Sources: map[string]int64{"src-a": 17, "src-b": 9}}
	occurred := time.Now().UTC().Add(-3 * time.Second) // 节点时钟落后 3s → skew ≈ +3
	hb := apiruntime.Heartbeat{
		RequestID: "r1", NodeName: node, OccurredAt: occurred, PolicyVersion: "v2.0",
		AuthzPolicyVersion: "az-v42", AuthzWatermark: wm,
		AuthzSnapshotExpiresAt: &expires, AuthzLeaseSeconds: &lease, AuthzAppliedAt: &applied,
	}
	before := time.Now().UTC()
	if err := store.RecordHeartbeat(ctx, hb); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}
	after := time.Now().UTC()

	var ackPV string
	var ackWatermark []byte
	var ackApplied, ackExpires, lastAckAt time.Time
	var ackLease *int32
	var skew int64
	if err := pool.QueryRow(ctx, `
SELECT authz_policy_version, authz_watermark, authz_applied_at, authz_snapshot_expires_at,
       authz_lease_seconds, clock_skew_seconds, last_ack_at
FROM api_node_authz_acks WHERE node_name=$1`, node).
		Scan(&ackPV, &ackWatermark, &ackApplied, &ackExpires, &ackLease, &skew, &lastAckAt); err != nil {
		t.Fatalf("read ack row: %v", err)
	}
	if ackPV != "az-v42" {
		t.Fatalf("ack policy version = %q", ackPV)
	}
	var gotWM apiruntime.VectorWatermark
	if err := json.Unmarshal(ackWatermark, &gotWM); err != nil {
		t.Fatalf("decode watermark jsonb: %v", err)
	}
	if gotWM.ManualSeq != 41 || gotWM.Sources["src-a"] != 17 || gotWM.Sources["src-b"] != 9 {
		t.Fatalf("watermark round-trip = %+v", gotWM)
	}
	if ackLease == nil || *ackLease != 60 {
		t.Fatalf("ack lease = %+v", ackLease)
	}
	if !ackApplied.Equal(applied) || !ackExpires.Equal(expires) {
		t.Fatalf("ack times = (%v,%v)", ackApplied, ackExpires)
	}
	// last_ack_at 取管理面收拍时刻（非节点自报时间）
	if lastAckAt.Before(before) || lastAckAt.After(after) {
		t.Fatalf("last_ack_at = %v, want within [%v,%v]", lastAckAt, before, after)
	}
	// skew ≈ +3s（允许执行耗时窗口）
	if skew < 0 || skew > 15 {
		t.Fatalf("clock_skew_seconds = %d, want ~3 (0..15)", skew)
	}

	// 重放幂等：同拍重复上报仅刷新相同值，行数不变
	if err := store.RecordHeartbeat(ctx, hb); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if n := countAckRows(t, ctx, pool, node); n != 1 {
		t.Fatalf("replay produced %d ack rows, want 1", n)
	}

	// 负漂移臂：节点时钟超前 120s → skew ≈ −120；旧 occurred_at 不回退 last_seen_at
	future := time.Now().UTC().Add(120 * time.Second)
	if err := store.RecordHeartbeat(ctx, apiruntime.Heartbeat{
		RequestID: "r2", NodeName: node, OccurredAt: future, PolicyVersion: "v2.1",
		AuthzPolicyVersion: "az-v43", AuthzWatermark: wm,
		AuthzLeaseSeconds: &lease, AuthzAppliedAt: &applied,
	}); err != nil {
		t.Fatalf("second heartbeat: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT clock_skew_seconds, authz_policy_version FROM api_node_authz_acks WHERE node_name=$1`, node).
		Scan(&skew, &ackPV); err != nil {
		t.Fatalf("read ack row 2: %v", err)
	}
	if skew > -105 || skew < -135 {
		t.Fatalf("negative clock_skew_seconds = %d, want ~-120", skew)
	}
	if ackPV != "az-v43" {
		t.Fatalf("ack overwrite = %q, want az-v43", ackPV)
	}
	// 更早的心跳 occurred_at：节点活性取最大不回退（合并不回退口径）
	old := time.Now().UTC().Add(-time.Hour)
	if err := store.RecordHeartbeat(ctx, apiruntime.Heartbeat{
		RequestID: "r3", NodeName: node, OccurredAt: old, PolicyVersion: "",
	}); err != nil {
		t.Fatalf("older heartbeat: %v", err)
	}
	var lastSeen time.Time
	var pv string
	if err := pool.QueryRow(ctx,
		`SELECT last_seen_at, last_policy_version FROM api_gateway_nodes WHERE node_name=$1`, node).
		Scan(&lastSeen, &pv); err != nil {
		t.Fatalf("read node row 2: %v", err)
	}
	if !lastSeen.Equal(future) {
		t.Fatalf("last_seen_at regressed: %v, want %v", lastSeen, future)
	}
	if pv != "v2.1" {
		t.Fatalf("empty policy version must not overwrite: %q", pv)
	}
	// v1 拍（无授权字段）不清除 ACK 行——保留最近一次已知 ACK 事实
	if n := countAckRows(t, ctx, pool, node); n != 1 {
		t.Fatalf("v1 beat must not delete ack row, got %d", n)
	}
}

// 事务原子性：ACK 写失败（租约超 int4 范围）整拍回滚——节点行不产生，
// 不留下「活性已推进但 ACK 丢失」的半拍。
func TestRecordHeartbeatAtomicRollback(t *testing.T) {
	pool, ctx := openHeartbeatPostgres(t)
	store := NewStore(pool)
	node := uniqNode("hb-tx")
	badLease := math.MaxInt32 + 1
	err := store.RecordHeartbeat(ctx, apiruntime.Heartbeat{
		RequestID: "r1", NodeName: node, OccurredAt: time.Now().UTC(), PolicyVersion: "v2.0",
		AuthzPolicyVersion: "az-v42", AuthzLeaseSeconds: &badLease,
	})
	if err == nil {
		t.Fatal("out-of-range lease must fail the whole heartbeat")
	}
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM api_gateway_nodes WHERE node_name=$1`, node).Scan(&count); err != nil {
		t.Fatalf("count node rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("node row must roll back with ack failure, got %d", count)
	}
	if n := countAckRows(t, ctx, pool, node); n != 0 {
		t.Fatalf("ack row must not exist after rollback, got %d", n)
	}
}

// 空节点名仍拒绝（既有校验在事务外，行为不变）。
func TestRecordHeartbeatEmptyNodeName(t *testing.T) {
	pool, ctx := openHeartbeatPostgres(t)
	if err := NewStore(pool).RecordHeartbeat(ctx, apiruntime.Heartbeat{RequestID: "r1"}); err == nil {
		t.Fatal("empty node name must be rejected")
	}
}
