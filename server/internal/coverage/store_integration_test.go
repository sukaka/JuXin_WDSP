// store_integration_test.go 执行覆盖摄入仓储真实 PG 集成测试（迁移 000168 契约）。
// 依赖一次性 PostgreSQL：COVERAGE_TEST_PG_DSN 未设置时 t.Skip（环境不可用如实跳过，
// 不 mock 冒充）。覆盖：明细插入/幂等重放、聚合分钟桶 upsert 累加与 is_other 并集、
// 阶段计数快照、按维度键+时间窗 QueryAgg（E 口径）、采集器→真实 PG 端到端入库。
package coverage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	gwcov "github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
	"github.com/jiuzhang-waf/server/internal/database"
)

var it0 = time.Date(2026, 10, 3, 9, 15, 0, 0, time.UTC)

func openCoveragePostgres(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("COVERAGE_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("COVERAGE_TEST_PG_DSN not set, skipping coverage PG integration test")
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
	// 重跑应为空转（幂等保护）
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("rerun migrations: %v", err)
	}
	var applied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version = 168`).Scan(&applied); err != nil {
		t.Fatalf("check migration record: %v", err)
	}
	if applied != 1 {
		t.Fatalf("migration 168 records=%d, want 1", applied)
	}
	return pool, ctx
}

func truncateCoverage(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx,
		`TRUNCATE coverage_observations, coverage_minute_agg, coverage_counter_snapshots`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

func covTableCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table string) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// withTx 在事务内执行 fn 并提交；任何失败先回滚再 Fatal——保证连接归还，
// 防 t.Cleanup(pool.Close) 因泄漏的事务连接永久阻塞（puddle Close 等待连接归还）。
func withTx(t *testing.T, ctx context.Context, pool *pgxpool.Pool, fn func(tx pgx.Tx) error) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // Commit 成功后 Rollback 为 no-op
	if err := fn(tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit tx: %v", err)
	}
}

func itObs(requestID, detector string, status gwcov.Status) gwcov.Observation {
	o := gwcov.Observation{
		RequestID:     requestID,
		ApplicationID: "app-it",
		EndpointKey:   "GET /v1/it/{id}",
		Detector:      detector,
		Phase:         gwcov.PhaseRequest,
		Scope:         gwcov.ScopeDeclared{Bytes: 100, Messages: 1, Direction: "request"},
		Status:        status,
		BytesExamined: 100,
		PolicyVersion: "pol-it",
		NodeID:        "node-it",
		OccurredAt:    it0,
	}
	switch status {
	case gwcov.StatusPartial:
		o.ReasonCode = gwcov.ReasonInputTruncated
		o.Truncated = true
		o.BytesExamined = 50
	case gwcov.StatusSkipped:
		o.ReasonCode = gwcov.ReasonRuleUnselected
	case gwcov.StatusError:
		o.ReasonCode = gwcov.ReasonParseError
	case gwcov.StatusNotApplicable:
		o.ReasonCode = gwcov.ReasonNAFrozenRule
		o.NARuleID = "na-classification/graphql-subscription"
	}
	return o
}

func TestCoverageStoreObservationsIdempotent(t *testing.T) {
	pool, ctx := openCoveragePostgres(t)
	truncateCoverage(t, ctx, pool)
	s := NewStore(pool)

	batch := []gwcov.Observation{
		itObs("rid-it-1", "graphql.cost_v1", gwcov.StatusFull),
		itObs("rid-it-2", "graphql.cost_v1", gwcov.StatusPartial),
		func() gwcov.Observation { // 同 request_id+detector，phase 不同 → 新行
			o := itObs("rid-it-1", "graphql.cost_v1", gwcov.StatusFull)
			o.Phase = gwcov.PhaseResponse
			return o
		}(),
	}
	withTx(t, ctx, pool, func(tx pgx.Tx) error {
		return s.InsertObservations(ctx, tx, batch)
	})
	if got := covTableCount(t, ctx, pool, "coverage_observations"); got != 3 {
		t.Fatalf("明细行数=%d want 3", got)
	}

	// 重放同批：request_id+detector+phase 幂等，不产生重复行
	withTx(t, ctx, pool, func(tx pgx.Tx) error {
		return s.InsertObservations(ctx, tx, batch)
	})
	if got := covTableCount(t, ctx, pool, "coverage_observations"); got != 3 {
		t.Fatalf("重放后明细行数=%d want 3（幂等）", got)
	}

	// 字段回读校验（采样明细留痕内容）
	var status, reason, naRule string
	var truncated bool
	var scopeBytes, examined int64
	if err := pool.QueryRow(ctx, `
SELECT status, reason_code, na_rule_id, truncated, scope_bytes, bytes_examined
FROM coverage_observations WHERE request_id='rid-it-2'`).Scan(&status, &reason, &naRule, &truncated, &scopeBytes, &examined); err != nil {
		t.Fatal(err)
	}
	if status != "PARTIAL" || reason != "COV_INPUT_TRUNCATED" || !truncated || scopeBytes != 100 || examined != 50 {
		t.Fatalf("明细回读不符: status=%s reason=%s truncated=%v scope=%v examined=%v", status, reason, truncated, scopeBytes, examined)
	}
}

func TestCoverageStoreMinuteAggUpsertAndQuery(t *testing.T) {
	pool, ctx := openCoveragePostgres(t)
	truncateCoverage(t, ctx, pool)
	s := NewStore(pool)

	minute := it0.Truncate(time.Minute)
	key := DimKey{ApplicationID: "app-it", EndpointKey: "GET /v1/it/{id}", Detector: "graphql.cost_v1",
		Phase: "request", PolicyVersion: "pol-it", NodeID: "node-it", Minute: minute}
	other := key
	other.EndpointKey = "other"
	other.Detector = "other"

	upsert := func(rows []AggRow) {
		withTx(t, ctx, pool, func(tx pgx.Tx) error {
			return s.UpsertMinuteAgg(ctx, tx, rows)
		})
	}
	// 两次 upsert 同维度同分钟：计数累加（增量语义）
	upsert([]AggRow{{Key: key, Bucket: Bucket{Full: 3, Partial: 1}}})
	upsert([]AggRow{{Key: key, Bucket: Bucket{Full: 2, Skipped: 1}}})
	// other 归拢桶（is_other=true；再次 false 不得清标记）
	upsert([]AggRow{{Key: other, Bucket: Bucket{Error: 1}, IsOther: true}})
	upsert([]AggRow{{Key: other, Bucket: Bucket{Error: 1}, IsOther: false}})

	if got := covTableCount(t, ctx, pool, "coverage_minute_agg"); got != 2 {
		t.Fatalf("聚合行数=%d want 2", got)
	}
	var full, partial, skipped, errCount, na int64
	var isOther bool
	if err := pool.QueryRow(ctx, `
SELECT full_count, partial_count, skipped_count, error_count, na_count, is_other
FROM coverage_minute_agg WHERE detector='graphql.cost_v1'`).Scan(&full, &partial, &skipped, &errCount, &na, &isOther); err != nil {
		t.Fatal(err)
	}
	if full != 5 || partial != 1 || skipped != 1 || errCount != 0 || na != 0 || isOther {
		t.Fatalf("聚合累加不符: full=%d partial=%d skipped=%d other=%v", full, partial, skipped, isOther)
	}
	if err := pool.QueryRow(ctx, `
SELECT error_count, is_other FROM coverage_minute_agg WHERE detector='other'`).Scan(&errCount, &isOther); err != nil {
		t.Fatal(err)
	}
	if errCount != 2 || !isOther {
		t.Fatalf("other 桶: error=%d is_other=%v, want 2/true（标记取并集）", errCount, isOther)
	}

	// QueryAgg：维度键 + 时间窗；E 口径比率查询侧计算
	rows, err := s.QueryAgg(ctx, pool, AggQuery{
		ApplicationID: "app-it",
		From:          minute.Add(-time.Minute),
		To:            minute.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("QueryAgg: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("QueryAgg 行数=%d want 2", len(rows))
	}
	for _, m := range rows {
		if m.Detector == "graphql.cost_v1" {
			if m.E != 7 || m.FullRate != 5.0/7.0 || m.EffectiveRate != 6.0/7.0 || m.NoApplicableTraffic {
				t.Fatalf("E 口径不符: E=%d full_rate=%v effective=%v no_traffic=%v",
					m.E, m.FullRate, m.EffectiveRate, m.NoApplicableTraffic)
			}
		}
	}
	// 时间窗过滤：窗外为空
	rows, err = s.QueryAgg(ctx, pool, AggQuery{
		From: minute.Add(time.Hour), To: minute.Add(2 * time.Hour),
	})
	if err != nil || len(rows) != 0 {
		t.Fatalf("窗外查询应空: rows=%d err=%v", len(rows), err)
	}
}

func TestCoverageStoreCounterSnapshots(t *testing.T) {
	pool, ctx := openCoveragePostgres(t)
	truncateCoverage(t, ctx, pool)
	s := NewStore(pool)

	withTx(t, ctx, pool, func(tx pgx.Tx) error {
		return s.InsertCounterSnapshot(ctx, tx, "node-it", []StageCount{
			{Stage: stageProcessed, Count: 12},
			{Stage: stageSampleKept, Count: 4},
		}, it0)
	})
	if got := covTableCount(t, ctx, pool, "coverage_counter_snapshots"); got != 2 {
		t.Fatalf("快照行数=%d want 2", got)
	}
	var cnt int64
	if err := pool.QueryRow(ctx, `
SELECT count FROM coverage_counter_snapshots WHERE node_id='node-it' AND stage=$1`, stageProcessed).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 12 {
		t.Fatalf("stage 计数回读=%d want 12", cnt)
	}
}

// LatestStageCounts 真实 PG：guard 阶段集与 cov_ingest 集同表不同 captured_at 源，
// 须按阶段集各取「窗口内最新一份」；节点过滤与窗口过滤生效。
func TestCoverageStoreLatestStageCounts(t *testing.T) {
	pool, ctx := openCoveragePostgres(t)
	truncateCoverage(t, ctx, pool)
	s := NewStore(pool)

	t1 := it0                           // 窗口内较早一份（guard 阶段）
	t2 := it0.Add(2 * time.Minute)      // 窗口内最新一份（guard 阶段）
	tIngest := it0.Add(3 * time.Minute) // 更新的 cov_ingest 快照（不得影响 guard 集选取）
	tOld := it0.Add(-time.Hour)         // 窗口外
	guardSet := []string{"total", "rejected_cc", "reached_upstream"}

	withTx(t, ctx, pool, func(tx pgx.Tx) error {
		// node-a：guard 两份（t1/t2）+ cov_ingest 一份（tIngest 更新）+ 窗口外一份
		if err := s.InsertCounterSnapshot(ctx, tx, "node-a", []StageCount{
			{Stage: "total", Count: 10}, {Stage: "rejected_cc", Count: 1}, {Stage: "reached_upstream", Count: 9},
		}, t1); err != nil {
			return err
		}
		if err := s.InsertCounterSnapshot(ctx, tx, "node-a", []StageCount{
			{Stage: "total", Count: 20}, {Stage: "rejected_cc", Count: 2}, {Stage: "reached_upstream", Count: 18},
		}, t2); err != nil {
			return err
		}
		if err := s.InsertCounterSnapshot(ctx, tx, "node-a", []StageCount{
			{Stage: stageAggOverflow, Count: 3},
		}, tIngest); err != nil {
			return err
		}
		if err := s.InsertCounterSnapshot(ctx, tx, "node-a", []StageCount{
			{Stage: "total", Count: 999},
		}, tOld); err != nil {
			return err
		}
		// node-b：仅窗口内一份 guard
		return s.InsertCounterSnapshot(ctx, tx, "node-b", []StageCount{
			{Stage: "total", Count: 5}, {Stage: "reached_upstream", Count: 5},
		}, t1)
	})

	from := it0.Add(-time.Minute)
	to := it0.Add(10 * time.Minute)
	// guard 阶段集：node-a 取 t2 那份（更新的 cov_ingest 快照不得抢走「最新」）
	snaps, err := s.LatestStageCounts(ctx, guardSet, "", from, to)
	if err != nil {
		t.Fatalf("LatestStageCounts: %v", err)
	}
	if len(snaps) != 2 {
		t.Fatalf("节点数=%d want 2", len(snaps))
	}
	if snaps[0].NodeID != "node-a" || !snaps[0].CapturedAt.Equal(t2) {
		t.Fatalf("node-a 应取 t2 快照: %+v", snaps[0])
	}
	if snaps[0].Counts["total"] != 20 || snaps[0].Counts["rejected_cc"] != 2 || snaps[0].Counts["reached_upstream"] != 18 {
		t.Fatalf("node-a 计数不符: %+v", snaps[0].Counts)
	}
	if snaps[1].NodeID != "node-b" || snaps[1].Counts["total"] != 5 {
		t.Fatalf("node-b 不符: %+v", snaps[1])
	}
	// 节点过滤
	snaps, err = s.LatestStageCounts(ctx, guardSet, "node-b", from, to)
	if err != nil || len(snaps) != 1 || snaps[0].NodeID != "node-b" {
		t.Fatalf("node 过滤不符: %+v err=%v", snaps, err)
	}
	// cov_ingest 阶段集：node-a 取 tIngest 那份
	snaps, err = s.LatestStageCounts(ctx, []string{stageAggOverflow, stageAggInvalid}, "", from, to)
	if err != nil || len(snaps) != 1 || snaps[0].Counts[stageAggOverflow] != 3 || !snaps[0].CapturedAt.Equal(tIngest) {
		t.Fatalf("cov_ingest 集不符: %+v err=%v", snaps, err)
	}
	// 窗口外为空
	snaps, err = s.LatestStageCounts(ctx, guardSet, "", tOld.Add(-time.Hour), tOld.Add(-time.Minute))
	if err != nil || len(snaps) != 0 {
		t.Fatalf("窗外应为空: %+v err=%v", snaps, err)
	}
}

// 采集器 → 真实 PG 端到端：JSONL 摄入 → 明细 + 聚合 + 快照三表落库；断点丢失重放明细不重复。
func TestCoverageCollectorPostgresEndToEnd(t *testing.T) {
	pool, ctx := openCoveragePostgres(t)
	truncateCoverage(t, ctx, pool)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "coverage-observations.jsonl")
	cpPath := filepath.Join(dir, "checkpoint")

	var lines []string
	for i := 0; i < 10; i++ {
		lines = append(lines, covLine(t, fmt.Sprintf("rid-e2e-%d", i), "graphql.cost_v1", gwcov.StatusFull))
	}
	lines = append(lines, "{bad-json")
	writeLines(t, logPath, lines)

	s := NewStore(pool)
	// event_parse_failures 为各采集器共享表（不在本包 truncate 范围），按本采集器 ID 清理
	if _, err := pool.Exec(ctx, `DELETE FROM event_parse_failures WHERE collector_id='cov-it-01'`); err != nil {
		t.Fatal(err)
	}
	c := NewCollector(s, pool.Begin, "cov-it-01", logPath, cpPath, "node-it")
	c.SetSampleN(2) // 10 合法 → 明细 5 行
	n, err := c.CollectOnce(ctx)
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 11 {
		t.Fatalf("processed=%d want 11", n)
	}
	if got := covTableCount(t, ctx, pool, "coverage_observations"); got != 5 {
		t.Fatalf("明细行数=%d want 5（采样 N=2）", got)
	}
	if got := covTableCount(t, ctx, pool, "coverage_minute_agg"); got != 1 {
		t.Fatalf("聚合行数=%d want 1", got)
	}
	var full int64
	if err := pool.QueryRow(ctx, `SELECT full_count FROM coverage_minute_agg`).Scan(&full); err != nil {
		t.Fatal(err)
	}
	if full != 10 {
		t.Fatalf("聚合 FULL=%d want 10（采样不影响聚合）", full)
	}
	if got := covTableCount(t, ctx, pool, "coverage_counter_snapshots"); got == 0 {
		t.Fatal("flush 应落阶段计数快照")
	}
	// 坏行进通用解析失败队列
	var parseFailures int64
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM event_parse_failures WHERE collector_id='cov-it-01'`).Scan(&parseFailures); err != nil {
		t.Fatal(err)
	}
	if parseFailures != 1 {
		t.Fatalf("解析失败队列行数=%d want 1", parseFailures)
	}

	// 断点丢失 → 全量重放：明细幂等不重复（聚合累加口径见 collector.go flush 注释，此处不断言）
	if err := os.Remove(cpPath); err != nil {
		t.Fatal(err)
	}
	c2 := NewCollector(s, pool.Begin, "cov-it-01", logPath, cpPath, "node-it")
	c2.SetSampleN(2)
	if n, err := c2.CollectOnce(ctx); err != nil || n != 11 {
		t.Fatalf("重放 processed=%d err=%v, want 11", n, err)
	}
	if got := covTableCount(t, ctx, pool, "coverage_observations"); got != 5 {
		t.Fatalf("重放后明细行数=%d want 5（幂等）", got)
	}
}
