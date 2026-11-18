// collector_test.go 覆盖采集器单测（无真实 PG；fakeTx 捕获批次内容断言）。
// 覆盖：采样率/聚合计数/入库批构成、断点续传（追加两轮）、轮转重读、错误行隔离、
// 死事务断点不前移。真实 PG 语义（幂等/聚合 upsert/查询）见 store_integration_test.go。
package coverage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	gwcov "github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
)

var ct0 = time.Date(2026, 10, 3, 8, 30, 0, 0, time.UTC)

// covLine 构造一条合法观测 JSONL 行（同契约字段；detector/status 可变）。
func covLine(t *testing.T, requestID, detector string, status gwcov.Status) string {
	t.Helper()
	o := gwcov.Observation{
		RequestID:     requestID,
		ApplicationID: "app-1",
		EndpointKey:   "GET /v1/users/{id}",
		Detector:      detector,
		Phase:         gwcov.PhaseRequest,
		Scope:         gwcov.ScopeDeclared{Bytes: 100, Messages: 1, Direction: "request"},
		Status:        status,
		BytesExamined: 100,
		PolicyVersion: "pol-1",
		NodeID:        "node-1",
		OccurredAt:    ct0,
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
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// fakeQuerier 捕获批次 SQL 参数（Exec 调用按 store.go 参数序解析）。
type fakeQuerier struct {
	mu           sync.Mutex
	obsInserts   [][]interface{} // coverage_observations 每次 Exec 的参数
	aggUpserts   [][]interface{} // coverage_minute_agg 每次 Exec 的参数
	snapInserts  [][]interface{} // coverage_counter_snapshots 每次 Exec 的参数
	commits      int
	rollbacks    int
	failNextExec error // 注入：下一次 Exec 失败（死批次用例）
}

func (q *fakeQuerier) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.failNextExec != nil {
		err := q.failNextExec
		q.failNextExec = nil
		return pgconn.CommandTag{}, err
	}
	switch {
	case strings.Contains(sql, "coverage_observations"):
		q.obsInserts = append(q.obsInserts, args)
	case strings.Contains(sql, "coverage_minute_agg"):
		q.aggUpserts = append(q.aggUpserts, args)
	case strings.Contains(sql, "coverage_counter_snapshots"):
		q.snapInserts = append(q.snapInserts, args)
	}
	return pgconn.CommandTag{}, nil
}

func (q *fakeQuerier) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	return nil
}

func (q *fakeQuerier) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return nil, fmt.Errorf("fakeQuerier: Query not supported")
}

// fakeTx 实现 pgx.Tx 最小子集（其余方法经内嵌 nil 接口补齐，测试不触达）。
type fakeTx struct {
	pgx.Tx
	q *fakeQuerier
}

func (t *fakeTx) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	return t.q.Exec(ctx, sql, args...)
}
func (t *fakeTx) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return t.q.Query(ctx, sql, args...)
}
func (t *fakeTx) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	return t.q.QueryRow(ctx, sql, args...)
}
func (t *fakeTx) Commit(ctx context.Context) error {
	t.q.mu.Lock()
	t.q.commits++
	t.q.mu.Unlock()
	return nil
}
func (t *fakeTx) Rollback(ctx context.Context) error {
	t.q.mu.Lock()
	t.q.rollbacks++
	t.q.mu.Unlock()
	return nil
}

// newTestCollector 装配单测采集器（bad-DSN 连接池仅用于 parse-failure 通用队列
// 的 best-effort 写入——连接即失败走告警分支，不影响断言；真实队列语义见集成测试）。
func newTestCollector(t *testing.T, logPath, cpPath string, sampleN uint64) (*Collector, *fakeQuerier) {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://127.0.0.1:1/none?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	fq := &fakeQuerier{}
	beginner := func(ctx context.Context) (pgx.Tx, error) { return &fakeTx{q: fq}, nil }
	c := NewCollector(NewStore(pool), beginner, "cov-test-01", logPath, cpPath, "node-it")
	c.SetSampleN(sampleN)
	return c, fq
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatal(err)
		}
	}
}

func readCheckpoint(t *testing.T, path string) checkpoint {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	var cp checkpoint
	if err := json.Unmarshal(raw, &cp); err != nil {
		t.Fatalf("checkpoint not json: %v", err)
	}
	return cp
}

func snapshotStageSum(fq *fakeQuerier, stage string) uint64 {
	fq.mu.Lock()
	defer fq.mu.Unlock()
	var sum uint64
	for _, args := range fq.snapInserts {
		if len(args) >= 3 && args[1] == stage {
			if n, ok := args[2].(int64); ok {
				sum += uint64(n)
			}
		}
	}
	return sum
}

func TestCollectorIngestSamplingAndAgg(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "coverage-observations.jsonl")
	cpPath := filepath.Join(dir, "checkpoint")

	var lines []string
	for i := 0; i < 10; i++ { // 10 FULL（同维度）
		lines = append(lines, covLine(t, fmt.Sprintf("rid-full-%d", i), "graphql.cost_v1", gwcov.StatusFull))
	}
	lines = append(lines, covLine(t, "rid-partial", "graphql.cost_v1", gwcov.StatusPartial))
	lines = append(lines, covLine(t, "rid-na", "graphql.cost_v1", gwcov.StatusNotApplicable))
	lines = append(lines, "{not-json")                                                                                                         // 坏 JSON
	lines = append(lines, `{"request_id":"rid-bad","detector":"d","phase":"request","status":"SKIPPED","occurred_at":"2026-10-03T08:30:00Z"}`) // SKIPPED 缺 reason
	writeLines(t, logPath, lines)

	c, fq := newTestCollector(t, logPath, cpPath, 3) // N=3：12 合法 → 保留 4
	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 14 {
		t.Fatalf("processed=%d want 14", n)
	}
	// 明细采样：12 合法行 1/3 采样 → 4 行入库
	if len(fq.obsInserts) != 4 {
		t.Fatalf("明细入库 %d 行, want 4（采样 N=3）", len(fq.obsInserts))
	}
	// 聚合：同维度同分钟 1 桶，FULL=10 PARTIAL=1 NA=1（采样不影响聚合）
	if len(fq.aggUpserts) != 1 {
		t.Fatalf("聚合 upsert %d 行, want 1", len(fq.aggUpserts))
	}
	agg := fq.aggUpserts[0]
	if agg[2] != "graphql.cost_v1" || agg[7] != int64(10) || agg[8] != int64(1) || agg[11] != int64(1) {
		t.Fatalf("聚合桶参数不符: detector=%v full=%v partial=%v na=%v", agg[2], agg[7], agg[8], agg[11])
	}
	if agg[12] != false {
		t.Fatalf("is_other 应为 false: %v", agg[12])
	}
	// 阶段计数快照
	if got := snapshotStageSum(fq, stageProcessed); got != 12 {
		t.Fatalf("%s=%d want 12", stageProcessed, got)
	}
	if got := snapshotStageSum(fq, stageParseFailures); got != 2 {
		t.Fatalf("%s=%d want 2", stageParseFailures, got)
	}
	if got := snapshotStageSum(fq, stageSampleKept); got != 4 {
		t.Fatalf("%s=%d want 4", stageSampleKept, got)
	}
	if got := snapshotStageSum(fq, stageSampleDropped); got != 8 {
		t.Fatalf("%s=%d want 8", stageSampleDropped, got)
	}
	if fq.commits != 1 || fq.rollbacks != 0 {
		t.Fatalf("commits=%d rollbacks=%d, want 1/0", fq.commits, fq.rollbacks)
	}
	// 错误行隔离：错误文件 2 行，合法行照常入库
	errRaw, err := os.ReadFile(logPath + ".errors")
	if err != nil {
		t.Fatalf("错误文件应存在: %v", err)
	}
	if got := strings.Count(strings.TrimRight(string(errRaw), "\n"), "\n") + 1; got != 2 {
		t.Fatalf("错误文件 %d 行, want 2", got)
	}
	if c.failedCount != 2 || c.processedCount != 12 {
		t.Fatalf("failed=%d processed=%d, want 2/12", c.failedCount, c.processedCount)
	}
	// 断点推进到文件尾
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if cp := readCheckpoint(t, cpPath); cp.Offset != info.Size() {
		t.Fatalf("checkpoint offset=%d want %d", cp.Offset, info.Size())
	}
}

func TestCollectorCheckpointResumeTwoRounds(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "coverage-observations.jsonl")
	cpPath := filepath.Join(dir, "checkpoint")

	writeLines(t, logPath, []string{
		covLine(t, "rid-1", "d1", gwcov.StatusFull),
		covLine(t, "rid-2", "d1", gwcov.StatusFull),
	})
	c, fq := newTestCollector(t, logPath, cpPath, 1) // N=1 全保留
	ctx := context.Background()
	if n, err := c.CollectOnce(ctx); err != nil || n != 2 {
		t.Fatalf("第一轮 processed=%d err=%v, want 2", n, err)
	}
	// 无新内容：空转
	if n, err := c.CollectOnce(ctx); err != nil || n != 0 {
		t.Fatalf("空轮 processed=%d err=%v, want 0", n, err)
	}
	// 追加第二轮：只处理新增
	writeLines(t, logPath, []string{
		covLine(t, "rid-3", "d1", gwcov.StatusFull),
		covLine(t, "rid-4", "d1", gwcov.StatusFull),
		covLine(t, "rid-5", "d1", gwcov.StatusFull),
	})
	if n, err := c.CollectOnce(ctx); err != nil || n != 3 {
		t.Fatalf("第二轮 processed=%d err=%v, want 3", n, err)
	}
	if len(fq.obsInserts) != 5 {
		t.Fatalf("累计明细入库 %d 行, want 5（两轮不重复）", len(fq.obsInserts))
	}
	// 聚合累计：5 FULL 同一桶（两次 upsert 增量 2+3）
	var fullSum int64
	for _, args := range fq.aggUpserts {
		fullSum += args[7].(int64)
	}
	if fullSum != 5 {
		t.Fatalf("聚合 FULL 累计=%d want 5", fullSum)
	}
}

func TestCollectorRotationRereads(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "coverage-observations.jsonl")
	cpPath := filepath.Join(dir, "checkpoint")
	ctx := context.Background()

	writeLines(t, logPath, []string{
		covLine(t, "rid-a", "d1", gwcov.StatusFull),
		covLine(t, "rid-b", "d1", gwcov.StatusFull),
	})
	c, fq := newTestCollector(t, logPath, cpPath, 1)
	if n, err := c.CollectOnce(ctx); err != nil || n != 2 {
		t.Fatalf("首轮 processed=%d err=%v", n, err)
	}

	// 换 inode 轮转（copytruncate 等价形态：删除重建）
	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	writeLines(t, logPath, []string{covLine(t, "rid-c", "d1", gwcov.StatusFull)})
	if n, err := c.CollectOnce(ctx); err != nil || n != 1 {
		t.Fatalf("轮转后 processed=%d err=%v, want 1（从头重读新文件）", n, err)
	}

	// 同 inode 截断变小（直接覆写缩短）→ 亦判轮转身读
	if err := os.WriteFile(logPath, []byte(covLine(t, "rid-d", "d1", gwcov.StatusFull)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := c.CollectOnce(ctx); err != nil || n != 1 {
		t.Fatalf("截断后 processed=%d err=%v, want 1", n, err)
	}
	if len(fq.obsInserts) != 4 {
		t.Fatalf("累计明细入库 %d 行, want 4", len(fq.obsInserts))
	}
}

func TestCollectorDeadTxCheckpointStays(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "coverage-observations.jsonl")
	cpPath := filepath.Join(dir, "checkpoint")
	writeLines(t, logPath, []string{covLine(t, "rid-1", "d1", gwcov.StatusFull)})

	c, fq := newTestCollector(t, logPath, cpPath, 1)
	fq.failNextExec = fmt.Errorf("injected exec failure")
	if _, err := c.CollectOnce(context.Background()); err == nil {
		t.Fatal("批次失败应返回错误")
	}
	if _, err := os.Stat(cpPath); !os.IsNotExist(err) {
		t.Fatal("批次失败断点不得前移（checkpoint 不应生成）")
	}
	// 恢复后重放完整落库
	if n, err := c.CollectOnce(context.Background()); err != nil || n != 1 {
		t.Fatalf("重放 processed=%d err=%v, want 1", n, err)
	}
	if len(fq.obsInserts) != 1 {
		t.Fatalf("重放后明细入库 %d 行, want 1", len(fq.obsInserts))
	}
}

func TestCollectorMissingLogFileIdle(t *testing.T) {
	dir := t.TempDir()
	c, _ := newTestCollector(t, filepath.Join(dir, "not-exists.jsonl"), filepath.Join(dir, "checkpoint"), 1)
	n, err := c.CollectOnce(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("缺日志文件应空转不报错: n=%d err=%v", n, err)
	}
}

func TestParseObservationLineContract(t *testing.T) {
	if _, err := parseObservationLine([]byte("{bad")); err == nil {
		t.Fatal("坏 JSON 应报错")
	}
	if _, err := parseObservationLine([]byte(`{"request_id":"x","detector":"d","phase":"request","status":"FULL"}`)); err == nil {
		t.Fatal("缺 occurred_at 应报错（采集侧不补时间戳）")
	}
	line := covLine(t, "rid-ok", "d1", gwcov.StatusFull)
	o, err := parseObservationLine([]byte(line))
	if err != nil {
		t.Fatalf("合法行应解析: %v", err)
	}
	if o.RequestID != "rid-ok" || o.OccurredAt.IsZero() {
		t.Fatalf("解析内容不符: %+v", o)
	}
}

// TestCollectorCounterSnapshotRouting counter_snapshot 行应走独立入库通道：
// 不经观测校验/采样/聚合，node_id/stage/count 按行映射入库；坏行（空 node_id、
// 坏时间戳）进错误文件，且不影响同批观测行的正常入库。
func TestCollectorCounterSnapshotRouting(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "coverage-observations.jsonl")
	cpPath := filepath.Join(dir, "cp.json")
	c, fq := newTestCollector(t, logPath, cpPath, 1)
	writeLines(t, logPath, []string{
		`{"record_type":"counter_snapshot","node_id":"gw-7","captured_at":"2026-10-03T12:00:00Z","counts":[{"stage":"total","count":42},{"stage":"rejected_cc","count":3}]}`,
		`{"record_type":"counter_snapshot","node_id":"","captured_at":"2026-10-03T12:00:00Z","counts":[{"stage":"total","count":1}]}`,
		`{"record_type":"counter_snapshot","node_id":"gw-8","captured_at":"not-a-time","counts":[{"stage":"total","count":2}]}`,
		covLine(t, "rid-coexist-1", "pipeline", gwcov.StatusFull),
	})
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// gw-7 的两个阶段按行映射入库
	if got := snapshotNodeStageSum(fq, "gw-7", "total"); got != 42 {
		t.Fatalf("gw-7 total=%d want 42", got)
	}
	if got := snapshotNodeStageSum(fq, "gw-7", "rejected_cc"); got != 3 {
		t.Fatalf("gw-7 rejected_cc=%d want 3", got)
	}
	// 空 node / 坏时间戳：不入库
	if got := snapshotNodeStageSum(fq, "gw-8", "total"); got != 0 {
		t.Fatalf("坏时间戳行不应入库: got %d", got)
	}
	// 观测行照常入库（counter 行不挤占采样/明细通道）
	if len(fq.obsInserts) != 1 {
		t.Fatalf("obsInserts=%d want 1", len(fq.obsInserts))
	}
	// 错误文件含两条坏 counter 行
	errRaw, err := os.ReadFile(logPath + ".errors")
	if err != nil {
		t.Fatalf("错误文件不存在: %v", err)
	}
	if got := strings.Count(string(errRaw), "bad counter_snapshot"); got != 2 {
		t.Fatalf("错误文件 counter 行=%d want 2", got)
	}
}

// snapshotNodeStageSum 按节点+阶段汇总 fakeQuerier 捕获的计数快照入库参数。
func snapshotNodeStageSum(fq *fakeQuerier, nodeID, stage string) uint64 {
	fq.mu.Lock()
	defer fq.mu.Unlock()
	var sum uint64
	for _, args := range fq.snapInserts {
		if len(args) >= 3 && args[0] == nodeID && args[1] == stage {
			if n, ok := args[2].(int64); ok {
				sum += uint64(n)
			}
		}
	}
	return sum
}
