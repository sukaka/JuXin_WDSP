// collector_batchtx_test.go W22 访问日志采集器事务批量化（每个 flush 批次一个
// DB 事务，行数据 + 失败队列 + 断点原子提交）的单元测试。
// 覆盖：逐 flush 提交与断点同事务、Commit 失败回滚且重放、坏行失败队列、
// 插入失败行级子事务回滚后续航。loadCheckpoint 对查询失败容忍（视为无断点），
// 单测以空置连接池触发该路径，断点写入经 fake tx 断言；真实 PG 语义见集成测试。
package accesslogs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fakeBatchTx 最小 pgx.Tx 假实现：记录操作流，可编程 Commit 失败与按语句子串
// 匹配的一次性 Exec 失败。采集器只经 tx 做 Exec/Commit/Rollback；其余 pgx.Tx
// 方法（嵌入 nil 接口）不应被调用，调用即 panic 暴露。
type fakeBatchTx struct {
	pgx.Tx
	ops        []string
	commitErr  error
	failSubstr string // 非空时首个包含该子串的 Exec 失败（模拟行插入失败）
	failFired  bool
	committed  bool
	rolled     bool
}

func (t *fakeBatchTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	t.ops = append(t.ops, sql)
	if t.failSubstr != "" && !t.failFired && strings.Contains(sql, t.failSubstr) {
		t.failFired = true
		return pgconn.CommandTag{}, errors.New("injected exec failure")
	}
	return pgconn.CommandTag{}, nil
}

func (t *fakeBatchTx) Commit(context.Context) error {
	t.ops = append(t.ops, "__commit__")
	if t.commitErr != nil {
		return t.commitErr
	}
	t.committed = true
	return nil
}

func (t *fakeBatchTx) Rollback(context.Context) error {
	t.ops = append(t.ops, "__rollback__")
	t.rolled = true
	return nil
}

// countOps 统计包含给定子串的操作数。
func (t *fakeBatchTx) countOps(substr string) int {
	n := 0
	for _, o := range t.ops {
		if strings.Contains(o, substr) {
			n++
		}
	}
	return n
}

// countPrefix 统计以给定前缀开头的操作数（SAVEPOINT/RELEASE/ROLLBACK TO 语句
// 互含子串，必须按前缀区分）。
func (t *fakeBatchTx) countPrefix(prefix string) int {
	n := 0
	for _, o := range t.ops {
		if strings.HasPrefix(strings.TrimSpace(o), prefix) {
			n++
		}
	}
	return n
}

// indexOf 返回首个包含子串的操作下标（-1 = 不存在）。
func (t *fakeBatchTx) indexOf(substr string) int {
	for i, o := range t.ops {
		if strings.Contains(o, substr) {
			return i
		}
	}
	return -1
}

// fakeTxFactory 按批次顺序产出 fakeBatchTx；failFirstCommit 时首个事务 Commit 失败。
type fakeTxFactory struct {
	txs             []*fakeBatchTx
	failFirstCommit bool
	failInsertOnce  bool
}

func (f *fakeTxFactory) begin(context.Context) (pgx.Tx, error) {
	t := &fakeBatchTx{}
	if f.failFirstCommit && len(f.txs) == 0 {
		t.commitErr = errors.New("injected commit failure")
	}
	if f.failInsertOnce && len(f.txs) == 0 {
		t.failSubstr = "INSERT INTO access_logs"
	}
	f.txs = append(f.txs, t)
	return t, nil
}

// deadPool 返回不连通连接池（loadCheckpoint 对查询失败按「无断点」容忍，
// 断点写入在事务模式下经 fake tx 断言，不经连接池）。
func deadPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://127.0.0.1:1/unused?sslmode=disable")
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func writeLogLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func accessLine(reqID string) string {
	return fmt.Sprintf(`{"occurred_at":%q,"request_id":%q,"request_method":"GET","request_uri":"/v1/x?a=1","response_status":200}`,
		time.Now().UTC().Format(time.RFC3339Nano), reqID)
}

// 批次事务路径：每个 flush 批次一个事务，行插入逐行 SAVEPOINT/RELEASE，
// 断点与批次同事务（checkpoint upsert 在 COMMIT 之前），全部提交不回滚。
func TestCollectOnce_BatchTx_CommitsPerFlush(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access-full.log")

	lines := []string{accessLine("al-1"), accessLine("al-2"), accessLine("al-3"), accessLine("al-4"), accessLine("al-5")}
	writeLogLines(t, logPath, lines)

	factory := &fakeTxFactory{}
	c := NewCollector(deadPool(t), "test-al-batchtx", logPath)
	c.SetBatchTxFactory(factory.begin)
	c.SetFlushPolicy(2, time.Hour) // 仅批量触发：2+2+1 三个批次

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 5 || c.processedCount != 5 {
		t.Fatalf("want 5 processed, got %d/%d", n, c.processedCount)
	}
	if len(factory.txs) != 3 {
		t.Fatalf("want 3 batch txs, got %d", len(factory.txs))
	}
	wantRows := []int{2, 2, 1}
	for i, tx := range factory.txs {
		if !tx.committed || tx.rolled {
			t.Fatalf("tx[%d] committed=%v rolled=%v, want committed only", i, tx.committed, tx.rolled)
		}
		if got := tx.countPrefix("SAVEPOINT " + lineSavepoint); got != wantRows[i] {
			t.Fatalf("tx[%d] savepoints = %d, want %d（逐行子事务）", i, got, wantRows[i])
		}
		if got := tx.countPrefix("RELEASE SAVEPOINT " + lineSavepoint); got != wantRows[i] {
			t.Fatalf("tx[%d] releases = %d, want %d", i, got, wantRows[i])
		}
		if got := tx.countOps("INSERT INTO access_logs"); got != wantRows[i] {
			t.Fatalf("tx[%d] inserts = %d, want %d", i, got, wantRows[i])
		}
		// 断点同事务：checkpoint upsert 必须出现在 COMMIT 之前
		cpIdx := tx.indexOf("INSERT INTO event_collector_checkpoints")
		if cpIdx < 0 || cpIdx > tx.indexOf("__commit__") {
			t.Fatalf("tx[%d] checkpoint write must precede commit: ops=%v", i, tx.ops)
		}
	}
	// store 恢复为连接池装配实例（浅拷贝不残留）
	if c.store.db != DBTX(c.db) {
		t.Fatal("store not restored to pool-backed instance after batch tx")
	}
}

// Commit 失败：整批回滚（断点随事务不落库）；重放时同一批行重新插入并成功提交。
func TestCollectOnce_BatchTx_CommitFailureReplay(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access-full.log")

	writeLogLines(t, logPath, []string{accessLine("ac-1"), accessLine("ac-2"), accessLine("ac-3")})

	factory := &fakeTxFactory{failFirstCommit: true}
	c := NewCollector(deadPool(t), "test-al-commitfail", logPath)
	c.SetBatchTxFactory(factory.begin)
	c.SetFlushPolicy(3, time.Hour)

	if _, err := c.CollectOnce(context.Background()); err == nil {
		t.Fatal("want injected commit failure, got nil")
	}
	if len(factory.txs) != 1 || !factory.txs[0].rolled || factory.txs[0].committed {
		t.Fatalf("first batch must be rolled back: %+v", factory.txs)
	}
	// 失败批次的断点写入随事务回滚（写入确实发出过，但从未提交）
	if factory.txs[0].countOps("INSERT INTO event_collector_checkpoints") != 1 {
		t.Fatal("checkpoint write must be attempted inside failed batch tx")
	}

	// 重放：三行重新插入并成功提交（真实库中重放行由 request_id 去重——集成测试断言）。
	// flushBatch 放大到不触发中途 flush：EOF 单次批次，断点随该批次事务提交。
	c2 := NewCollector(deadPool(t), "test-al-commitfail", logPath)
	c2.SetBatchTxFactory(factory.begin)
	c2.SetFlushPolicy(100, time.Hour)
	n, err := c2.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("replay CollectOnce: %v", err)
	}
	if n != 3 {
		t.Fatalf("want 3 replayed, got %d", n)
	}
	if len(factory.txs) != 2 || !factory.txs[1].committed {
		t.Fatal("replay batch must be committed")
	}
	if factory.txs[1].countOps("INSERT INTO access_logs") != 3 {
		t.Fatalf("replay must re-insert 3 rows, ops=%v", factory.txs[1].ops)
	}
}

// 坏行：解析失败行进失败队列（同事务），批次照常提交，好行不受影响。
func TestCollectOnce_BatchTx_ParseFailureQueuedInTx(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access-full.log")

	writeLogLines(t, logPath, []string{accessLine("ap-1"), "{bad json", accessLine("ap-2")})

	factory := &fakeTxFactory{}
	c := NewCollector(deadPool(t), "test-al-parsefail", logPath)
	c.SetBatchTxFactory(factory.begin)
	c.SetFlushPolicy(100, time.Hour)

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 3 || c.processedCount != 2 || c.failedCount != 1 {
		t.Fatalf("want 3 processed/2 ok/1 failed, got %d/%d/%d", n, c.processedCount, c.failedCount)
	}
	if len(factory.txs) != 1 || !factory.txs[0].committed {
		t.Fatal("batch must commit despite parse failure")
	}
	tx := factory.txs[0]
	if tx.countOps("INSERT INTO event_parse_failures") != 1 {
		t.Fatalf("parse failure must be queued in tx, ops=%v", tx.ops)
	}
	if tx.countOps("INSERT INTO access_logs") != 2 {
		t.Fatalf("good rows must be inserted, ops=%v", tx.ops)
	}
}

// 插入失败：行级子事务回滚恢复事务，失败行补写失败队列，后续行与批次提交不受影响
// （「失败行进队列、断点照常前移」原语义在事务模式下保持）。
func TestCollectOnce_BatchTx_InsertFailureRollsBackLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access-full.log")

	writeLogLines(t, logPath, []string{accessLine("ai-1"), accessLine("ai-2"), accessLine("ai-3")})

	factory := &fakeTxFactory{failInsertOnce: true} // 首个 INSERT INTO access_logs 失败（ai-1）
	c := NewCollector(deadPool(t), "test-al-insertfail", logPath)
	c.SetBatchTxFactory(factory.begin)
	c.SetFlushPolicy(100, time.Hour)

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce must tolerate row insert failure: %v", err)
	}
	if n != 3 || c.processedCount != 2 || c.failedCount != 1 {
		t.Fatalf("want 3 processed/2 ok/1 failed, got %d/%d/%d", n, c.processedCount, c.failedCount)
	}
	if len(factory.txs) != 1 || !factory.txs[0].committed {
		t.Fatal("batch must commit despite row insert failure")
	}
	tx := factory.txs[0]
	if tx.countOps("ROLLBACK TO SAVEPOINT "+lineSavepoint) < 1 {
		t.Fatalf("failed line must roll back to line savepoint, ops=%v", tx.ops)
	}
	if tx.countOps("INSERT INTO event_parse_failures") != 1 {
		t.Fatalf("failed row must be queued after rollback, ops=%v", tx.ops)
	}
	// 失败行的 INSERT 之后仍有两条好行 INSERT（事务恢复后续航）
	if tx.countOps("INSERT INTO access_logs") != 3 {
		t.Fatalf("want 3 insert attempts (1 failed + 2 ok), ops=%v", tx.ops)
	}
}
