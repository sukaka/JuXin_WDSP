// collector_batchtx_test.go W22 采集器事务批量化（每个 flush 批次一个 DB 事务）的单元测试。
// 覆盖：逐 flush 提交、记录级 SAVEPOINT 纪律、SavePrimary 失败回滚且断点不前移、
// Commit 失败回滚且重放幂等、副作用失败不阻断批次、心跳不开事务、begin 失败、
// recorder 引用恢复。PG 语句级语义（真实回滚/重放去重）见集成测试
// （collector_batchtx_integration_test.go，一次性 PG 容器驱动）。
package apiruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"os"
)

// fakeBatchTx 最小 pgx.Tx 假实现：记录操作流（SAVEPOINT/RELEASE/COMMIT/ROLLBACK），
// 可编程 Commit 失败点。采集器在批次窗口内只对 tx 做 Exec(SAVEPOINT/RELEASE)+
// Commit/Rollback；其余 pgx.Tx 方法（嵌入 nil 接口）不应被调用，调用即 panic 暴露。
type fakeBatchTx struct {
	pgx.Tx
	ops       []string
	commitErr error
	committed bool
	rolled    bool
}

func (t *fakeBatchTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	t.ops = append(t.ops, "exec:"+strings.SplitN(strings.TrimSpace(sql), " ", 2)[0])
	return pgconn.CommandTag{}, nil
}

func (t *fakeBatchTx) Commit(context.Context) error {
	t.ops = append(t.ops, "commit")
	if t.commitErr != nil {
		return t.commitErr
	}
	t.committed = true
	return nil
}

func (t *fakeBatchTx) Rollback(context.Context) error {
	t.ops = append(t.ops, "rollback")
	t.rolled = true
	return nil
}

func (t *fakeBatchTx) countOp(op string) int {
	n := 0
	for _, o := range t.ops {
		if o == op {
			n++
		}
	}
	return n
}

// fakeTxFactory 按批次顺序产出 fakeBatchTx；failFirstCommit 时首个事务 Commit 失败
// （模拟入库故障/连接中断），err 非空时 Begin 直接失败。
type fakeTxFactory struct {
	txs             []*fakeBatchTx
	err             error
	failFirstCommit bool
}

func (f *fakeTxFactory) begin(context.Context) (pgx.Tx, error) {
	if f.err != nil {
		return nil, f.err
	}
	t := &fakeBatchTx{}
	if f.failFirstCommit && len(f.txs) == 0 {
		t.commitErr = errors.New("injected commit failure")
	}
	f.txs = append(f.txs, t)
	return t, nil
}

// dedupSaver 按 request_id 幂等的内存主事件库（镜像 SavePrimary WHERE NOT EXISTS 语义），
// dupes 记录被重放拦下的重复保存次数（真实库中的去重由集成测试断言）。
type dedupSaver struct {
	seen  map[string]bool
	saved []*PrimaryEvent
	dupes int
}

func newDedupSaver() *dedupSaver { return &dedupSaver{seen: map[string]bool{}} }

func (s *dedupSaver) SavePrimary(_ context.Context, ev *PrimaryEvent) error {
	if ev.RequestID != "" && s.seen[ev.RequestID] {
		s.dupes++
		return nil
	}
	s.seen[ev.RequestID] = true
	cp := *ev
	s.saved = append(s.saved, &cp)
	return nil
}

// errDiscovery 第 failOn 次 UpsertDiscovery 失败（模拟副作用入库故障）。
type errDiscovery struct {
	calls  int
	failOn int
}

func (d *errDiscovery) UpsertDiscovery(_ context.Context, in apiassets.DiscoveryInput) (*apiassets.Endpoint, error) {
	d.calls++
	if d.failOn > 0 && d.calls == d.failOn {
		return nil, errors.New("injected discovery failure")
	}
	return &apiassets.Endpoint{}, nil
}

// 批次事务路径：每个 flush 批次开启一个事务，副作用逐记录 SAVEPOINT/RELEASE，
// flush 整体 COMMIT 后断点前移；收集器复用后 recorder 引用恢复原装配实例。
func TestCollectOnce_BatchTx_CommitsPerFlush(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/api-runtime-events.log"
	cpPath := dir + "/checkpoint"

	lines := []string{
		notableLine(t, "bt-1"), notableLine(t, "bt-2"), notableLine(t, "bt-3"),
		notableLine(t, "bt-4"), notableLine(t, "bt-5"),
	}
	writeLines(t, logPath, lines)

	saver := &fakeSaver{}
	disc := &fakeDiscovery{}
	factory := &fakeTxFactory{}
	c := NewCollector(saver, "test-batchtx", logPath, cpPath, "node-1")
	c.SetDiscoveryUpserter(disc)
	c.SetBatchTxFactory(factory.begin)
	c.SetFlushPolicy(2, time.Hour) // 仅批量触发：2+2+1 三个批次

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 5 {
		t.Fatalf("want 5 processed, got %d", n)
	}
	if len(saver.saved) != 5 || len(disc.calls) != 5 {
		t.Fatalf("want 5 saved + 5 discovery, got %d/%d", len(saver.saved), len(disc.calls))
	}
	// 三个批次事务（2/2/1），全部提交、无回滚；逐记录 SAVEPOINT 与 RELEASE 成对
	if len(factory.txs) != 3 {
		t.Fatalf("want 3 batch txs, got %d", len(factory.txs))
	}
	wantRecs := []int{2, 2, 1}
	for i, tx := range factory.txs {
		if !tx.committed || tx.rolled {
			t.Fatalf("tx[%d] committed=%v rolled=%v, want committed only", i, tx.committed, tx.rolled)
		}
		if got := tx.countOp("exec:SAVEPOINT"); got != wantRecs[i] {
			t.Fatalf("tx[%d] savepoints = %d, want %d（逐记录子事务）", i, got, wantRecs[i])
		}
		if got := tx.countOp("exec:RELEASE"); got != wantRecs[i] {
			t.Fatalf("tx[%d] releases = %d, want %d", i, got, wantRecs[i])
		}
		if tx.ops[len(tx.ops)-1] != "commit" {
			t.Fatalf("tx[%d] last op = %s, want commit", i, tx.ops[len(tx.ops)-1])
		}
	}
	// 末次 EOF flush 后断点推进到文件尾；savedCount 按提交批次计入
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if cp := readCheckpoint(t, cpPath); cp.Offset != info.Size() {
		t.Fatalf("final checkpoint offset = %d, want file size %d", cp.Offset, info.Size())
	}
	if c.savedCount != 5 {
		t.Fatalf("savedCount = %d, want 5", c.savedCount)
	}
	// recorder 引用恢复原装配实例（浅拷贝不残留，collector 跨批次复用安全）
	if c.saver != PrimarySaver(saver) || c.discovery != DiscoveryUpserter(disc) {
		t.Fatal("recorders not restored to original instances after batch tx")
	}
}

// SavePrimary 失败：批次整体回滚、断点停在最近一次成功 flush；故障消除后新实例
// 从断点重放，全程每个事件恰好落库一次（与 autocommit 路径同一纪律，W20 用例的事务版）。
func TestCollectOnce_BatchTx_SaveFailureRollbackCheckpointHeld(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/api-runtime-events.log"
	cpPath := dir + "/checkpoint"

	lines := []string{
		notableLine(t, "bf-1"), notableLine(t, "bf-2"), notableLine(t, "bf-3"),
		notableLine(t, "bf-4"), notableLine(t, "bf-5"),
	}
	writeLines(t, logPath, lines)
	off2 := int64(len(lines[0]) + 1 + len(lines[1]) + 1)

	saver := &flakySaver{failOn: 3} // 第二个批次首条 SavePrimary 失败
	factory := &fakeTxFactory{}
	c := NewCollector(saver, "test-batchtx-fail", logPath, cpPath, "node-1")
	c.SetBatchTxFactory(factory.begin)
	c.SetFlushPolicy(2, time.Hour)

	n, err := c.CollectOnce(context.Background())
	if err == nil {
		t.Fatal("want injected save failure, got nil")
	}
	if n != 4 {
		t.Fatalf("want 4 processed before failure, got %d", n)
	}
	cp := readCheckpoint(t, cpPath)
	if cp.Offset != off2 {
		t.Fatalf("checkpoint offset = %d, want %d（断点不前移）", cp.Offset, off2)
	}
	if len(saver.saved) != 2 {
		t.Fatalf("want 2 saved before failure, got %d", len(saver.saved))
	}
	// 两个批次事务：第一个提交，第二个回滚（未提交）
	if len(factory.txs) != 2 {
		t.Fatalf("want 2 batch txs, got %d", len(factory.txs))
	}
	if !factory.txs[0].committed || factory.txs[0].rolled {
		t.Fatal("first batch tx must be committed")
	}
	if factory.txs[1].committed || !factory.txs[1].rolled {
		t.Fatal("failed batch tx must be rolled back, not committed")
	}

	// 故障消除，崩溃恢复实例从断点重放（重放上界 = 断点之后 3 行）
	saver.failOn = 0
	c2 := NewCollector(saver, "test-batchtx-fail", logPath, cpPath, "node-1")
	c2.SetBatchTxFactory(factory.begin)
	c2.SetFlushPolicy(2, time.Hour)
	n2, err := c2.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("resume CollectOnce: %v", err)
	}
	if n2 != 3 {
		t.Fatalf("want bounded rescan of 3 lines, got %d", n2)
	}
	if len(saver.saved) != 5 {
		t.Fatalf("want 5 total saved, got %d", len(saver.saved))
	}
	for i, want := range []string{"bf-1", "bf-2", "bf-3", "bf-4", "bf-5"} {
		if saver.saved[i].RequestID != want {
			t.Fatalf("saved[%d].RequestID = %s, want %s", i, saver.saved[i].RequestID, want)
		}
	}
}

// Commit 失败：整批回滚、断点文件不生成；下轮重放同一批事件，幂等库不产生重复行
// （重放呈现 = dedupSaver.dupes 计数，真实库去重由集成测试断言）。
func TestCollectOnce_BatchTx_CommitFailureReplayIdempotent(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/api-runtime-events.log"
	cpPath := dir + "/checkpoint"

	lines := []string{
		notableLine(t, "cf-1"), notableLine(t, "cf-2"), notableLine(t, "cf-3"),
	}
	writeLines(t, logPath, lines)

	saver := newDedupSaver()
	factory := &fakeTxFactory{failFirstCommit: true}
	c := NewCollector(saver, "test-batchtx-commitfail", logPath, cpPath, "node-1")
	c.SetBatchTxFactory(factory.begin)
	c.SetFlushPolicy(3, time.Hour)

	if _, err := c.CollectOnce(context.Background()); err == nil {
		t.Fatal("want injected commit failure, got nil")
	}
	if len(factory.txs) != 1 || !factory.txs[0].rolled || factory.txs[0].committed {
		t.Fatalf("first batch must be rolled back: %+v", factory.txs)
	}
	if c.savedCount != 0 {
		t.Fatalf("rolled-back batch must not count as saved, got %d", c.savedCount)
	}
	if _, err := os.Stat(cpPath); err == nil {
		t.Fatal("checkpoint must not exist after failed first batch（断点不前移）")
	}

	// 重放：同一批事件重新入库，幂等库最终恰 3 行，且重放确实发生（dupes=3）
	c2 := NewCollector(saver, "test-batchtx-commitfail", logPath, cpPath, "node-1")
	c2.SetBatchTxFactory(factory.begin)
	c2.SetFlushPolicy(3, time.Hour)
	if _, err := c2.CollectOnce(context.Background()); err != nil {
		t.Fatalf("replay CollectOnce: %v", err)
	}
	if len(saver.saved) != 3 || saver.dupes != 3 {
		t.Fatalf("want 3 unique rows + 3 deduped replays, got %d/%d", len(saver.saved), saver.dupes)
	}
	for i, want := range []string{"cf-1", "cf-2", "cf-3"} {
		if saver.saved[i].RequestID != want {
			t.Fatalf("saved[%d].RequestID = %s, want %s", i, saver.saved[i].RequestID, want)
		}
	}
	if !factory.txs[1].committed {
		t.Fatal("replay batch must be committed")
	}
}

// 副作用失败不阻断批次：发现 upsert 失败仅记日志，主事件照常同事务提交、断点前移
// （「错误仅记日志」纪律在事务模式下成立；PG 语句级回滚由集成测试覆盖）。
func TestCollectOnce_BatchTx_SideEffectFailureKeepsBatch(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/api-runtime-events.log"
	cpPath := dir + "/checkpoint"

	lines := []string{notableLine(t, "se-1"), notableLine(t, "se-2"), notableLine(t, "se-3")}
	writeLines(t, logPath, lines)

	saver := &fakeSaver{}
	disc := &errDiscovery{failOn: 2}
	factory := &fakeTxFactory{}
	c := NewCollector(saver, "test-batchtx-sideeffect", logPath, cpPath, "node-1")
	c.SetDiscoveryUpserter(disc)
	c.SetBatchTxFactory(factory.begin)
	c.SetFlushPolicy(100, time.Hour) // EOF 单次批次

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce must tolerate side-effect failure: %v", err)
	}
	if n != 3 || len(saver.saved) != 3 {
		t.Fatalf("want 3 processed + 3 saved, got %d/%d", n, len(saver.saved))
	}
	if len(factory.txs) != 1 || !factory.txs[0].committed {
		t.Fatal("batch must commit despite side-effect failure")
	}
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if cp := readCheckpoint(t, cpPath); cp.Offset != info.Size() {
		t.Fatalf("checkpoint must advance to file size %d, got %d", info.Size(), cp.Offset)
	}
}

// 心跳记录不开启批次事务（心跳不落业务数据，仅透传节点活性聚合）。
func TestCollectOnce_BatchTx_HeartbeatOpensNoTx(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/api-runtime-events.log"
	cpPath := dir + "/checkpoint"

	hb := Record{RequestID: "hb-1", GatewayNode: "node-1", Heartbeat: true,
		OccurredAt: time.Now().UTC(), PolicyVersion: "p1"}
	writeLines(t, logPath, []string{mustJSON(t, hb)})

	factory := &fakeTxFactory{}
	c := NewCollector(&fakeSaver{}, "test-batchtx-hb", logPath, cpPath, "node-1")
	c.SetBatchTxFactory(factory.begin)

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 processed, got %d", n)
	}
	if len(factory.txs) != 0 {
		t.Fatalf("heartbeat must not open batch tx, got %d", len(factory.txs))
	}
	if c.heartbeatCount != 1 {
		t.Fatalf("heartbeatCount = %d, want 1", c.heartbeatCount)
	}
}

// Begin 失败：采集报错、断点不生成、无任何保存（下轮重试）。
func TestCollectOnce_BatchTx_BeginFailure(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/api-runtime-events.log"
	cpPath := dir + "/checkpoint"

	writeLines(t, logPath, []string{notableLine(t, "bg-1")})

	saver := &fakeSaver{}
	factory := &fakeTxFactory{err: errors.New("injected begin failure")}
	c := NewCollector(saver, "test-batchtx-beginfail", logPath, cpPath, "node-1")
	c.SetBatchTxFactory(factory.begin)

	if _, err := c.CollectOnce(context.Background()); err == nil {
		t.Fatal("want injected begin failure, got nil")
	}
	if len(saver.saved) != 0 {
		t.Fatalf("nothing must be saved, got %d", len(saver.saved))
	}
	if _, err := os.Stat(cpPath); err == nil {
		t.Fatal("checkpoint must not exist after begin failure")
	}
}
