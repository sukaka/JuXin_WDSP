// collector_flush_test.go W20 采集器批量化修复（批量/周期 flush + 断点同节奏落盘）的单元测试。
// 覆盖：批量触发、周期触发、中途失败断点保持、崩溃（新采集器实例）有界重扫、默认参数。
// 现场与改造依据：docs/evidence/api-security-performance-baseline.md §11.8 发现 2。
package apiruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// flakySaver 第 failOn 次 SavePrimary 调用失败（模拟采集中途入库故障/进程被杀）。
type flakySaver struct {
	saved  []*PrimaryEvent
	calls  int
	failOn int
}

func (f *flakySaver) SavePrimary(_ context.Context, ev *PrimaryEvent) error {
	f.calls++
	if f.failOn > 0 && f.calls == f.failOn {
		return errors.New("injected save failure")
	}
	cp := *ev
	f.saved = append(f.saved, &cp)
	return nil
}

// cpProbeSaver 在每次 SavePrimary 时记录断点文件当前 offset（-1 = 断点不存在），
// 用于断言 flush 在扫描中途（而非仅 EOF）已落盘。
type cpProbeSaver struct {
	fakeSaver
	cpPath  string
	offsets []int64
}

func (s *cpProbeSaver) SavePrimary(ctx context.Context, ev *PrimaryEvent) error {
	off := int64(-1)
	if data, err := os.ReadFile(s.cpPath); err == nil {
		var cp checkpoint
		if json.Unmarshal(data, &cp) == nil {
			off = cp.Offset
		}
	}
	s.offsets = append(s.offsets, off)
	return s.fakeSaver.SavePrimary(ctx, ev)
}

func notableLine(t *testing.T, reqID string) string {
	t.Helper()
	return mustJSON(t, Record{
		RequestID: reqID, EndpointKey: "GET /v1/flush/{id}", Method: "GET", PathTemplate: "/v1/flush/{id}",
		IsAPI: true, FinalAction: "BLOCK", RiskLevel: "MEDIUM", RiskScore: 40,
		OccurredAt: time.Now().UTC(),
	})
}

func readCheckpoint(t *testing.T, cpPath string) checkpoint {
	t.Helper()
	data, err := os.ReadFile(cpPath)
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	var cp checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		t.Fatalf("unmarshal checkpoint: %v", err)
	}
	if !cp.valid() {
		t.Fatalf("checkpoint invalid: %+v", cp)
	}
	return cp
}

// 批量触发：每 flushBatch 行落一次批次+断点；中途入库失败时断点停在最近一次成功 flush；
// 崩溃后新采集器实例（模拟 api 容器重建）从断点恢复，重扫量有界（仅断点之后的行），
// 不重复读取/保存已提交部分。
func TestCollectOnce_FlushBatchCheckpointsMidScan(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")

	lines := []string{
		notableLine(t, "fb-1"), notableLine(t, "fb-2"), notableLine(t, "fb-3"),
		notableLine(t, "fb-4"), notableLine(t, "fb-5"),
	}
	writeLines(t, logPath, lines)
	off2 := int64(len(lines[0]) + 1 + len(lines[1]) + 1) // 前两行（含 \n）的字节数

	saver := &flakySaver{failOn: 3} // 第 3 次 SavePrimary（第二个批量批次首条）失败
	c := NewCollector(saver, "test-flush-batch", logPath, cpPath, "node-1")
	c.SetFlushPolicy(2, time.Hour) // 仅批量触发（周期阈值放大到不触发）

	n, err := c.CollectOnce(context.Background())
	if err == nil {
		t.Fatal("want injected save failure, got nil")
	}
	if n != 4 {
		t.Fatalf("want 4 processed before failure, got %d", n)
	}
	// 断点停在第一个成功批次（前两行），而非 offset 0 或 EOF
	cp := readCheckpoint(t, cpPath)
	if cp.Offset != off2 {
		t.Fatalf("checkpoint offset = %d, want %d（最近一次成功 flush）", cp.Offset, off2)
	}
	if len(saver.saved) != 2 {
		t.Fatalf("want 2 saved before failure, got %d", len(saver.saved))
	}

	// 崩溃恢复：全新采集器实例（容器重建语义）从断点续传，故障消除
	saver.failOn = 0
	c2 := NewCollector(saver, "test-flush-batch", logPath, cpPath, "node-1")
	c2.SetFlushPolicy(2, time.Hour)
	n2, err := c2.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("resume CollectOnce: %v", err)
	}
	// 有界重扫：仅断点之后的 3 行，非全量 5 行
	if n2 != 3 {
		t.Fatalf("want bounded rescan of 3 lines, got %d", n2)
	}
	// 已提交的 fb-1/fb-2 未重复保存；五事件全程各恰好一次（重放安全由断点 + request_id 幂等兜底）
	if len(saver.saved) != 5 {
		t.Fatalf("want 5 total saved, got %d", len(saver.saved))
	}
	for i, want := range []string{"fb-1", "fb-2", "fb-3", "fb-4", "fb-5"} {
		if saver.saved[i].RequestID != want {
			t.Fatalf("saved[%d].RequestID = %s, want %s（顺序/重复异常）", i, saver.saved[i].RequestID, want)
		}
	}
	// 末次 EOF flush 后断点推进到文件尾
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if cp := readCheckpoint(t, cpPath); cp.Offset != info.Size() {
		t.Fatalf("final checkpoint offset = %d, want file size %d", cp.Offset, info.Size())
	}
}

// 周期触发：距上次 flush 超阈值即落批+断点（批量阈值放大到不触发）。
// 每次 SavePrimary 时探测断点：第 2/3 条保存时断点必须已是前一行 offset，
// 证明 flush 发生在扫描中途而非仅 EOF。
func TestCollectOnce_FlushIntervalCheckpointsMidScan(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")

	lines := []string{notableLine(t, "fi-1"), notableLine(t, "fi-2"), notableLine(t, "fi-3")}
	writeLines(t, logPath, lines)
	off1 := int64(len(lines[0]) + 1)
	off2 := off1 + int64(len(lines[1])+1)

	saver := &cpProbeSaver{cpPath: cpPath}
	c := NewCollector(saver, "test-flush-interval", logPath, cpPath, "node-1")
	c.SetFlushPolicy(100000, time.Nanosecond) // 仅周期触发（每行都超阈值）

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 3 {
		t.Fatalf("want 3 processed, got %d", n)
	}
	if len(saver.saved) != 3 {
		t.Fatalf("want 3 saved, got %d", len(saver.saved))
	}
	// 保存 fi-1 时断点尚未存在；保存 fi-2/fi-3 时断点已分别落在前一行 offset
	want := []int64{-1, off1, off2}
	if len(saver.offsets) != len(want) {
		t.Fatalf("probe count = %d, want %d", len(saver.offsets), len(want))
	}
	for i := range want {
		if saver.offsets[i] != want[i] {
			t.Fatalf("checkpoint offset at save[%d] = %d, want %d（周期 flush 未在扫描中途落盘）",
				i, saver.offsets[i], want[i])
		}
	}
}

// 默认参数与 SetFlushPolicy 纪律：内建默认保守（2000 行 / 2s）；非正值不覆盖既有配置。
func TestSetFlushPolicy(t *testing.T) {
	c := NewCollector(&fakeSaver{}, "test-flush-policy", filepath.Join(t.TempDir(), "x.log"), "", "node")
	if c.flushBatch != defaultFlushBatch || c.flushInterval != defaultFlushInterval {
		t.Fatalf("defaults not applied: batch=%d interval=%v", c.flushBatch, c.flushInterval)
	}
	if defaultFlushBatch != 2000 || defaultFlushInterval != 2*time.Second {
		t.Fatalf("unexpected built-in defaults: batch=%d interval=%v", defaultFlushBatch, defaultFlushInterval)
	}
	c.SetFlushPolicy(0, 0)
	if c.flushBatch != defaultFlushBatch || c.flushInterval != defaultFlushInterval {
		t.Fatal("non-positive values must keep defaults")
	}
	c.SetFlushPolicy(100, time.Second)
	if c.flushBatch != 100 || c.flushInterval != time.Second {
		t.Fatalf("override failed: batch=%d interval=%v", c.flushBatch, c.flushInterval)
	}
	c.SetFlushPolicy(-1, -time.Second)
	if c.flushBatch != 100 || c.flushInterval != time.Second {
		t.Fatal("negative values must keep current policy")
	}
}
