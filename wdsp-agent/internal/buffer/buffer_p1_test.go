// P1-03 严格限额测试：活动段纳入年龄/大小淘汰、总量硬上限含当前段、
// 损坏段计数、最旧段年龄与淘汰指标。
package buffer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 总量硬上限含当前写入段：Write 后任意时刻 total ≤ maxBytes（不再有
// "保留当前段" 的 ~1 段豁免量），淘汰按 size_evicted 计数。
func TestStrictMaxBytesIncludesActiveSegment(t *testing.T) {
	b := openTB(t, 128, 200, time.Hour) // 段 128B，总硬上限 200B
	rec := bytes.Repeat([]byte("x"), 60)
	for i := 0; i < 10; i++ {
		if err := b.Write(rec); err != nil {
			t.Fatal(err)
		}
		if b.Bytes() > 200 {
			t.Fatalf("第 %d 次写入后总量 %d 超硬上限 200", i+1, b.Bytes())
		}
	}
	st := b.Stats()
	if st.DroppedSegments[ReasonSizeEvict] == 0 {
		t.Fatal("应有 size_evicted 淘汰计数")
	}
	// 淘汰后缓存仍可写入（活动段被淘汰时关闭句柄，下次写入滚新段）
	if err := b.Write(rec); err != nil {
		t.Fatalf("淘汰活动段后写入失败: %v", err)
	}
	if b.Bytes() > 200 {
		t.Fatalf("淘汰后写入仍超硬上限: %d", b.Bytes())
	}
	// 重启扫描后仍严格在上限内
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b2, err := Open(b.dir, 128, 200, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close()
	if b2.Bytes() > 200 {
		t.Fatalf("重开后超硬上限: %d", b2.Bytes())
	}
}

// 单条记录超过总量硬上限：直接拒绝（永远无法保留，防御配置错误）。
func TestWriteRecordExceedingMaxBytesRejected(t *testing.T) {
	b := openTB(t, 128, 64, time.Hour)
	if err := b.Write(bytes.Repeat([]byte("x"), 100)); err == nil {
		t.Fatal("超过总上限的单条记录应拒绝")
	}
	if b.Bytes() != 0 {
		t.Fatalf("拒绝后不应有残留: %d", b.Bytes())
	}
}

// 活动段超龄同样淘汰（含活动段按冻结口径；只有持续写入的活动段才刷新年龄）。
func TestActiveSegmentAgeEviction(t *testing.T) {
	dir := t.TempDir()
	b, err := Open(dir, 128, 1<<20, time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	rec := bytes.Repeat([]byte("x"), 60)
	for i := 0; i < 3; i++ {
		if err := b.Write(rec); err != nil {
			t.Fatal(err)
		}
	}
	segs, _ := filepath.Glob(filepath.Join(dir, "seg-*.log"))
	if len(segs) == 0 {
		t.Fatal("应有段文件")
	}
	// 把全部段（含活动段）mtime 改到 2 小时前
	old := time.Now().Add(-2 * time.Hour)
	for _, s := range segs {
		if err := os.Chtimes(s, old, old); err != nil {
			t.Fatal(err)
		}
	}
	// 重建索引（恢复 modTime 视角）后执行周期清理
	b2, err := Open(dir, 128, 1<<20, time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close()
	b2.Enforce()
	if b2.Segments() != 0 || b2.Bytes() != 0 {
		t.Fatalf("全部段（含活动段）超龄应清空: segs=%d bytes=%d", b2.Segments(), b2.Bytes())
	}
	st := b2.Stats()
	if st.DroppedSegments[ReasonAgeEvict] != int64(len(segs)) {
		t.Fatalf("age_evicted 计数错误: %v", st.DroppedSegments)
	}
	// 淘汰后缓存仍可写入
	if err := b2.Write(rec); err != nil {
		t.Fatalf("超龄清空后写入失败: %v", err)
	}
}

// 损坏段：封存段尾部截断 → 可读前缀照常补传，损坏尾部计数，段删除不残留。
func TestCorruptSegmentCounted(t *testing.T) {
	dir := t.TempDir()
	b, err := Open(dir, 128, 1<<20, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	rec := []byte(`{"n":1}`)
	if err := b.Write(rec); err != nil {
		t.Fatal(err)
	}
	if err := b.Write(bytes.Repeat([]byte("y"), 200)); err != nil { // 触发滚动，封存 seg-1
		t.Fatal(err)
	}
	if b.Segments() < 2 {
		t.Fatalf("应已滚动出封存段: %d", b.Segments())
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	// 损坏封存段 seg-00000001.log：尾部追加半条记录（长度头声称 50B 但只有 5B）
	f, err := os.OpenFile(filepath.Join(dir, segName(1)), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 50)
	if _, err := f.Write(append(hdr[:], []byte("trunc")...)); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	b2, err := Open(dir, 128, 1<<20, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close()
	var got [][]byte
	if _, err := b2.Replay(100, func(batch [][]byte) error {
		got = append(got, batch...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("可读记录应全部补传: %d", len(got))
	}
	if !bytes.Equal(got[0], rec) {
		t.Fatalf("首条内容不符: %s", got[0])
	}
	st := b2.Stats()
	if st.CorruptSegments != 1 {
		t.Fatalf("损坏段应计数 1: %d", st.CorruptSegments)
	}
	if st.DroppedBytes[ReasonCorrupt] != 9 { // 4 字节头 + 5 字节截断体
		t.Fatalf("损坏字节计数错误: %v", st.DroppedBytes)
	}
	if b2.Segments() != 0 {
		t.Fatalf("补传后段应清空: %d", b2.Segments())
	}
}

// 畸形长度头（0 与超 maxRecordBytes）按损坏计数，可读前缀保留。
func TestCorruptLengthHeaderCounted(t *testing.T) {
	dir := t.TempDir()
	b, err := Open(dir, 1<<20, 1<<20, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Write([]byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, segName(1)), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	var hdr [4]byte // 全零长度头 = 畸形
	if _, err := f.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("garbage-after-bad-header")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	b2, err := Open(dir, 1<<20, 1<<20, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close()
	got := 0
	if _, err := b2.Replay(100, func(batch [][]byte) error {
		got += len(batch)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("仅畸形头前的记录可读: %d", got)
	}
	st := b2.Stats()
	if st.CorruptSegments != 1 || st.DroppedBytes[ReasonCorrupt] != 4+24 {
		t.Fatalf("损坏计数错误: %+v", st)
	}
}

// OldestAge 报告最旧段年龄。
func TestOldestAge(t *testing.T) {
	b := openTB(t, 128, 1<<20, time.Hour)
	if d := b.OldestAge(time.Now()); d != 0 {
		t.Fatalf("空缓存年龄应为 0: %v", d)
	}
	if err := b.Write([]byte(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	if d := b.OldestAge(time.Now().Add(time.Minute)); d < time.Minute {
		t.Fatalf("年龄应反映最旧段: %v", d)
	}
}

// 满盘语义：总量硬上限下持续写入 = 旧数据被淘汰腾出空间，写入不失败、
// 总量永不越限（淘汰计数持续增加）。
func TestFullCapacityContinuousWrite(t *testing.T) {
	b := openTB(t, 128, 256, time.Hour)
	rec := bytes.Repeat([]byte("x"), 60)
	for i := 0; i < 100; i++ {
		if err := b.Write(rec); err != nil {
			t.Fatalf("第 %d 次写入失败: %v", i, err)
		}
	}
	if b.Bytes() > 256 {
		t.Fatalf("总量越限: %d", b.Bytes())
	}
	st := b.Stats()
	if st.DroppedSegments[ReasonSizeEvict] == 0 {
		t.Fatal("持续写入应有淘汰计数")
	}
	// 缓存中仅剩最新数据：补传条数远小于写入条数
	got := 0
	if _, err := b.Replay(500, func(batch [][]byte) error {
		got += len(batch)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got == 0 || got >= 100 {
		t.Fatalf("应只保留最新部分: %d", got)
	}
	fmt.Printf("保留 %d/100 条\n", got)
}
