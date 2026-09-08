package buffer

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openTB(t *testing.T, segBytes, maxBytes int64, maxAge time.Duration) *Buffer {
	t.Helper()
	b, err := Open(t.TempDir(), segBytes, maxBytes, maxAge, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestWriteAndReplayOrder(t *testing.T) {
	b := openTB(t, 1<<20, 10<<20, time.Hour)
	for i := 0; i < 10; i++ {
		if err := b.Write([]byte(fmt.Sprintf(`{"n":%d}`, i))); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	done, err := b.Replay(4, func(batch [][]byte) error {
		for _, r := range batch {
			got = append(got, string(r))
		}
		return nil
	})
	if err != nil || done != 1 {
		t.Fatalf("done=%d err=%v", done, err)
	}
	if len(got) != 10 {
		t.Fatalf("got %d recs", len(got))
	}
	for i, r := range got {
		if r != fmt.Sprintf(`{"n":%d}`, i) {
			t.Fatalf("第 %d 条乱序: %s", i, r)
		}
	}
	if b.Bytes() != 0 || b.Segments() != 0 {
		t.Fatalf("补传成功后应清空: bytes=%d segs=%d", b.Bytes(), b.Segments())
	}
}

func TestSegmentRollover(t *testing.T) {
	b := openTB(t, 128, 1<<20, time.Hour) // 128B 段
	rec := bytes.Repeat([]byte("x"), 60)
	for i := 0; i < 5; i++ {
		if err := b.Write(rec); err != nil {
			t.Fatal(err)
		}
	}
	if b.Segments() < 3 {
		t.Fatalf("应滚动多段, got %d", b.Segments())
	}
	// 全部可补传
	total := 0
	_, err := b.Replay(100, func(batch [][]byte) error {
		total += len(batch)
		return nil
	})
	if err != nil || total != 5 {
		t.Fatalf("total=%d err=%v", total, err)
	}
}

func TestMaxBytesFIFO(t *testing.T) {
	b := openTB(t, 128, 200, time.Hour)  // 总上限 200B
	rec := bytes.Repeat([]byte("x"), 60) // 每条 64B
	for i := 0; i < 10; i++ {
		if err := b.Write(rec); err != nil {
			t.Fatal(err)
		}
	}
	if b.Bytes() > 200+128 { // 允许当前段在写
		t.Fatalf("超上限未 FIFO: %d", b.Bytes())
	}
	// 重启扫描仍在上限内
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b2, err := Open(b.dir, 128, 200, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close()
	if b2.Bytes() > 200+128 {
		t.Fatalf("重开后超上限: %d", b2.Bytes())
	}
}

func TestMaxAgeCleanup(t *testing.T) {
	dir := t.TempDir()
	b, err := Open(dir, 128, 1<<20, time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	rec := bytes.Repeat([]byte("x"), 60)
	for i := 0; i < 4; i++ {
		if err := b.Write(rec); err != nil {
			t.Fatal(err)
		}
	}
	// 把最旧两段的 mtime 改到 2 小时前
	segs, _ := filepath.Glob(filepath.Join(dir, "seg-*.log"))
	if len(segs) < 2 {
		t.Fatalf("segs=%d", len(segs))
	}
	old := time.Now().Add(-2 * time.Hour)
	for _, s := range segs[:len(segs)-1] {
		if err := os.Chtimes(s, old, old); err != nil {
			t.Fatal(err)
		}
	}
	// 重开触发扫描清理
	_ = b.Close()
	b2, err := Open(dir, 128, 1<<20, time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close()
	if b2.Segments() != 1 {
		t.Fatalf("超龄段应被清理, 剩 %d 段", b2.Segments())
	}
}

func TestReplayFailureKeepsData(t *testing.T) {
	b := openTB(t, 1<<20, 10<<20, time.Hour)
	for i := 0; i < 5; i++ {
		if err := b.Write([]byte(fmt.Sprintf(`{"n":%d}`, i))); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	done, err := b.Replay(2, func(batch [][]byte) error {
		calls++
		if calls == 2 {
			return fmt.Errorf("模拟发送失败")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if done != 0 {
		t.Fatalf("整段未成功不应删段: done=%d", done)
	}
	if b.Bytes() == 0 {
		t.Fatal("失败后数据应保留")
	}
	// 再次补传可成功
	done, err = b.Replay(2, func(batch [][]byte) error { return nil })
	if err != nil || done != 1 || b.Bytes() != 0 {
		t.Fatalf("重试补传失败: done=%d err=%v bytes=%d", done, err, b.Bytes())
	}
}

func TestDisabled(t *testing.T) {
	b, err := Open(t.TempDir(), 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Write([]byte("x")); err != ErrDisabled {
		t.Fatalf("err=%v", err)
	}
	if b.Bytes() != 0 {
		t.Fatal("禁用态不应有数据")
	}
}

func TestUpdateLimits(t *testing.T) {
	b := openTB(t, 128, 1<<20, time.Hour)
	rec := bytes.Repeat([]byte("x"), 60)
	for i := 0; i < 5; i++ {
		if err := b.Write(rec); err != nil {
			t.Fatal(err)
		}
	}
	b.UpdateLimits(150, 0, true) // 收紧上限 → FIFO
	if b.Bytes() > 150+128 {
		t.Fatalf("UpdateLimits 未生效: %d", b.Bytes())
	}
	b.UpdateLimits(0, 0, false)
	if err := b.Write(rec); err != ErrDisabled {
		t.Fatalf("禁用后写入应 ErrDisabled: %v", err)
	}
}
