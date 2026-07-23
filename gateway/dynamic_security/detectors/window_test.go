package detectors

import (
	"testing"
	"time"
)

func TestLRU_EvictsOldest(t *testing.T) {
	l := newLRU(2)
	l.set("a", 1)
	l.set("b", 2)
	// 触达 a 使其成为最近使用，b 变为最久未用
	if _, ok := l.get("a"); !ok {
		t.Fatal("a should exist")
	}
	l.set("c", 3)
	if _, ok := l.get("b"); ok {
		t.Fatal("b should be evicted (LRU)")
	}
	if _, ok := l.get("a"); !ok {
		t.Fatal("a should survive (recently used)")
	}
	if _, ok := l.get("c"); !ok {
		t.Fatal("c should exist")
	}
}

func TestWindowTracker_RollsWindowAndArchivesHistory(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	tr := newWindowTracker(10, clk.Now)
	for i := 0; i < 3; i++ {
		count, hist := tr.add("k")
		if count != i+1 || len(hist) != 0 {
			t.Fatalf("same window: count=%d hist=%v", count, hist)
		}
	}
	clk.Advance(time.Minute)
	count, hist := tr.add("k")
	if count != 1 {
		t.Fatalf("new window should reset count, got %d", count)
	}
	if len(hist) != 1 || hist[0] != 3 {
		t.Fatalf("history should archive previous window count 3, got %v", hist)
	}
}

func TestWindowTracker_KeyCapacityLRU(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	tr := newWindowTracker(2, clk.Now)
	tr.add("a")
	tr.add("b")
	tr.add("c") // 超容量，淘汰最久未用的 a
	// 单线程测试内直接检查内部索引（lru 本身非线程安全，由 tracker 加锁）
	_, aOK := tr.entries.get("a")
	_, cOK := tr.entries.get("c")
	if aOK {
		t.Fatal("a should be evicted at capacity")
	}
	if !cOK {
		t.Fatal("c should exist")
	}
}
