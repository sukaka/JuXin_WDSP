package riskengine

import (
	"fmt"
	"testing"
	"time"
)

func entryAt(typ string, score int, at time.Time) SignalEntry {
	return SignalEntry{Type: typ, Score: score, Reason: "test", At: at}
}

// 滑窗求和 + 明细完整性（解释"为什么得 N 分"）。
func TestMemoryStoreSumAndDetail(t *testing.T) {
	s := NewMemoryStore(time.Hour, 0, nil)
	now := time.Now().UTC()
	if err := s.Add("id1",
		entryAt("SENSITIVE_PATH_PROBE", 15, now.Add(-time.Minute)),
		entryAt("AUTH_FAIL_PROBE", 15, now.Add(-30*time.Second)),
		entryAt("WAF", 50, now)); err != nil {
		t.Fatal(err)
	}
	score, entries, err := s.State("id1")
	if err != nil {
		t.Fatal(err)
	}
	if score != 80 || len(entries) != 3 {
		t.Fatalf("score=%d entries=%d", score, len(entries))
	}
	if entries[0].Type != "SENSITIVE_PATH_PROBE" || entries[2].Type != "WAF" || entries[2].At.IsZero() {
		t.Fatalf("entries detail: %+v", entries)
	}
	// 隔离：其他 identity 为零
	if score, entries, _ := s.State("id2"); score != 0 || len(entries) != 0 {
		t.Fatalf("isolation: %d %v", score, entries)
	}
}

// 滑窗过期：窗口外信号不计分；窗口边界（恰好 cutoff）保留。
func TestMemoryStoreWindowExpiry(t *testing.T) {
	s := NewMemoryStore(time.Hour, 0, nil)
	base := time.Now().UTC()
	s.now = func() time.Time { return base }
	_ = s.Add("id1", entryAt("A", 50, base.Add(-2*time.Hour)), entryAt("B", 30, base.Add(-30*time.Minute)))
	score, entries, _ := s.State("id1")
	if score != 30 || len(entries) != 1 || entries[0].Type != "B" {
		t.Fatalf("expired must not count: %d %+v", score, entries)
	}
	// 时间前进：B 也过期后归零
	s.now = func() time.Time { return base.Add(time.Hour) }
	if score, entries, _ = s.State("id1"); score != 0 || len(entries) != 0 {
		t.Fatalf("all expired: %d %+v", score, entries)
	}
}

// 截断 [0,100]：超 100 按 100。
func TestMemoryStoreClamp(t *testing.T) {
	s := NewMemoryStore(time.Hour, 0, nil)
	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		_ = s.Add("id1", entryAt("WAF", 50, now))
	}
	score, entries, _ := s.State("id1")
	if score != 100 || len(entries) != 10 {
		t.Fatalf("clamp: %d %d", score, len(entries))
	}
}

// 明细上限：超 MaxEntriesPerIdentity 淘汰最旧（有界内存纪律）。
func TestMemoryStoreEntryCap(t *testing.T) {
	s := NewMemoryStore(24*time.Hour, 0, nil)
	now := time.Now().UTC()
	for i := 0; i < MaxEntriesPerIdentity+50; i++ {
		_ = s.Add("id1", entryAt(fmt.Sprintf("T%d", i), 1, now.Add(time.Duration(i)*time.Second)))
	}
	_, entries, _ := s.State("id1")
	if len(entries) != MaxEntriesPerIdentity {
		t.Fatalf("cap: %d", len(entries))
	}
	// 保留最近批次（最旧的 T0 已被淘汰）
	if entries[0].Type == "T0" || entries[len(entries)-1].Type != fmt.Sprintf("T%d", MaxEntriesPerIdentity+49) {
		t.Fatalf("oldest must be evicted: %s..%s", entries[0].Type, entries[len(entries)-1].Type)
	}
}
