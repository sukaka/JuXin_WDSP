// store_test.go 内存仓储语义测试：upsert 幂等、列表筛选、状态流转、统计、
// 扫描记录与推荐去重标记（SQLStore 遵循同一契约）。
package ainoise

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func wafEvent(host, uri, ip string, ruleID int, at time.Time) EventInput {
	return EventInput{
		EventID: uuid.New(), Source: SourceWAF, Host: host, RawURI: uri,
		RuleID: &ruleID, ClientIP: ip, OccurredAt: at,
	}
}

func TestMemStoreUpsertIdempotent(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	now := time.Now().UTC()
	ev := wafEvent("a.com", "/users/42", "1.2.3.4", 942100, now)

	created, id1, err := m.UpsertEvent(ctx, ev)
	if err != nil || !created {
		t.Fatalf("first upsert created=%v err=%v", created, err)
	}
	// 同一事件重复扫描（窗口重叠）：不新建簇、不重复计数
	created, id2, err := m.UpsertEvent(ctx, ev)
	if err != nil {
		t.Fatal(err)
	}
	if created || id2 != id1 {
		t.Fatalf("rescan created=%v id mismatch", created)
	}
	c, _ := m.Get(ctx, id1)
	if c.EventCount != 1 {
		t.Fatalf("event_count=%d want 1 (idempotent rescan)", c.EventCount)
	}

	// 同指纹新事件：计数 +1，last_seen 前移
	ev2 := wafEvent("a.com", "/users/43", "1.2.3.4", 942100, now.Add(time.Minute))
	created, id3, err := m.UpsertEvent(ctx, ev2)
	if err != nil {
		t.Fatal(err)
	}
	if created || id3 != id1 {
		t.Fatalf("same-fingerprint event should reuse cluster, created=%v", created)
	}
	c, _ = m.Get(ctx, id1)
	if c.EventCount != 2 {
		t.Fatalf("event_count=%d want 2", c.EventCount)
	}
	if !c.LastSeen.Equal(now.Add(time.Minute)) {
		t.Fatalf("last_seen not advanced: %v", c.LastSeen)
	}

	// 不同 IP → 不同簇
	ev3 := wafEvent("a.com", "/users/44", "9.9.9.9", 942100, now)
	created, id4, err := m.UpsertEvent(ctx, ev3)
	if err != nil {
		t.Fatal(err)
	}
	if !created || id4 == id1 {
		t.Fatal("different client_ip should create new cluster")
	}
}

func TestMemStoreRepresentativeAndEvents(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	now := time.Now().UTC()
	e1 := wafEvent("a.com", "/x/1", "1.1.1.1", 111, now)
	e2 := wafEvent("a.com", "/x/2", "1.1.1.1", 111, now.Add(time.Second))
	_, id, _ := m.UpsertEvent(ctx, e1)
	_, _, _ = m.UpsertEvent(ctx, e2)
	events, err := m.ListEvents(ctx, id, 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("events=%v err=%v", events, err)
	}
	rep := 0
	for _, e := range events {
		if e.IsRepresentative {
			rep++
		}
	}
	if rep != 1 || !events[0].IsRepresentative {
		t.Fatalf("exactly one representative first, got %v", events)
	}
}

func TestMemStoreTransition(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	_, id, _ := m.UpsertEvent(ctx, wafEvent("a.com", "/x", "1.1.1.1", 111, time.Now().UTC()))

	// resolve → RESOLVED；再 suppress/resolve 均拒绝
	if _, err := m.Transition(ctx, id, "resolve"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Transition(ctx, id, "suppress"); err != ErrClusterState {
		t.Fatalf("suppress resolved: %v", err)
	}
	if _, err := m.Transition(ctx, id, "resolve"); err != ErrClusterState {
		t.Fatalf("re-resolve: %v", err)
	}
	if _, err := m.Transition(ctx, uuid.New(), "suppress"); err != ErrClusterNotFound {
		t.Fatalf("missing cluster: %v", err)
	}

	// suppress → SUPPRESSED → resolve 允许
	_, id2, _ := m.UpsertEvent(ctx, wafEvent("b.com", "/y", "2.2.2.2", 222, time.Now().UTC()))
	c, err := m.Transition(ctx, id2, "suppress")
	if err != nil || c.Status != StatusSuppressed {
		t.Fatalf("suppress: %v %v", c, err)
	}
	c, err = m.Transition(ctx, id2, "resolve")
	if err != nil || c.Status != StatusResolved {
		t.Fatalf("resolve suppressed: %v %v", c, err)
	}
}

func TestMemStoreListAndStats(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	now := time.Now().UTC()
	_, id1, _ := m.UpsertEvent(ctx, wafEvent("a.com", "/x/1", "1.1.1.1", 111, now))
	_, _, _ = m.UpsertEvent(ctx, wafEvent("a.com", "/x/2", "1.1.1.1", 111, now.Add(time.Second)))
	api := EventInput{
		EventID: uuid.New(), Source: SourceAPI, RawURI: "GET /users/{id}",
		DetectorCode: "api_schema", OccurredAt: now,
	}
	_, _, _ = m.UpsertEvent(ctx, api)
	_, _ = m.Transition(ctx, id1, "suppress")

	list, total, err := m.List(ctx, ListFilter{Source: "WAF"})
	if err != nil || total != 1 || len(list) != 1 {
		t.Fatalf("list waf: total=%d err=%v", total, err)
	}
	list, total, _ = m.List(ctx, ListFilter{Status: "SUPPRESSED"})
	if total != 1 || list[0].ID != id1 {
		t.Fatalf("list suppressed: total=%d", total)
	}
	stats, err := m.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.ActiveClusters != 1 || stats.SuppressedClusters != 1 || stats.FoldedEvents != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	// LIKE_FP 统计
	_ = m.UpdateVerdict(ctx, id1, VerdictLikelyFalsePositive, nil, "x")
	_, id2, _ := m.UpsertEvent(ctx, wafEvent("c.com", "/z", "3.3.3.3", 333, now))
	conf := 0.9
	_ = m.UpdateVerdict(ctx, id2, VerdictLikelyFalsePositive, &conf, "fp")
	stats, _ = m.Stats(ctx)
	if stats.LikelyFalsePositiveClusters != 1 {
		t.Fatalf("like_fp=%d want 1 (suppressed 不计)", stats.LikelyFalsePositiveClusters)
	}
}

func TestMemStoreCandidatesAndOpenRecommendation(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	now := time.Now().UTC()
	rule := 942100
	_, id, _ := m.UpsertEvent(ctx, EventInput{
		EventID: uuid.New(), Source: SourceWAF, Host: "a.com", RawURI: "/p",
		RuleID: &rule, ClientIP: "1.1.1.1", OccurredAt: now,
	})
	// 未达阈值不出现在候选
	cands, _ := m.VerdictCandidates(ctx, 2, 10)
	if len(cands) != 0 {
		t.Fatal("below threshold should not be candidate")
	}
	_, _, _ = m.UpsertEvent(ctx, EventInput{
		EventID: uuid.New(), Source: SourceWAF, Host: "a.com", RawURI: "/p",
		RuleID: &rule, ClientIP: "1.1.1.1", OccurredAt: now.Add(time.Second),
	})
	cands, _ = m.VerdictCandidates(ctx, 2, 10)
	if len(cands) != 1 || cands[0].ID != id {
		t.Fatalf("candidates=%v", cands)
	}
	// 判定后不再出现在待评分候选
	_ = m.UpdateVerdict(ctx, id, VerdictLikelyFalsePositive, nil, "fp")
	cands, _ = m.VerdictCandidates(ctx, 2, 10)
	if len(cands) != 0 {
		t.Fatal("scored cluster should leave verdict candidates")
	}
	fp, _ := m.FalsePositiveCandidates(ctx, 2, 10)
	if len(fp) != 1 {
		t.Fatalf("fp candidates=%v", fp)
	}
	// 推荐去重标记
	open, _ := m.HasOpenRecommendation(ctx, id)
	if open {
		t.Fatal("unexpected open recommendation")
	}
	m.SetOpenRecommendation(id)
	open, _ = m.HasOpenRecommendation(ctx, id)
	if !open {
		t.Fatal("open recommendation not tracked")
	}
}

func TestMemStoreSweepRuns(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	now := time.Now().UTC()
	fin := now.Add(time.Second)
	_ = m.RecordSweepRun(ctx, &SweepRun{StartedAt: now, FinishedAt: &fin, ScannedEvents: 3, Status: SweepSuccess})
	runs, total, err := m.ListSweepRuns(ctx, 1, 10)
	if err != nil || total != 1 || len(runs) != 1 {
		t.Fatalf("runs total=%d err=%v", total, err)
	}
	if runs[0].ScannedEvents != 3 || runs[0].Status != SweepSuccess || runs[0].ID == uuid.Nil {
		t.Fatalf("run=%+v", runs[0])
	}
}
