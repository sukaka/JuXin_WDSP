// sweeper_test.go 暴露面周期评估测试（MemStore + 假 DNS + 注入时钟）：
// 流量证据评估写维度 / 人工与锁定不覆盖 / 结论未变化 24h 内不重复写明细 /
// DNS 回落 / 留存清理 / 单端点失败隔离。
package apiexposure

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fixedNow 固定时钟（2026-10-23 12:00 UTC）。
func fixedNow() time.Time { return time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC) }

// newTestSweeper 装配测试评估器（假 DNS 全域公网可解析）。
func newTestSweeper(store *MemStore, settings SettingsReader, dns *PublicResolver) *Sweeper {
	if dns == nil {
		dns = newTestResolver(func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		})
	}
	return NewSweeper(store, settings).SetResolver(dns).SetClock(fixedNow)
}

// seedTraffic 造窗口内流量：近 days 天每天每 scope 请求 reqs 次（今天与昨天…）。
func seedTraffic(t *testing.T, store *MemStore, id uuid.UUID, scope string, days int, reqsPerDay int64) {
	t.Helper()
	ctx := context.Background()
	now := fixedNow()
	for d := 0; d < days; d++ {
		ts := now.Add(-time.Duration(d) * 24 * time.Hour)
		for i := int64(0); i < reqsPerDay; i++ {
			if err := store.RecordSource(ctx, id, scope, "fp-"+scope+"-1", ts); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestSweepTrafficVerdicts(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	pubID := uuid.New()   // 公网来源 3 天 → PUBLIC/HIGH
	intID := uuid.New()   // 内网来源 3 天×30 次 → INTERNAL/MEDIUM
	staleID := uuid.New() // 无流量，DNS 公网可解析 → PUBLIC/LOW（CONFIG）
	store.addEndpoint(pubID, "GET /pub", "pub.example.com", DeployReverseProxy, false, "", "", 0)
	store.addEndpoint(intID, "GET /intra", "intra.local", DeployReverseProxy, false, "", "", 0)
	store.addEndpoint(staleID, "GET /stale", "stale.example.com", DeployReverseProxy, false, "", "", 0)
	seedTraffic(t, store, pubID, ScopePublic, 3, 10)
	seedTraffic(t, store, intID, ScopeInternal, 3, 30)

	s := newTestSweeper(store, &fakeSettings{}, nil)
	stats, err := s.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if stats.Candidates != 3 || stats.Assessed != 3 || stats.Failed != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	// 维度已生效
	assertDimension := func(id uuid.UUID, value, source string) {
		t.Helper()
		ectx, err := store.EndpointContext(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if ectx.ExistingValue != value || ectx.ExistingSource != source {
			t.Fatalf("endpoint %s dimension = (%s, %s), want (%s, %s)",
				id, ectx.ExistingValue, ectx.ExistingSource, value, source)
		}
	}
	assertDimension(pubID, VerdictPublic, SourceTraffic)
	assertDimension(intID, VerdictInternal, SourceTraffic)
	assertDimension(staleID, VerdictPublic, SourceConfig)
	// 评估明细已写且证据为中文摘要
	latest, err := store.LatestAssessment(ctx, pubID)
	if err != nil || latest == nil {
		t.Fatalf("latest assessment: %v, %v", latest, err)
	}
	if latest.Verdict != VerdictPublic || latest.Confidence != ConfidenceHigh || len(latest.Evidence) == 0 {
		t.Fatalf("latest = %+v", latest)
	}
	if latest.Evidence[0].Type != "traffic_public" {
		t.Fatalf("evidence = %+v", latest.Evidence)
	}
}

func TestSweepManualNeverOverwritten(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	manualID := uuid.New() // MANUAL INTERNAL，窗口内有公网流量
	lockedID := uuid.New() // 锁定（现存 AUTO INTERNAL）
	store.addEndpoint(manualID, "GET /m", "m.example.com", DeployReverseProxy, false, VerdictInternal, SourceManual, 1)
	store.addEndpoint(lockedID, "GET /l", "l.example.com", DeployReverseProxy, true, VerdictInternal, "AUTO", 0.5)
	seedTraffic(t, store, manualID, ScopePublic, 3, 10)
	seedTraffic(t, store, lockedID, ScopePublic, 3, 10)

	s := newTestSweeper(store, &fakeSettings{}, nil)
	if _, err := s.SweepOnce(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	for _, id := range []uuid.UUID{manualID, lockedID} {
		ectx, _ := store.EndpointContext(ctx, id)
		if ectx.ExistingValue != VerdictInternal {
			t.Fatalf("endpoint %s overwritten to %s", id, ectx.ExistingValue)
		}
		if store.applyCount(id) != 0 {
			t.Fatalf("endpoint %s applyCount=%d, want 0", id, store.applyCount(id))
		}
		// 仍写评估明细（verdict=人工值，source=MANUAL）
		latest, _ := store.LatestAssessment(ctx, id)
		if latest == nil || latest.Source != SourceManual || latest.Verdict != VerdictInternal {
			t.Fatalf("endpoint %s manual assessment = %+v", id, latest)
		}
	}
}

func TestSweepSkipsUnchangedAssessment(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	id := uuid.New()
	store.addEndpoint(id, "GET /x", "x.example.com", DeployReverseProxy, false, "", "", 0)
	seedTraffic(t, store, id, ScopePublic, 3, 10)
	s := newTestSweeper(store, &fakeSettings{}, nil)
	if _, err := s.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := len(store.assessments[id]); got != 1 {
		t.Fatalf("assessments=%d, want 1", got)
	}
	// 结论未变化且 24h 内已评估：ListCandidates 不再选中（最近评估 <24h）→ 不重写
	if _, err := s.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := len(store.assessments[id]); got != 1 {
		t.Fatalf("after re-sweep assessments=%d, want 1", got)
	}
}

func TestSweepFailureIsolation(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	okID := uuid.New()
	missingID := uuid.New() // 有流量但端点已不存在（外键级联前快照）→ EndpointContext ErrNotFound
	store.addEndpoint(okID, "GET /ok", "ok.example.com", DeployReverseProxy, false, "", "", 0)
	seedTraffic(t, store, okID, ScopePublic, 3, 10)
	// 直接造 missingID 的流量行（绕过 addEndpoint）
	if err := store.RecordSource(ctx, missingID, ScopePublic, "fp-x", fixedNow()); err != nil {
		t.Fatal(err)
	}
	// MemStore.ListCandidates 只枚举已登记端点；构造未登记端点候选需要 SQL 侧行为——
	// 这里改测 Sweeper 对单端点错误的隔离：assessOne 对不存在端点返回 ErrNotFound，
	// SweepOnce 循环继续。用 AssessEndpoint 验证错误如实返回。
	s := newTestSweeper(store, &fakeSettings{}, nil)
	if _, _, err := s.AssessEndpoint(ctx, missingID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("assess missing endpoint = %v, want ErrNotFound", err)
	}
	// 正常端点不受影响
	a, applied, err := s.AssessEndpoint(ctx, okID)
	if err != nil || a.Verdict != VerdictPublic || !applied {
		t.Fatalf("assess ok endpoint = (%+v, %t, %v)", a, applied, err)
	}
}

func TestSweepPrune(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	id := uuid.New()
	store.addEndpoint(id, "GET /p", "p.example.com", DeployReverseProxy, false, "", "", 0)
	// 40 天前的旧桶 + 旧评估
	old := fixedNow().Add(-40 * 24 * time.Hour)
	if err := store.RecordSource(ctx, id, ScopeInternal, "fp-old", old); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteAssessment(ctx, id, Assessment{
		Verdict: VerdictInternal, Source: SourceTraffic, Confidence: ConfidenceMedium,
		Evidence: []EvidenceItem{{Type: "traffic_internal", Summary: "旧评估"}},
	}, old); err != nil {
		t.Fatal(err)
	}
	s := newTestSweeper(store, &fakeSettings{}, nil)
	stats, err := s.SweepOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pruned < 3 { // 旧 bucket + 旧 seen + 旧 assessment
		t.Fatalf("pruned = %d, want >= 3", stats.Pruned)
	}
	if got := store.bucketCount(id, old, ScopeInternal); got != 0 {
		t.Fatalf("old bucket count = %d, want 0", got)
	}
}

// TestAssessEndpointAlwaysWrites 人工重评恒写明细（结论未变化也写）。
func TestAssessEndpointAlwaysWrites(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	id := uuid.New()
	store.addEndpoint(id, "GET /y", "y.example.com", DeployReverseProxy, false, "", "", 0)
	seedTraffic(t, store, id, ScopePublic, 3, 10)
	s := newTestSweeper(store, &fakeSettings{}, nil)
	if _, err := s.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AssessEndpoint(ctx, id); err != nil {
		t.Fatal(err)
	}
	if got := len(store.assessments[id]); got != 2 {
		t.Fatalf("after reassess assessments=%d, want 2", got)
	}
}

// TestSweepWithoutResolver 未注入 DNS 判定器：流量不足时无 DNS 证据 → UNKNOWN。
func TestSweepWithoutResolver(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	id := uuid.New()
	store.addEndpoint(id, "GET /z", "z.example.com", DeployReverseProxy, false, "", "", 0)
	s := NewSweeper(store, &fakeSettings{}).SetClock(fixedNow) // 无 resolver
	if _, err := s.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	ectx, _ := store.EndpointContext(ctx, id)
	if ectx.ExistingValue != VerdictUnknown {
		t.Fatalf("dimension = %s, want UNKNOWN", ectx.ExistingValue)
	}
	latest, _ := store.LatestAssessment(ctx, id)
	if latest == nil || hasEvidenceType(Assessment{Evidence: latest.Evidence}, "config_dns") {
		t.Fatalf("dns evidence should be absent: %+v", latest)
	}
}
