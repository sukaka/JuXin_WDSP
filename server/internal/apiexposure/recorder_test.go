// recorder_test.go 采集侧来源聚合记录器测试：scope 分类（内网/公网/合作方/非法）、
// 匿名指纹只计桶、partner CIDR 缓存与 settings 变更生效（TTL 内不重读）。
package apiexposure

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeSettings 测试设置（map 驱动，GetString/GetInt 满足 SettingsReader）。
type fakeSettings struct {
	mu   sync.Mutex
	str  map[string]string
	ints map[string]int
}

func (f *fakeSettings) GetString(_ context.Context, group, key, def string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.str[group+":"+key]; ok {
		return v
	}
	return def
}

func (f *fakeSettings) GetInt(_ context.Context, group, key string, def int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.ints[group+":"+key]; ok {
		return v
	}
	return def
}

func (f *fakeSettings) set(kv map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.str = kv
}

func TestRecordSourceClassification(t *testing.T) {
	store := NewMemStore()
	epID := uuid.New()
	now := time.Now()
	rec := NewSourceRecorder(store, &fakeSettings{str: map[string]string{
		"exposure_engine:partner_egress_cidrs": "203.0.113.0/24",
	}})
	ctx := context.Background()
	// 内网 / 公网 / 合作方出口 / 非法
	for _, c := range []struct {
		ip    string
		scope string
	}{
		{"10.1.2.3", ScopeInternal},
		{"8.8.8.8", ScopePublic},
		{"203.0.113.9", ScopePartner},
	} {
		if err := rec.RecordSource(ctx, epID, c.ip, "fp-"+c.scope, now); err != nil {
			t.Fatalf("RecordSource(%s): %v", c.ip, err)
		}
	}
	if err := rec.RecordSource(ctx, epID, "not-an-ip", "fp-x", now); err != nil {
		t.Fatalf("invalid ip should be tolerated: %v", err)
	}
	stats, err := store.WindowStats(ctx, epID, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, b := range stats {
		got[b.Scope] = b.Requests
	}
	if got[ScopeInternal] != 1 || got[ScopePublic] != 1 || got[ScopePartner] != 1 {
		t.Fatalf("window stats = %v", got)
	}
}

// TestRecordSourceAnonymousFingerprint 匿名来源（空指纹）只计桶不落去重明细。
func TestRecordSourceAnonymousFingerprint(t *testing.T) {
	store := NewMemStore()
	epID := uuid.New()
	now := time.Now()
	rec := NewSourceRecorder(store, nil)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := rec.RecordSource(ctx, epID, "8.8.8.8", "", now); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := store.WindowStats(ctx, epID, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 1 || stats[0].Requests != 3 || stats[0].UniqueSources != 0 {
		t.Fatalf("anonymous stats = %+v", stats)
	}
	// 带指纹两个不同来源 → 去重 2
	_ = rec.RecordSource(ctx, epID, "8.8.8.8", "fp-a", now)
	_ = rec.RecordSource(ctx, epID, "1.1.1.1", "fp-b", now)
	stats, _ = store.WindowStats(ctx, epID, now.Add(-24*time.Hour))
	if stats[0].Requests != 5 || stats[0].UniqueSources != 2 {
		t.Fatalf("dedup stats = %+v", stats[0])
	}
}

// TestPartnerCIDRCacheTTL partner CIDR 在 TTL 内用缓存（settings 变更不立即生效），
// 超 TTL 重读生效。
func TestPartnerCIDRCacheTTL(t *testing.T) {
	store := NewMemStore()
	settings := &fakeSettings{str: map[string]string{}}
	rec := NewSourceRecorder(store, settings)
	ctx := context.Background()
	epID := uuid.New()
	now := time.Now()
	// 初始无 CIDR：203.0.113.9 是公网
	_ = rec.RecordSource(ctx, epID, "203.0.113.9", "fp1", now)
	settings.set(map[string]string{"exposure_engine:partner_egress_cidrs": "203.0.113.0/24"})
	// TTL 内仍走缓存（公网）
	_ = rec.RecordSource(ctx, epID, "203.0.113.9", "fp1", now)
	// 过期缓存强制重读
	rec.partner.mu.Lock()
	rec.partner.loadedAt = time.Now().Add(-2 * partnerCacheTTL)
	rec.partner.mu.Unlock()
	_ = rec.RecordSource(ctx, epID, "203.0.113.9", "fp1", now)
	stats, _ := store.WindowStats(ctx, epID, now.Add(-24*time.Hour))
	got := map[string]int64{}
	for _, b := range stats {
		got[b.Scope] = b.Requests
	}
	if got[ScopePublic] != 2 || got[ScopePartner] != 1 {
		t.Fatalf("cache ttl stats = %v", got)
	}
}
