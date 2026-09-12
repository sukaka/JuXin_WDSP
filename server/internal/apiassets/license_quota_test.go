// license_quota_test.go 授权端点配额哨兵单元测试（MemStore 驱动与 SQL Store
// 相同的配额语义）：新端点首插超配额 → ErrLicenseQuotaExceeded 且不落库；
// 既有端点命中不受影响；quota=0 / 无 provider 不限制。
package apiassets

import (
	"context"
	"errors"
	"testing"
)

func TestMemStoreLicenseQuotaExceeded(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore().SetEndpointQuotaProvider(func(context.Context) int64 { return 2 })

	// 配额内两个端点正常落库
	if _, err := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/a/{id}", Confidence: 0.7, IsAPI: true}); err != nil {
		t.Fatalf("配额内首插应成功: %v", err)
	}
	if _, err := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/b/{id}", Confidence: 0.7, IsAPI: true}); err != nil {
		t.Fatalf("配额内首插应成功: %v", err)
	}
	// 第三个新端点：哨兵错误且不落库
	if _, err := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/c/{id}", Confidence: 0.7, IsAPI: true}); !errors.Is(err, ErrLicenseQuotaExceeded) {
		t.Fatalf("超配额新端点应返回 ErrLicenseQuotaExceeded，got %v", err)
	}
	if _, total, err := store.List(ctx, ListFilter{Page: 1, PageSize: 20}); err != nil || total != 2 {
		t.Fatalf("被拒端点不得落库: total=%d err=%v", total, err)
	}
	// 既有端点命中不受配额影响（hit_count 照常累加）
	e, err := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/a/{id}", Confidence: 0.9, IsAPI: true})
	if err != nil {
		t.Fatalf("既有端点命中不应受配额影响: %v", err)
	}
	if e.HitCount != 2 {
		t.Fatalf("命中计数应累加为 2，got %d", e.HitCount)
	}
	// 配额提高后新端点恢复落库
	store.SetEndpointQuotaProvider(func(context.Context) int64 { return 10 })
	if _, err := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/c/{id}", Confidence: 0.7, IsAPI: true}); err != nil {
		t.Fatalf("配额提高后应恢复落库: %v", err)
	}
}

func TestMemStoreLicenseQuotaZeroAndNilUnlimited(t *testing.T) {
	ctx := context.Background()
	// quota=0：不限制
	zero := NewMemStore().SetEndpointQuotaProvider(func(context.Context) int64 { return 0 })
	for i, p := range []string{"/a/{id}", "/b/{id}", "/c/{id}"} {
		if _, err := zero.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: p, Confidence: 0.7, IsAPI: true}); err != nil {
			t.Fatalf("quota=0 第 %d 个端点不应被拒: %v", i+1, err)
		}
	}
	// 无 provider：不限制（既有行为）
	noProvider := NewMemStore()
	if _, err := noProvider.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/a/{id}", Confidence: 0.7, IsAPI: true}); err != nil {
		t.Fatalf("无 provider 不应强制配额: %v", err)
	}
}
