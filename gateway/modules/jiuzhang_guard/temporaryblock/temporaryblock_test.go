package temporaryblock

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

type fakeValkey struct {
	hash map[string]string
}

func newFake() *fakeValkey { return &fakeValkey{hash: map[string]string{}} }

func (f *fakeValkey) Eval(_ context.Context, _ string, _ []string, _ []string) ([]interface{}, error) {
	return nil, nil
}
func (f *fakeValkey) HSet(_ context.Context, _, field, value string) error {
	f.hash[field] = value
	return nil
}
func (f *fakeValkey) HGetAll(_ context.Context, _ string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range f.hash {
		out[k] = v
	}
	return out, nil
}
func (f *fakeValkey) HDel(_ context.Context, _ string, fields ...string) error {
	for _, k := range fields {
		delete(f.hash, k)
	}
	return nil
}
func (f *fakeValkey) Ping(_ context.Context) error { return nil }
func (f *fakeValkey) Close() error                 { return nil }

func TestStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	fk := newFake()
	s := NewStore(fk, "")
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	b := Block{ID: "b1", ClientIP: "203.0.113.5", AppID: "app1", ExpiresAt: exp, Auto: true}
	if err := s.Put(ctx, b); err != nil {
		t.Fatal(err)
	}
	all, bad, err := s.All(ctx)
	if err != nil || bad != 0 {
		t.Fatal(err)
	}
	got, ok := all[FieldKey("203.0.113.5", "app1")]
	if !ok || got.ID != "b1" || !got.ExpiresAt.Equal(exp) {
		t.Fatalf("round trip: %+v ok=%v", got, ok)
	}
	// 损坏条目：计数不吞错
	fk.hash["broken"] = "{not json"
	_, bad, _ = s.All(ctx)
	if bad != 1 {
		t.Fatalf("bad entries counted: %d", bad)
	}
	// 删除
	if err := s.Remove(ctx, "203.0.113.5", "app1"); err != nil {
		t.Fatal(err)
	}
	all, _, _ = s.All(ctx)
	if _, ok := all[FieldKey("203.0.113.5", "app1")]; ok {
		t.Fatal("remove failed")
	}
}

func TestCacheBlocked(t *testing.T) {
	ctx := context.Background()
	fk := newFake()
	s := NewStore(fk, "")
	c := NewCache(s, 0)
	now := time.Now()
	c.now = func() time.Time { return now }

	// 应用级封禁
	b := Block{ID: "b1", ClientIP: "203.0.113.6", AppID: "app1", ExpiresAt: now.Add(time.Hour)}
	if err := c.PutLocal(ctx, b); err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("203.0.113.6")
	if _, ok := c.Blocked(ip, "app1"); !ok {
		t.Fatal("app block should hit")
	}
	if _, ok := c.Blocked(ip, "other"); ok {
		t.Fatal("app block should not hit other app")
	}
	// 全局封禁
	c.PutLocal(ctx, Block{ID: "b2", ClientIP: "203.0.113.7", AppID: "", ExpiresAt: now.Add(time.Hour)})
	ip2 := netip.MustParseAddr("203.0.113.7")
	if _, ok := c.Blocked(ip2, "anyapp"); !ok {
		t.Fatal("global block should hit any app")
	}
	// 过期自动失效
	c.PutLocal(ctx, Block{ID: "b3", ClientIP: "203.0.113.8", AppID: "", ExpiresAt: now.Add(time.Minute)})
	now = now.Add(2 * time.Minute)
	if _, ok := c.Blocked(netip.MustParseAddr("203.0.113.8"), ""); ok {
		t.Fatal("expired block should not hit")
	}
}

func TestCacheRefresh(t *testing.T) {
	ctx := context.Background()
	fk := newFake()
	s := NewStore(fk, "")
	// 预置 Valkey 数据（模拟管理平台写入）
	data, _ := json.Marshal(Block{ID: "ext", ClientIP: "198.51.100.9", AppID: "", ExpiresAt: time.Now().Add(time.Hour)})
	fk.hash[FieldKey("198.51.100.9", "")] = string(data)
	c := NewCache(s, 0)
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Blocked(netip.MustParseAddr("198.51.100.9"), "x"); !ok {
		t.Fatal("refresh should sync valkey blocks")
	}
	// 管理平台解封后刷新生效
	fk.HDel(ctx, "", FieldKey("198.51.100.9", ""))
	c.Refresh(ctx)
	if _, ok := c.Blocked(netip.MustParseAddr("198.51.100.9"), "x"); ok {
		t.Fatal("released block should clear after refresh")
	}
}
