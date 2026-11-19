package temporaryblock

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type fakeValkey struct {
	hash     map[string]string
	failEval bool
}

func newFake() *fakeValkey { return &fakeValkey{hash: map[string]string{}} }

func (f *fakeValkey) Eval(_ context.Context, script string, _ []string, args []string) ([]interface{}, error) {
	if f.failEval {
		return nil, errors.New("valkey down")
	}
	if script != pruneLua {
		return nil, errors.New("unexpected script")
	}
	// pruneLua 语义镜像：仅当当前值与快照一致时删除
	n := int64(0)
	for i := 0; i+1 < len(args); i += 2 {
		if v, ok := f.hash[args[i]]; ok && v == args[i+1] {
			delete(f.hash, args[i])
			n++
		}
	}
	return []interface{}{n}, nil
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
	all, _, bad, err := s.All(ctx)
	if err != nil || bad != 0 {
		t.Fatal(err)
	}
	got, ok := all[FieldKey("203.0.113.5", "app1")]
	if !ok || got.ID != "b1" || !got.ExpiresAt.Equal(exp) {
		t.Fatalf("round trip: %+v ok=%v", got, ok)
	}
	// 损坏条目：计数不吞错
	fk.hash["broken"] = "{not json"
	_, _, bad, _ = s.All(ctx)
	if bad != 1 {
		t.Fatalf("bad entries counted: %d", bad)
	}
	// 删除
	if err := s.Remove(ctx, "203.0.113.5", "app1"); err != nil {
		t.Fatal(err)
	}
	all, _, _, _ = s.All(ctx)
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

func TestBlockedManualPriorityAcrossScopesAndAutoReappearance(t *testing.T) {
	now := time.Now()
	c := NewCache(nil, 0)
	c.now = func() time.Time { return now }
	ip := netip.MustParseAddr("203.0.113.60")

	// 应用自动封禁不得遮蔽全局人工封禁。
	if err := c.PutLocal(context.Background(), Block{ID: "auto-app", ClientIP: ip.String(), AppID: "app1", Auto: true, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := c.PutLocal(context.Background(), Block{ID: "manual-global", ClientIP: ip.String(), AppID: "", Auto: false, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if got, ok := c.Blocked(ip, "app1"); !ok || got.ID != "manual-global" {
		t.Fatalf("global manual block must win over app auto block: %+v ok=%v", got, ok)
	}

	// 自动封禁并发重现后，人工封禁仍保持优先级。
	if err := c.PutLocal(context.Background(), Block{ID: "auto-app-renewed", ClientIP: ip.String(), AppID: "app1", Auto: true, ExpiresAt: now.Add(2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if got, ok := c.Blocked(ip, "app1"); !ok || got.ID != "manual-global" {
		t.Fatalf("renewed app auto block must not hide manual global block: %+v ok=%v", got, ok)
	}

	// 应用人工封禁同样优先于全局自动封禁，并保留应用作用域优先级。
	if err := c.PutLocal(context.Background(), Block{ID: "auto-global", ClientIP: ip.String(), AppID: "", Auto: true, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := c.PutLocal(context.Background(), Block{ID: "manual-app", ClientIP: ip.String(), AppID: "app1", Auto: false, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if got, ok := c.Blocked(ip, "app1"); !ok || got.ID != "manual-app" {
		t.Fatalf("app manual block must win over global auto block: %+v ok=%v", got, ok)
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

// 纯内存模式（store 为 nil）：PutLocal 惰性清扫过期项，map 不随轮换源 IP 无界增长。
func TestPutLocalEvictsExpired(t *testing.T) {
	ctx := context.Background()
	c := NewCache(nil, 0)
	now := time.Now()
	c.now = func() time.Time { return now }
	if err := c.PutLocal(ctx, Block{ID: "old", ClientIP: "2001:db8::1", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute) // old 过期
	if err := c.PutLocal(ctx, Block{ID: "new", ClientIP: "2001:db8::2", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.items) != 1 {
		t.Fatalf("expired entries must be swept on PutLocal: %d", len(c.items))
	}
	if _, ok := c.items[FieldKey("2001:db8::1", "")]; ok {
		t.Fatal("expired entry should be deleted, not just skipped")
	}
}

// Valkey 模式：Refresh 对过期 field 条件 HDel（哈希不单调膨胀），存活与 localOnly 条目不受影响。
func TestRefreshPrunesExpiredRemote(t *testing.T) {
	ctx := context.Background()
	fk := newFake()
	s := NewStore(fk, "")
	now := time.Now()
	expiredKey := FieldKey("203.0.113.20", "")
	freshKey := FieldKey("203.0.113.21", "")
	d, _ := json.Marshal(Block{ID: "old", ClientIP: "203.0.113.20", ExpiresAt: now.Add(-time.Minute)})
	fk.hash[expiredKey] = string(d)
	d, _ = json.Marshal(Block{ID: "fresh", ClientIP: "203.0.113.21", ExpiresAt: now.Add(time.Hour)})
	fk.hash[freshKey] = string(d)

	c := NewCache(s, 0)
	c.now = func() time.Time { return now }
	// localOnly 条目（Valkey 写失败遗留）不应被过期清理波及
	c.localOnly[FieldKey("203.0.113.22", "")] = Block{ID: "local", ClientIP: "203.0.113.22", ExpiresAt: now.Add(time.Hour)}

	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := fk.hash[expiredKey]; ok {
		t.Fatal("expired field must be HDel'd from valkey")
	}
	if _, ok := fk.hash[freshKey]; !ok {
		t.Fatal("fresh field must survive prune")
	}
	if _, ok := c.Blocked(netip.MustParseAddr("203.0.113.22"), ""); !ok {
		t.Fatal("localOnly entry must survive refresh")
	}
	// 清理失败如实上报（不静默吞错），本地视图仍已更新
	fk.hash[expiredKey] = string(mustJSON(t, Block{ID: "old2", ClientIP: "203.0.113.20", ExpiresAt: now.Add(-time.Minute)}))
	fk.failEval = true
	if err := c.Refresh(ctx); err == nil || c.LastError() == nil {
		t.Fatal("prune failure must surface via err/LastError")
	}
	if _, ok := c.Blocked(netip.MustParseAddr("203.0.113.20"), ""); ok {
		t.Fatal("expired entry must not block even when prune fails")
	}
	fk.failEval = false
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := fk.hash[expiredKey]; ok {
		t.Fatal("next refresh should retry prune")
	}
}

// 读后重封竞态：快照值已变化时 PruneIfUnchanged 不得误删新封禁。
func TestPruneIfUnchangedSkipsRewritten(t *testing.T) {
	ctx := context.Background()
	fk := newFake()
	s := NewStore(fk, "")
	key := FieldKey("198.51.100.30", "")
	old := string(mustJSON(t, Block{ID: "old", ClientIP: "198.51.100.30", ExpiresAt: time.Now().Add(-time.Minute)}))
	fk.hash[key] = old
	// 快照后管理平台重封同 field（值已变化）
	fk.hash[key] = string(mustJSON(t, Block{ID: "renewed", ClientIP: "198.51.100.30", ExpiresAt: time.Now().Add(time.Hour)}))
	if err := s.PruneIfUnchanged(ctx, map[string]string{key: old}); err != nil {
		t.Fatal(err)
	}
	var b Block
	if err := json.Unmarshal([]byte(fk.hash[key]), &b); err != nil || b.ID != "renewed" {
		t.Fatalf("rewritten field must not be pruned: %q %v", fk.hash[key], err)
	}
	// 值未变化时正常删除
	if err := s.PruneIfUnchanged(ctx, map[string]string{key: fk.hash[key]}); err != nil {
		t.Fatal(err)
	}
	if _, ok := fk.hash[key]; ok {
		t.Fatal("unchanged field should be pruned")
	}
}

func mustJSON(t *testing.T, b Block) []byte {
	t.Helper()
	d, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

type failPutValkey struct {
	*fakeValkey
}

func (f *failPutValkey) HSet(_ context.Context, _, _, _ string) error {
	return errors.New("valkey write failed")
}

// M-G4 回归：items 与 localOnly 严格有界，自动封禁洪泛不得挤出人工封禁，
// 且短时间突发 PutLocal 不逐次做全表扫描。
func TestMG4BoundedCacheProtectsManualBlocksAndCapsLocalOnly(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	fk := &failPutValkey{fakeValkey: newFake()}
	c := NewCache(NewStore(fk, ""), 0)
	c.now = func() time.Time { return now }
	c.maxItems = 5
	c.maxLocalOnly = 5
	c.sweepInterval = 30 * time.Second

	// 写入 2 条人工封禁
	_ = c.PutLocal(ctx, Block{ID: "m1", ClientIP: "198.51.100.1", Auto: false, ExpiresAt: now.Add(time.Hour)})
	_ = c.PutLocal(ctx, Block{ID: "m2", ClientIP: "198.51.100.2", Auto: false, ExpiresAt: now.Add(time.Hour)})

	// 洪泛写入 50 条自动封禁（Valkey 写失败同时压测 localOnly 上限）
	for i := 10; i < 60; i++ {
		_ = c.PutLocal(ctx, Block{
			ID:        "a",
			ClientIP:  netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}).String(),
			Auto:      true,
			ExpiresAt: now.Add(time.Duration(i) * time.Minute),
		})
	}

	c.mu.RLock()
	itemsLen := len(c.items)
	localLen := len(c.localOnly)
	c.mu.RUnlock()
	if itemsLen > 5 || localLen > 5 {
		t.Fatalf("M-G4: cache maps exceeded cap 5: items=%d localOnly=%d", itemsLen, localLen)
	}
	// 两条人工封禁必须完好无损
	for _, ipStr := range []string{"198.51.100.1", "198.51.100.2"} {
		if b, ok := c.Blocked(netip.MustParseAddr(ipStr), ""); !ok || b.Auto {
			t.Fatalf("M-G4: manual block %s must not be evicted by auto flood: %+v ok=%v", ipStr, b, ok)
		}
	}
}
