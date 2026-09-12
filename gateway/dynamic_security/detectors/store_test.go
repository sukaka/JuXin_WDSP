package detectors

import (
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// 计数存储可插拔（store.go）测试：注入路由、内存适配器、并发释放闭包绑定。
// 既有内存路径行为由 window/behavior/ratelimit/resource/envanomaly 既有测试覆盖，此处不重复。

// ---------- 测试替身（记录调用，返回预设值） ----------

type fakeWindowStore struct {
	calls []string
	count int
	hist  []int
}

func (f *fakeWindowStore) AddAndCount(key string) (int, []int) {
	f.calls = append(f.calls, key)
	return f.count, f.hist
}

type fakeObjectCursorStore struct {
	calls []string
	ret   bool
}

func (f *fakeObjectCursorStore) Consecutive(key string, id int64) bool {
	f.calls = append(f.calls, key)
	return f.ret
}

type fakeIPSpreadStore struct {
	keys    []string
	members []string
	ret     int
}

func (f *fakeIPSpreadStore) AddDistinct(key, member string) int {
	f.keys = append(f.keys, key)
	f.members = append(f.members, member)
	return f.ret
}

type fakeConcurrencyStore struct {
	acquires []string
	releases []string
	currents []string
	n        int
}

func (f *fakeConcurrencyStore) Acquire(key string) int {
	f.acquires = append(f.acquires, key)
	return f.n
}
func (f *fakeConcurrencyStore) Release(key string) { f.releases = append(f.releases, key) }
func (f *fakeConcurrencyStore) Current(key string) int {
	f.currents = append(f.currents, key)
	return f.n
}

func contextWithOverrides(o *StoreOverrides) *dsctx.RequestContext {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	ctx.BindDetectorStoreOverrides(o)
	return ctx
}

// 注入 BehaviorWindow 后 CheckBehavior 走注入实现；未注入的写限速仍走默认内存。
func TestStoreOverrides_BehaviorWindowRouted(t *testing.T) {
	fake := &fakeWindowStore{count: 1}
	CheckBehavior(contextWithOverrides(&StoreOverrides{BehaviorWindow: fake}), "ip:198.51.100.1", "GET /v1/x")
	if len(fake.calls) != 1 || fake.calls[0] != "ip:198.51.100.1|GET /v1/x" {
		t.Fatalf("behavior window override not used: %v", fake.calls)
	}
	// 同请求再查默认内存追踪器：不得有该键（未走内存路径）
	if _, ok := defaultBehaviorTracker.entries.get("ip:198.51.100.1|GET /v1/x"); ok {
		t.Fatal("default memory tracker must not be touched when override set")
	}
}

// 注入 APIWriteWindow 后写限速走注入实现；返回计数超阈值产生 API_WRITE_RATE match。
func TestStoreOverrides_APIWriteWindowRouted(t *testing.T) {
	fake := &fakeWindowStore{count: 61} // 超默认 60
	ctx := contextWithOverrides(&StoreOverrides{APIWriteWindow: fake})
	CheckAPIWriteRate(ctx, "ip:198.51.100.2", "POST /v1/y", 0)
	if len(fake.calls) != 1 {
		t.Fatalf("apiwrite window override not used: %v", fake.calls)
	}
	m := findMatch(ctx, "ratelimit.api_write_rate")
	if m == nil || m.Evidence["window_count"] != "61" {
		t.Fatalf("override count must drive match, got %+v", ctx.CopyMatches())
	}
}

// 注入 ObjectCursor 后连续数字 ID 判定走注入实现（返回 true → 升 BLOCK 类）。
func TestStoreOverrides_ObjectCursorRouted(t *testing.T) {
	fake := &fakeObjectCursorStore{ret: true}
	ctx := contextWithOverrides(&StoreOverrides{ObjectCursor: fake})
	p := &parser.Parsed{
		Method:         "PUT",
		RawPath:        "/v1/users/101",
		NormalizedPath: "/v1/users/{id}",
		Headers:        map[string]string{},
	}
	CheckResourceAccess(ctx, p, "ip:198.51.100.3", "", nil)
	if len(fake.calls) != 1 || fake.calls[0] != "ip:198.51.100.3|PUT /v1/users/{id}|path:2" {
		t.Fatalf("object cursor override not used: %v", fake.calls)
	}
	m := findMatch(ctx, "resource.unauthenticated_object_access")
	if m == nil || m.Category != "BLOCK" {
		t.Fatalf("override consecutive=true must escalate, got %+v", ctx.CopyMatches())
	}
}

// 注入 IPSpread 后跨 IP 跳变计数走注入实现（返回 distinct ≥ 阈值 → OBSERVE match）。
func TestStoreOverrides_IPSpreadRouted(t *testing.T) {
	fake := &fakeIPSpreadStore{ret: 5}
	const salt = "test-salt"
	credKey := CredentialKey(credSpreadRequest("spread-override-token", ""), salt)
	ctx := authTestCtx()
	ctx.BindDetectorStoreOverrides(&StoreOverrides{IPSpread: fake})
	CheckCredentialIPSpread(ctx, credSpreadRequest("spread-override-token", "203.0.113.99:1000"), credKey, salt, 0)
	if len(fake.keys) != 1 || fake.keys[0] != credKey {
		t.Fatalf("ip spread override not used: %v", fake.keys)
	}
	if len(fake.members) != 1 || fake.members[0] != Fingerprint(salt, "203.0.113.99") {
		t.Fatalf("member must be salted ip fingerprint: %v", fake.members)
	}
	if m := findMatch(ctx, "auth.credential_ip_spread"); m == nil || m.Evidence["distinct_ips"] != "5" {
		t.Fatalf("override distinct must drive match, got %+v", ctx.CopyMatches())
	}
}

// 注入 Concurrency 后 Acquire/Current 走注入实现；释放闭包绑定同一注入实例且幂等。
func TestStoreOverrides_ConcurrencyRoutedAndReleaseBound(t *testing.T) {
	fake := &fakeConcurrencyStore{n: 9}
	stores := &StoreOverrides{Concurrency: fake}
	// 包级默认追踪器可能被先运行的其他用例占用，换新后再断言本用例零触碰
	defaultCredentialConcurrency = &credentialConcurrencyTracker{entries: newLRU(envAnomalyMaxKeys)}
	n, release := AcquireCredentialInFlightWithStores("auth:override-concur", stores)
	if n != 9 || len(fake.acquires) != 1 || fake.acquires[0] != "auth:override-concur" {
		t.Fatalf("concurrency acquire override not used: n=%d %v", n, fake.acquires)
	}
	ctx := authTestCtx()
	ctx.BindDetectorStoreOverrides(stores)
	CheckCredentialConcurrency(ctx, "auth:override-concur", 0) // 默认阈值 8，注入返回 9 → 报
	if len(fake.currents) != 1 {
		t.Fatalf("concurrency current override not used: %v", fake.currents)
	}
	if m := findMatch(ctx, "auth.credential_concurrency"); m == nil || m.Evidence["inflight"] != "9" {
		t.Fatalf("override inflight must drive match, got %+v", ctx.CopyMatches())
	}
	release()
	release() // 幂等：注入实例只收到一次 Release
	if len(fake.releases) != 1 || fake.releases[0] != "auth:override-concur" {
		t.Fatalf("release must be idempotent and bound to override: %v", fake.releases)
	}
	// 默认内存并发追踪器未被触碰
	if defaultCredentialConcurrency.entries.ll.Len() != 0 {
		t.Fatal("default memory concurrency tracker must not be touched when override set")
	}
}

// 部分注入：仅 BehaviorWindow 注入时，其余检测面维持默认内存路径。
func TestStoreOverrides_PartialOverrideKeepsMemoryDefaults(t *testing.T) {
	resetBehaviorTrackerForTest(&fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	resetAPIWriteTrackerForTest()
	ctx := contextWithOverrides(&StoreOverrides{BehaviorWindow: &fakeWindowStore{count: 1}})
	CheckAPIWriteRate(ctx, "ip:198.51.100.4", "POST /v1/z", 0)
	if _, ok := defaultAPIWriteTracker.entries.get("ip:198.51.100.4|POST /v1/z"); !ok {
		t.Fatal("apiwrite must stay on default memory tracker when not overridden")
	}
}

// 未绑定覆盖时使用默认内存路径。
func TestStoreOverrides_UnboundUsesMemory(t *testing.T) {
	resetBehaviorTrackerForTest(&fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	CheckBehavior(dsctx.New("t", dsctx.DefaultParseLimits()), "ip:198.51.100.5", "GET /v1/w")
	if _, ok := defaultBehaviorTracker.entries.get("ip:198.51.100.5|GET /v1/w"); !ok {
		t.Fatal("default memory tracker must be used without request-scoped overrides")
	}
}

// 内存适配器与默认追踪器同一实现：滑窗滚动/历史归档语义一致。
func TestMemoryStores_AdaptersMatchDefaultSemantics(t *testing.T) {
	win := NewMemoryWindowStore(0, nil)
	if c, h := win.AddAndCount("k"); c != 1 || len(h) != 0 {
		t.Fatalf("first hit: count=%d hist=%v", c, h)
	}
	if c, _ := win.AddAndCount("k"); c != 2 {
		t.Fatalf("same window second hit: count=%d", c)
	}
	cur := NewMemoryObjectCursorStore(0)
	if cur.Consecutive("k", 100) {
		t.Fatal("first id must not be consecutive")
	}
	if !cur.Consecutive("k", 101) {
		t.Fatal("id 101 after 100 must be consecutive")
	}
	spread := NewMemoryIPSpreadStore(0, nil)
	if n := spread.AddDistinct("k", "fp1"); n != 1 {
		t.Fatalf("distinct first: %d", n)
	}
	if n := spread.AddDistinct("k", "fp1"); n != 1 {
		t.Fatalf("same member must not grow distinct: %d", n)
	}
	if n := spread.AddDistinct("k", "fp2"); n != 2 {
		t.Fatalf("distinct second member: %d", n)
	}
	conc := NewMemoryConcurrencyStore(0)
	if n := conc.Acquire("k"); n != 1 {
		t.Fatalf("acquire: %d", n)
	}
	conc.Release("k")
	if n := conc.Current("k"); n != 0 {
		t.Fatalf("after release: %d", n)
	}
	conc.Release("k") // 未记账键/零计数释放为空操作，不得击穿为负
	if n := conc.Current("k"); n != 0 {
		t.Fatalf("release floor: %d", n)
	}
}
