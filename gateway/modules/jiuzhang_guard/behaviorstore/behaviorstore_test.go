package behaviorstore

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// fakeValkey 脚本感知的内存 Valkey 替身：按 Lua 脚本常量分发，模拟各脚本的键语义
// （不验证 Lua 语法本身——无 miniredis 依赖，按任务纪律用接口 fake；失败注入验证 Fail-open）。
type fakeValkey struct {
	mu     sync.Mutex
	strs   map[string]string           // GET/SET/INCR 键
	hashes map[string]map[string]int64 // 窗口哈希键
	sets   map[string]map[string]struct{}
	ttls   map[string]int64 // 各键最后一次 PEXPIRE 毫秒参数
	fail   bool
	hang   bool // 模拟 Valkey 悬挂（TCP 活但不响应）：Eval 挂起直至调用侧 ctx 取消
	evals  int
	failed int
}

func newFakeValkey() *fakeValkey {
	return &fakeValkey{
		strs:   map[string]string{},
		hashes: map[string]map[string]int64{},
		sets:   map[string]map[string]struct{}{},
		ttls:   map[string]int64{},
	}
}

func (f *fakeValkey) Eval(ctx context.Context, script string, keys []string, args []string) ([]interface{}, error) {
	f.mu.Lock()
	f.evals++
	if f.hang {
		f.mu.Unlock()
		<-ctx.Done() // 悬挂直至调用侧超时取消（不持锁，免阻塞其他操作）
		return nil, ctx.Err()
	}
	defer f.mu.Unlock()
	if f.fail {
		f.failed++
		return nil, errors.New("valkey down")
	}
	switch script {
	case windowAddLua:
		return f.evalWindow(keys[0], args), nil
	case cursorSetLua:
		return f.evalCursor(keys[0], args), nil
	case spreadAddLua:
		return f.evalSpread(keys[0], args), nil
	case concurAcquireLua:
		f.ttls[keys[0]], _ = strconv.ParseInt(args[0], 10, 64)
		n := f.strInt(keys[0]) + 1
		f.strs[keys[0]] = strconv.FormatInt(n, 10)
		return []interface{}{n}, nil
	case concurReleaseLua:
		f.ttls[keys[0]], _ = strconv.ParseInt(args[0], 10, 64)
		v, ok := f.strs[keys[0]]
		if !ok {
			return []interface{}{int64(0)}, nil
		}
		n, _ := strconv.ParseInt(v, 10, 64)
		n--
		if n < 0 {
			n = 0
		}
		f.strs[keys[0]] = strconv.FormatInt(n, 10)
		return []interface{}{n}, nil
	case concurCurrentLua:
		return []interface{}{f.strInt(keys[0])}, nil
	}
	return nil, fmt.Errorf("unexpected script")
}

func (f *fakeValkey) strInt(key string) int64 {
	v, ok := f.strs[key]
	if !ok {
		return 0
	}
	n, _ := strconv.ParseInt(v, 10, 64)
	return n
}

// evalWindow 模拟 windowAddLua：HINCRBY 当前窗 → 已完成窗升序封顶 maxHist（淘汰更老 field）。
func (f *fakeValkey) evalWindow(key string, args []string) []interface{} {
	h, ok := f.hashes[key]
	if !ok {
		h = map[string]int64{}
		f.hashes[key] = h
	}
	curW, _ := strconv.ParseInt(args[0], 10, 64)
	maxHist, _ := strconv.Atoi(args[1])
	f.ttls[key], _ = strconv.ParseInt(args[2], 10, 64)
	h[args[0]]++
	var completed []int64
	for fstr := range h {
		if w, _ := strconv.ParseInt(fstr, 10, 64); w < curW {
			completed = append(completed, w)
		}
	}
	sortInts(completed)
	for len(completed) > maxHist {
		delete(h, strconv.FormatInt(completed[0], 10))
		completed = completed[1:]
	}
	out := []interface{}{h[args[0]]}
	for _, w := range completed {
		out = append(out, h[strconv.FormatInt(w, 10)])
	}
	return out
}

func (f *fakeValkey) evalCursor(key string, args []string) []interface{} {
	prev, ok := f.strs[key]
	f.strs[key] = args[0]
	f.ttls[key], _ = strconv.ParseInt(args[1], 10, 64)
	if ok {
		p, _ := strconv.ParseInt(prev, 10, 64)
		id, _ := strconv.ParseInt(args[0], 10, 64)
		if p+1 == id {
			return []interface{}{int64(1)}
		}
	}
	return []interface{}{int64(0)}
}

func (f *fakeValkey) evalSpread(key string, args []string) []interface{} {
	s, ok := f.sets[key]
	if !ok {
		s = map[string]struct{}{}
		f.sets[key] = s
	}
	capN, _ := strconv.Atoi(args[1])
	f.ttls[key], _ = strconv.ParseInt(args[2], 10, 64)
	if len(s) < capN {
		s[args[0]] = struct{}{}
	}
	return []interface{}{int64(len(s))}
}

func sortInts(a []int64) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func (f *fakeValkey) HSet(_ context.Context, _, _, _ string) error { return nil }
func (f *fakeValkey) HGetAll(_ context.Context, _ string) (map[string]string, error) {
	return nil, nil
}
func (f *fakeValkey) HDel(_ context.Context, _ string, _ ...string) error { return nil }
func (f *fakeValkey) Ping(_ context.Context) error                        { return nil }
func (f *fakeValkey) Close() error                                        { return nil }

// testClock 可推进时钟。
type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time          { return c.now }
func (c *testClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestStore(f *fakeValkey, clk *testClock, ttl time.Duration) (*Store, *observer.ObservedLogs) {
	core, logs := observer.New(zap.WarnLevel)
	s := New(f, "", ttl, zap.New(core))
	s.now = clk.Now
	return s, logs
}

var (
	baseTime   = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	windowKey  = regexp.MustCompile(`^jiuzhang:guard:api:(behavior|apiwrite):[0-9a-f]{32}$`)
	spreadKey  = regexp.MustCompile(`^jiuzhang:guard:api:ipspread:[0-9a-f]{32}:\d+$`)
	cursorKey  = regexp.MustCompile(`^jiuzhang:guard:api:objcur:[0-9a-f]{32}$`)
	concurKey  = regexp.MustCompile(`^jiuzhang:guard:api:concur:[0-9a-f]{32}$`)
	rawKeyLeak = "tenant-secret|GET /v1/orders"
)

// 滑窗计数/历史语义与内存实现一致；键为 sha256 截断哈希不落原始材料；TTL 按内置下限。
func TestWindowAdd_CountsHistoryAndKeyDiscipline(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	s, _ := newTestStore(f, clk, 0)
	add := s.Overrides().BehaviorWindow.AddAndCount

	if c, h := add(rawKeyLeak); c != 1 || len(h) != 0 {
		t.Fatalf("first hit: count=%d hist=%v", c, h)
	}
	if c, h := add(rawKeyLeak); c != 2 || len(h) != 0 {
		t.Fatalf("same window: count=%d hist=%v", c, h)
	}
	clk.Advance(time.Minute)
	if c, h := add(rawKeyLeak); c != 1 || len(h) != 1 || h[0] != 2 {
		t.Fatalf("window roll: count=%d hist=%v", c, h)
	}
	clk.Advance(time.Minute)
	if c, h := add(rawKeyLeak); c != 1 || len(h) != 2 || h[0] != 2 || h[1] != 1 {
		t.Fatalf("history ascending: count=%d hist=%v", c, h)
	}
	// 键纪律：前缀 + sha256 截断哈希，不含原始键材料；TTL = 12min 下限
	if len(f.hashes) != 1 {
		t.Fatalf("want 1 hash key, got %d", len(f.hashes))
	}
	for k := range f.hashes {
		if !windowKey.MatchString(k) {
			t.Fatalf("bad key shape: %q", k)
		}
		if f.ttls[k] != windowTTLFloor.Milliseconds() {
			t.Fatalf("ttl=%d want %d", f.ttls[k], windowTTLFloor.Milliseconds())
		}
	}
	for k := range f.hashes {
		if k == rawKeyLeak || len(k) < 40 {
			t.Fatalf("raw key material leaked: %q", k)
		}
	}
	// 历史封顶：再造 9 个完成窗（共 12 个），样本最多保留 10
	for i := 0; i < 9; i++ {
		clk.Advance(time.Minute)
		add(rawKeyLeak)
	}
	clk.Advance(time.Minute)
	_, h := add(rawKeyLeak)
	if len(h) != detectors.MaxHistoryWindows {
		t.Fatalf("history cap: len=%d want %d", len(h), detectors.MaxHistoryWindows)
	}
	// 最老样本已被淘汰：保留的是最近 10 个完成窗（升序）
	if h[0] != 1 || h[len(h)-1] != 1 {
		t.Fatalf("history content: %v", h)
	}
}

// 行为滑窗与写限速滑窗命名空间隔离：同键分别计数互不污染。
func TestWindowAdd_NamespacesIsolated(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	s, _ := newTestStore(f, clk, 0)
	o := s.Overrides()
	const key = "auth:abc|POST /v1/x"
	o.BehaviorWindow.AddAndCount(key)
	o.BehaviorWindow.AddAndCount(key)
	if c, _ := o.APIWriteWindow.AddAndCount(key); c != 1 {
		t.Fatalf("apiwrite namespace must count independently, got %d", c)
	}
	if len(f.hashes) != 2 {
		t.Fatalf("want 2 isolated keys, got %d", len(f.hashes))
	}
}

// Fail-open：Valkey 故障时滑窗计数由内存回退连续进行，告警每分钟节流；恢复后回到 Valkey。
func TestWindowAdd_FailOpenToMemory(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	s, logs := newTestStore(f, clk, 0)
	add := s.Overrides().BehaviorWindow.AddAndCount

	f.fail = true
	if c, h := add("k"); c != 1 || len(h) != 0 {
		t.Fatalf("fail-open first hit: count=%d hist=%v", c, h)
	}
	if c, _ := add("k"); c != 2 {
		t.Fatalf("fail-open memory continuity: count=%d", c)
	}
	if logs.Len() != 1 {
		t.Fatalf("warn must be throttled to 1 per minute, got %d", logs.Len())
	}
	clk.Advance(time.Minute)
	if c, h := add("k"); c != 1 || len(h) != 1 || h[0] != 2 {
		t.Fatalf("fail-open window roll in memory: count=%d hist=%v", c, h)
	}
	if logs.Len() != 2 {
		t.Fatalf("warn throttle should allow one more after a minute, got %d", logs.Len())
	}
	// 恢复：重新走 Valkey（该键 Valkey 侧无故障期计数，语义为各自独立降级，已注释说明）
	f.fail = false
	if c, _ := add("k"); c != 1 {
		t.Fatalf("valkey resumes after recovery: count=%d", c)
	}
	if f.failed != 3 {
		t.Fatalf("3 valkey attempts should have failed, got %d", f.failed)
	}
}

// 对象游标：连续数字 ID 判定 + 键纪律 + Fail-open 内存连续性。
func TestConsecutive_CursorAndFailOpen(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	s, _ := newTestStore(f, clk, 0)
	const key = "auth:abc|PUT /v1/users/{id}|path:2"
	if s.Consecutive(key, 100) {
		t.Fatal("first id must not be consecutive")
	}
	if !s.Consecutive(key, 101) {
		t.Fatal("101 after 100 must be consecutive")
	}
	if s.Consecutive(key, 105) {
		t.Fatal("105 after 101 must not be consecutive")
	}
	for k := range f.strs {
		if !cursorKey.MatchString(k) {
			t.Fatalf("bad cursor key: %q", k)
		}
		if f.ttls[k] != cursorTTLFloor.Milliseconds() {
			t.Fatalf("cursor ttl=%d", f.ttls[k])
		}
	}
	// Fail-open：故障期游标在内存侧连续推进
	f2 := newFakeValkey()
	s2, logs := newTestStore(f2, clk, 0)
	f2.fail = true
	if s2.Consecutive("k2", 200) {
		t.Fatal("memory fallback first id must not be consecutive")
	}
	if !s2.Consecutive("k2", 201) {
		t.Fatal("memory fallback must keep cursor continuity")
	}
	if logs.Len() == 0 {
		t.Fatal("fail-open must warn")
	}
}

// 跨 IP 集合：窗口级键（键名含窗口起点），窗口滚动即重置；成员去重；TTL 2min 下限。
func TestAddDistinct_WindowScopedSet(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	s, _ := newTestStore(f, clk, 0)
	const cred = "auth:spread"
	if n := s.AddDistinct(cred, "fp1"); n != 1 {
		t.Fatalf("first member: %d", n)
	}
	if n := s.AddDistinct(cred, "fp1"); n != 1 {
		t.Fatalf("same member dedup: %d", n)
	}
	if n := s.AddDistinct(cred, "fp2"); n != 2 {
		t.Fatalf("second member: %d", n)
	}
	clk.Advance(time.Minute)
	if n := s.AddDistinct(cred, "fp1"); n != 1 {
		t.Fatalf("new window resets set: %d", n)
	}
	if len(f.sets) != 2 {
		t.Fatalf("want 2 window-scoped set keys, got %d", len(f.sets))
	}
	for k := range f.sets {
		if !spreadKey.MatchString(k) {
			t.Fatalf("bad spread key: %q", k)
		}
		if f.ttls[k] != spreadTTLFloor.Milliseconds() {
			t.Fatalf("spread ttl=%d", f.ttls[k])
		}
	}
}

// 并发计数：Acquire/Current/Release 全链路 + 下界 0 + 未记账键释放为空操作 + Fail-open。
func TestConcurrency_LifecycleAndFailOpen(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	s, _ := newTestStore(f, clk, 0)
	const key = "auth:concur"
	if n := s.Acquire(key); n != 1 {
		t.Fatalf("acquire 1: %d", n)
	}
	if n := s.Acquire(key); n != 2 {
		t.Fatalf("acquire 2: %d", n)
	}
	if n := s.Current(key); n != 2 {
		t.Fatalf("current: %d", n)
	}
	s.Release(key)
	if n := s.Current(key); n != 1 {
		t.Fatalf("after release: %d", n)
	}
	s.Release(key)
	if n := s.Current(key); n != 0 {
		t.Fatalf("after all releases: %d", n)
	}
	s.Release(key) // 零计数再释放：下界 0 不击穿
	if n := s.Current(key); n != 0 {
		t.Fatalf("release floor: %d", n)
	}
	for k := range f.strs {
		if !concurKey.MatchString(k) {
			t.Fatalf("bad concurrency key: %q", k)
		}
		if f.ttls[k] != concurTTLFloor.Milliseconds() {
			t.Fatalf("concurrency ttl=%d", f.ttls[k])
		}
	}
	// Fail-open：故障期计数落内存，恢复后释放绑定的闭包语义由 detectors 侧 once 保证
	f.fail = true
	if n := s.Acquire("k2"); n != 1 {
		t.Fatalf("fail-open acquire: %d", n)
	}
	if n := s.Current("k2"); n != 1 {
		t.Fatalf("fail-open current from memory: %d", n)
	}
	s.Release("k2")
	if n := s.Current("k2"); n != 0 {
		t.Fatalf("fail-open release: %d", n)
	}
}

// TTL 覆盖：配置值大于内置下限才生效，否则按下限（防误配短 TTL 截断历史样本）。
func TestTTLFloorOverride(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	small, _ := newTestStore(f, clk, time.Second)
	small.Overrides().BehaviorWindow.AddAndCount("k")
	for k := range f.hashes {
		if f.ttls[k] != windowTTLFloor.Milliseconds() {
			t.Fatalf("ttl below floor must not apply: %d", f.ttls[k])
		}
	}
	f2 := newFakeValkey()
	big, _ := newTestStore(f2, clk, time.Hour)
	big.Overrides().BehaviorWindow.AddAndCount("k")
	for k := range f2.hashes {
		if f2.ttls[k] != time.Hour.Milliseconds() {
			t.Fatalf("ttl override must apply: %d", f2.ttls[k])
		}
	}
}

// Overrides 导出完整性：全部字段非 nil（装配层一次注入）。
func TestOverrides_AllFieldsSet(t *testing.T) {
	s := New(newFakeValkey(), "", 0, nil)
	o := s.Overrides()
	if o.BehaviorWindow == nil || o.APIWriteWindow == nil || o.ObjectCursor == nil ||
		o.IPSpread == nil || o.Concurrency == nil {
		t.Fatalf("overrides incomplete: %+v", o)
	}
}

// 超时路径：Valkey 悬挂（TCP 活但不响应）时每次 Eval 受 defaultOpTimeout 约束，
// 超时后走 Fail-open 内存降级——请求 goroutine 阻塞时间有界（修复前无限期阻塞）。
func TestEvalTimeout_HangFailOpen(t *testing.T) {
	f := newFakeValkey()
	clk := &testClock{now: baseTime}
	s, logs := newTestStore(f, clk, 0)
	f.hang = true

	start := time.Now()
	if c, h := s.Overrides().BehaviorWindow.AddAndCount("k"); c != 1 || len(h) != 0 {
		t.Fatalf("timeout fail-open window add: count=%d hist=%v", c, h)
	}
	if s.Consecutive("k", 1) {
		t.Fatal("timeout fail-open cursor first id must not be consecutive")
	}
	if n := s.AddDistinct("k", "fp1"); n != 1 {
		t.Fatalf("timeout fail-open spread: %d", n)
	}
	if n := s.Acquire("k"); n != 1 {
		t.Fatalf("timeout fail-open acquire: %d", n)
	}
	if n := s.Current("k"); n != 1 {
		t.Fatalf("timeout fail-open current: %d", n)
	}
	s.Release("k")
	if n := s.Current("k"); n != 0 {
		t.Fatalf("timeout fail-open release: %d", n)
	}
	// 7 次 Eval（6 个调用点）各悬挂一个超时周期：下界证明确实走了悬挂→超时路径，
	// 上界证明阻塞有界
	const ops = 7
	d := time.Since(start)
	if d < ops*defaultOpTimeout {
		t.Fatalf("hang path must wait per-op timeout each time, took only %v", d)
	}
	if d > ops*defaultOpTimeout+3*time.Second {
		t.Fatalf("blocking must be bounded by per-op timeout, took %v", d)
	}
	if f.evals != ops {
		t.Fatalf("want %d eval attempts, got %d", ops, f.evals)
	}
	if logs.Len() == 0 {
		t.Fatal("timeout fail-open must warn")
	}
}
