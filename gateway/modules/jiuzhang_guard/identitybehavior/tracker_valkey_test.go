package identitybehavior

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// fakeIBValkey observeLua 感知的内存 Valkey 替身：按脚本语义模拟计数桶/HLL/集合键
// （不验证 Lua 语法本身——与 behaviorstore 测试同一纪律；失败注入验证 fail-open）。
type fakeIBValkey struct {
	mu     sync.Mutex
	hashes map[string]map[string]int64 // 计数桶哈希
	sets   map[string]map[string]struct{}
	ttls   map[string]int64 // 各键最后一次 PEXPIRE 毫秒参数
	keys   []string         // 观测到的全部键（有序去重由调用方判）
	evals  int
	fail   bool
	hang   bool // 模拟悬挂：Eval 挂起直至调用侧 ctx 取消
}

func newFakeIBValkey() *fakeIBValkey {
	return &fakeIBValkey{
		hashes: map[string]map[string]int64{},
		sets:   map[string]map[string]struct{}{},
		ttls:   map[string]int64{},
	}
}

func (f *fakeIBValkey) Eval(ctx context.Context, script string, keys []string, args []string) ([]interface{}, error) {
	f.mu.Lock()
	f.evals++
	if f.hang {
		f.mu.Unlock()
		<-ctx.Done() // 悬挂直至调用侧超时取消（不持锁）
		return nil, ctx.Err()
	}
	defer f.mu.Unlock()
	if f.fail {
		return nil, errors.New("valkey down")
	}
	if script != observeLua {
		return nil, errors.New("unexpected script")
	}
	return f.evalObserve(keys, args), nil
}

// evalObserve 镜像 observeLua 语义（键/参数布局见 valkey.go 注释；整数估值公式一致）。
func (f *fakeIBValkey) evalObserve(keys []string, args []string) []interface{} {
	status, _ := strconv.Atoi(args[0])
	sensitive := args[1] == "1"
	method := args[2]
	paramsig := args[3]
	uriMember := args[4]
	accountMember := args[5]
	objectMember := args[6]
	auxTTL, _ := strconv.ParseInt(args[20], 10, 64)
	knownTTL, _ := strconv.ParseInt(args[19], 10, 64)

	paramNew := int64(0)
	if paramsig != "" && f.pfadd(keys[18], paramsig) {
		paramNew = 1
	}
	f.ttls[keys[18]] = auxTTL

	f.sadd(keys[17], method)
	mcount := int64(len(f.sets[keys[17]]))
	f.ttls[keys[17]] = auxTTL

	knownNew := f.pfadd(keys[16], uriMember)
	f.ttls[keys[16]] = knownTTL

	fields := []string{"req", "s401", "s403", "s404", "s405", "s500", "authf", "pmut", "sens", "newuri"}
	out := make([]interface{}, 0, observeResultLen)
	for i := 0; i < 4; i++ {
		curC, prevC := keys[i*2], keys[i*2+1]
		curH, prevH := keys[8+i*2], keys[8+i*2+1]
		elapsed, _ := strconv.ParseInt(args[7+i], 10, 64)
		dur, _ := strconv.ParseInt(args[11+i], 10, 64)
		ttl, _ := strconv.ParseInt(args[15+i], 10, 64)

		f.hincr(curC, "req", 1)
		switch status {
		case 401:
			f.hincr(curC, "s401", 1)
			f.hincr(curC, "authf", 1)
		case 403:
			f.hincr(curC, "s403", 1)
		case 404:
			f.hincr(curC, "s404", 1)
		case 405:
			f.hincr(curC, "s405", 1)
		case 500:
			f.hincr(curC, "s500", 1)
		}
		if paramNew == 1 {
			f.hincr(curC, "pmut", 1)
		}
		if sensitive {
			f.hincr(curC, "sens", 1)
		}
		if knownNew {
			f.hincr(curC, "newuri", 1)
		}
		f.ttls[curC] = ttl

		f.pfadd(curH, uriMember)
		f.ttls[curH] = ttl
		accCur, accPrev := keys[19+i*2], keys[20+i*2]
		objCur, objPrev := keys[27+i*2], keys[28+i*2]
		if accountMember != "" {
			f.pfadd(accCur, accountMember)
		}
		f.ttls[accCur] = ttl
		if objectMember != "" {
			f.pfadd(objCur, objectMember)
		}
		f.ttls[objCur] = ttl

		remain := dur - elapsed
		if remain < 0 {
			remain = 0
		}
		for _, field := range fields {
			c := f.hashes[curC][field]
			p := f.hashes[prevC][field]
			out = append(out, c*1000+p*remain*1000/dur)
		}
		out = append(out, int64(len(f.union(curH, prevH))))
		out = append(out, int64(len(f.union(accCur, accPrev))))
		out = append(out, int64(len(f.union(objCur, objPrev))))
	}
	out = append(out, mcount, paramNew)
	// 镜像 observeLua 末尾 1m 完成桶回放块（keys[1]=1m 上一计数桶，keys[9]=1m 上一 HLL 桶）
	for _, field := range fields {
		out = append(out, f.hashes[keys[1]][field])
	}
	out = append(out, int64(len(f.sets[keys[9]])))
	out = append(out, int64(len(f.sets[keys[20]])))
	out = append(out, int64(len(f.sets[keys[28]])))
	return out
}

func (f *fakeIBValkey) hincr(key, field string, n int64) {
	h, ok := f.hashes[key]
	if !ok {
		h = map[string]int64{}
		f.hashes[key] = h
	}
	h[field] += n
}

func (f *fakeIBValkey) sadd(key, member string) {
	s, ok := f.sets[key]
	if !ok {
		s = map[string]struct{}{}
		f.sets[key] = s
	}
	s[member] = struct{}{}
}

// pfadd 返回是否新增（HLL PFADD 幂等语义：同元素重复添加返回 0）。
func (f *fakeIBValkey) pfadd(key, member string) bool {
	s, ok := f.sets[key]
	if !ok {
		s = map[string]struct{}{}
		f.sets[key] = s
	}
	if _, exists := s[member]; exists {
		return false
	}
	s[member] = struct{}{}
	return true
}

func (f *fakeIBValkey) union(a, b string) map[string]struct{} {
	out := map[string]struct{}{}
	for m := range f.sets[a] {
		out[m] = struct{}{}
	}
	for m := range f.sets[b] {
		out[m] = struct{}{}
	}
	return out
}

func (f *fakeIBValkey) HSet(context.Context, string, string, string) error { return nil }
func (f *fakeIBValkey) HGetAll(context.Context, string) (map[string]string, error) {
	return nil, nil
}
func (f *fakeIBValkey) HDel(context.Context, string, ...string) error { return nil }
func (f *fakeIBValkey) Ping(context.Context) error                    { return nil }
func (f *fakeIBValkey) Close() error                                  { return nil }

// newValkeyTestStore 装配 fake 客户端 + 独立时钟（主存与内存回退同一时钟源）。
func newValkeyTestStore(f *fakeIBValkey, clk *memTestClock) (*ValkeyStore, *observer.ObservedLogs) {
	core, logs := observer.New(zap.WarnLevel)
	mem := NewMemoryStore(0, zap.New(core))
	mem.now = clk.Now
	s := NewValkeyStore(f, mem, zap.New(core))
	s.now = clk.Now
	return s, logs
}

func TestValkeyStoreBasicCounts(t *testing.T) {
	f := newFakeIBValkey()
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 10, 0, time.UTC)}
	s, _ := newValkeyTestStore(f, clk)
	for i := 0; i < 3; i++ {
		snap, err := s.Observe(baseInput("id-1"))
		if err != nil {
			t.Fatal(err)
		}
		if i == 2 {
			for w := Window1m; w < NumWindows; w++ {
				if got := snap.Windows[w].RequestCount; got != 3 {
					t.Fatalf("window %s request_count = %v, want 3", w.Name(), got)
				}
			}
		}
	}
	// 键前缀与哈希纪律
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.evals != 3 {
		t.Fatalf("single round-trip per observe: evals=%d", f.evals)
	}
	for k := range f.hashes {
		if !strings.HasPrefix(k, "jiuzhang:guard:ibh:c:") {
			t.Fatalf("counter key prefix: %q", k)
		}
		if strings.Contains(k, "id-1") || strings.Contains(k, "/index") {
			t.Fatalf("key material must be hashed: %q", k)
		}
	}
}

func TestValkeyStoreKeyTTLs(t *testing.T) {
	f := newFakeIBValkey()
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 10, 0, time.UTC)}
	s, _ := newValkeyTestStore(f, clk)
	in := baseInput("id-1")
	in.ParamSignature = "id=n" // 非空签名才会创建 ps 键（空签名不参与 HLL/变异）
	s.Observe(in)
	f.mu.Lock()
	defer f.mu.Unlock()
	var knownKey, methodKey, psKey string
	for k := range f.sets {
		switch {
		case strings.Contains(k, ":k:"):
			knownKey = k
		case strings.Contains(k, ":m:"):
			methodKey = k
		case strings.Contains(k, ":ps:"):
			psKey = k
		}
	}
	if knownKey == "" || methodKey == "" || psKey == "" {
		t.Fatalf("expected k/m/ps keys: %v", mapKeys(f.sets))
	}
	if f.ttls[knownKey] != knownTTLMs {
		t.Fatalf("known ttl = %d, want %d (48h)", f.ttls[knownKey], knownTTLMs)
	}
	if f.ttls[methodKey] != auxTTLMs || f.ttls[psKey] != auxTTLMs {
		t.Fatalf("aux ttl = %d/%d, want %d (30m)", f.ttls[methodKey], f.ttls[psKey], auxTTLMs)
	}
	// 桶键 TTL = 2×窗口
	wantBucketTTL := map[string]int64{
		"1m": 120000, "5m": 600000, "30m": 3600000, "24h": 172800000,
	}
	for k, ttl := range f.ttls {
		for name, want := range wantBucketTTL {
			if strings.Contains(k, ":c:"+name+":") || strings.Contains(k, ":u:"+name+":") {
				if ttl != want {
					t.Fatalf("bucket %s ttl = %d, want %d", k, ttl, want)
				}
			}
		}
	}
	// 桶键名含窗口起点（滚动换新键）：1m 当前桶键存在且后缀为该分钟起点
	want1mSuffix := ":" + strconv.FormatInt(clk.now.Truncate(time.Minute).Unix(), 10)
	found1m := false
	for k := range f.hashes {
		if strings.Contains(k, ":c:1m:") && strings.HasSuffix(k, want1mSuffix) {
			found1m = true
		}
	}
	if !found1m {
		t.Fatalf("1m current bucket key must embed bucket start %q", want1mSuffix)
	}
}

func TestValkeyStoreMethodParamAndKnown(t *testing.T) {
	f := newFakeIBValkey()
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 10, 0, time.UTC)}
	s, _ := newValkeyTestStore(f, clk)
	in := baseInput("id-1")
	in.ParamSignature = "id=n"
	snap, _ := s.Observe(in)
	if !snap.ParamSigNew || snap.DistinctMethods != 1 {
		t.Fatalf("first observe: %+v", snap)
	}
	in.Method = "POST"
	snap, _ = s.Observe(in)
	if snap.ParamSigNew || snap.DistinctMethods != 2 {
		t.Fatalf("repeat sig / new method: %+v", snap)
	}
	if got := snap.Windows[Window5m].ParameterMutationCount; got != 1 {
		t.Fatalf("mutation count = %v", got)
	}
	if got := snap.Windows[Window5m].NewURICount; got != 1 {
		t.Fatalf("known uri must recount once only: %v", got)
	}
}

// 双桶轮转：跨桶后估值与内存实现同公式（fake 按 Lua 整数公式返回，Go 解析一致）。
func TestValkeyStoreBucketRotationEstimate(t *testing.T) {
	f := newFakeIBValkey()
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)}
	s, _ := newValkeyTestStore(f, clk)
	for i := 0; i < 10; i++ {
		s.Observe(baseInput("id-1"))
	}
	clk.Advance(61 * time.Second)
	snap, _ := s.Observe(baseInput("id-1"))
	want := 1 + 10*(1-1.0/60.0)
	if got := snap.Windows[Window1m].RequestCount; got < want-0.02 || got > want+0.02 {
		t.Fatalf("rotation estimate = %v, want ≈%v", got, want)
	}
	// 上一桶 HLL 参与 unique 并集估计
	if got := snap.Windows[Window1m].UniqueURICount; got != 1 {
		t.Fatalf("unique across buckets: %d", got)
	}
}

// fail-open：Valkey 故障回退内存（请求不失败、计数继续），Warn 节流；恢复后回主路。
func TestValkeyStoreFailOpen(t *testing.T) {
	f := newFakeIBValkey()
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 10, 0, time.UTC)}
	s, logs := newValkeyTestStore(f, clk)
	f.fail = true
	for i := 0; i < 3; i++ {
		snap, err := s.Observe(baseInput("id-1"))
		if err != nil {
			t.Fatalf("fail-open must not error: %v", err)
		}
		if i == 2 && snap.Windows[Window1m].RequestCount != 3 {
			t.Fatalf("memory fallback must keep counting: %v", snap.Windows[Window1m].RequestCount)
		}
	}
	// Warn 记录且节流（3 次故障至多 1 条 Warn）
	warns := logs.FilterMessageSnippet("fail-open to memory")
	if warns.Len() == 0 {
		t.Fatal("fail-open warn expected")
	}
	if warns.Len() > 1 {
		t.Fatalf("warn must be throttled: %d", warns.Len())
	}
	// 恢复：主路重新生效（fake 侧 req 计数从 1 开始——故障期计数留在内存侧，不回灌）
	f.fail = false
	snap, err := s.Observe(baseInput("id-1"))
	if err != nil {
		t.Fatal(err)
	}
	if f.evals != 4 || snap.Windows[Window1m].RequestCount != 1 {
		t.Fatalf("recovery must use valkey path: evals=%d count=%v", f.evals, snap.Windows[Window1m].RequestCount)
	}
}

// DegradationMetrics 暴露低基数故障计数：普通错误与超时分开统计，恢复后的成功请求不再增长。
func TestValkeyStoreDegradationMetrics(t *testing.T) {
	f := newFakeIBValkey()
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 10, 0, time.UTC)}
	s, _ := newValkeyTestStore(f, clk)

	if got := s.DegradationMetrics(); got != (ValkeyDegradationMetrics{}) {
		t.Fatalf("initial degradation metrics = %+v, want zero", got)
	}
	f.fail = true
	for i := 0; i < 2; i++ {
		if _, err := s.Observe(baseInput("id-1")); err != nil {
			t.Fatal(err)
		}
	}
	got := s.DegradationMetrics()
	if got.FallbackTotal != 2 || got.ErrorTotal != 2 || got.TimeoutTotal != 0 {
		t.Fatalf("ordinary error metrics = %+v, want fallback=2 error=2 timeout=0", got)
	}

	// 成功请求不应把历史降级计数清零或误增。
	f.fail = false
	if _, err := s.Observe(baseInput("id-1")); err != nil {
		t.Fatal(err)
	}
	if got = s.DegradationMetrics(); got.FallbackTotal != 2 || got.ErrorTotal != 2 || got.TimeoutTotal != 0 {
		t.Fatalf("metrics after recovery = %+v, want unchanged", got)
	}

	f.hang = true
	if _, err := s.Observe(baseInput("id-1")); err != nil {
		t.Fatal(err)
	}
	got = s.DegradationMetrics()
	if got.FallbackTotal != 3 || got.ErrorTotal != 2 || got.TimeoutTotal != 1 {
		t.Fatalf("timeout metrics = %+v, want fallback=3 error=2 timeout=1", got)
	}
}

// Valkey 悬挂：Eval 在 opTimeout 内取消并 fail-open（请求 goroutine 阻塞有界）。
func TestValkeyStoreHangTimesOut(t *testing.T) {
	f := newFakeIBValkey()
	f.hang = true
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 10, 0, time.UTC)}
	s, _ := newValkeyTestStore(f, clk)
	start := time.Now()
	snap, err := s.Observe(baseInput("id-1"))
	if err != nil {
		t.Fatalf("fail-open must not error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("hang must fail-open within op timeout budget: %v", elapsed)
	}
	if snap.Windows[Window1m].RequestCount != 1 {
		t.Fatalf("memory fallback after hang: %v", snap.Windows[Window1m].RequestCount)
	}
}

func mapKeys(m map[string]map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// 完成桶回放（Valkey 路径）：CompletedWindow = 上一 1m 桶原始整数计数（未经 ×1000 缩放估值）。
func TestValkeyStoreCompletedWindow(t *testing.T) {
	f := newFakeIBValkey()
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 10, 0, time.UTC)}
	s, _ := newValkeyTestStore(f, clk)
	// 首桶：上一桶无数据 → 全 0
	snap, _ := s.Observe(baseInput("id-1"))
	if snap.CompletedWindow.RequestCount != 0 {
		t.Fatalf("first bucket completed window must be zero: %+v", snap.CompletedWindow)
	}
	// 同桶再突发 9 个（含 3 个 404）→ 桶内累计 10
	for i := 0; i < 9; i++ {
		in := baseInput("id-1")
		if i < 3 {
			in.Status = 404
		}
		s.Observe(in)
	}
	clk.Advance(51 * time.Second) // 进入下一 1m 桶（10:01:01）
	snap, err := s.Observe(baseInput("id-1"))
	if err != nil {
		t.Fatal(err)
	}
	cw := snap.CompletedWindow
	if cw.RequestCount != 10 || cw.Status404Count != 3 || cw.UniqueURICount != 1 {
		t.Fatalf("completed window raw counts: %+v", cw)
	}
	if want := clk.now.Truncate(time.Minute).Add(-time.Minute); !cw.WindowStart.Equal(want) {
		t.Fatalf("completed window start: %v, want %v", cw.WindowStart, want)
	}
	// 当前窗滑窗估值不受影响（含 prev 加权 ≈10.83，非原始 10）
	if got := snap.Windows[Window1m].RequestCount; got <= 10 {
		t.Fatalf("current sliding estimate must still weight prev bucket: %v", got)
	}
}
