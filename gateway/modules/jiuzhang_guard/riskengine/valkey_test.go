package riskengine

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// fakeRiskValkey addLua/stateLua 感知的内存 Valkey 替身：按脚本语义模拟 ZSET
// （不验证 Lua 语法本身——与 identitybehavior/behaviorstore 测试同一纪律；失败注入验证 fail-open）。
type fakeRiskValkey struct {
	mu    sync.Mutex
	zsets map[string]map[string]float64 // key -> member -> score
	ttls  map[string]int64
	evals int
	fail  bool
	hang  bool
}

func newFakeRiskValkey() *fakeRiskValkey {
	return &fakeRiskValkey{zsets: map[string]map[string]float64{}, ttls: map[string]int64{}}
}

func (f *fakeRiskValkey) Eval(ctx context.Context, script string, keys []string, args []string) ([]interface{}, error) {
	f.mu.Lock()
	f.evals++
	if f.hang {
		f.mu.Unlock()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	defer f.mu.Unlock()
	if f.fail {
		return nil, errors.New("valkey down")
	}
	switch script {
	case addLua:
		return f.evalAdd(keys, args), nil
	case stateLua:
		return f.evalState(keys, args), nil
	}
	return nil, errors.New("unexpected script")
}

func (f *fakeRiskValkey) evalAdd(keys, args []string) []interface{} {
	key := keys[0]
	now, _ := strconv.ParseInt(args[0], 10, 64)
	window, _ := strconv.ParseInt(args[1], 10, 64)
	ttl, _ := strconv.ParseInt(args[2], 10, 64)
	capN, _ := strconv.Atoi(args[3])
	zs := f.zsets[key]
	if zs == nil {
		zs = map[string]float64{}
		f.zsets[key] = zs
	}
	cutoff := float64(now - window)
	for m, sc := range zs {
		if sc <= cutoff {
			delete(zs, m)
		}
	}
	n := 0
	for i := 4; i+1 < len(args); i += 2 {
		sc, _ := strconv.ParseFloat(args[i], 64)
		zs[args[i+1]] = sc
		n++
	}
	if len(zs) > capN {
		members := make([]string, 0, len(zs))
		for m := range zs {
			members = append(members, m)
		}
		sort.Slice(members, func(a, b int) bool { return zs[members[a]] < zs[members[b]] })
		for _, m := range members[:len(zs)-capN] {
			delete(zs, m)
		}
	}
	f.ttls[key] = ttl
	return []interface{}{int64(n)}
}

func (f *fakeRiskValkey) evalState(keys, args []string) []interface{} {
	key := keys[0]
	now, _ := strconv.ParseInt(args[0], 10, 64)
	window, _ := strconv.ParseInt(args[1], 10, 64)
	zs := f.zsets[key]
	cutoff := float64(now - window)
	out := []interface{}{}
	if zs == nil {
		return out
	}
	type kv struct {
		m  string
		sc float64
	}
	var kept []kv
	for m, sc := range zs {
		if sc <= cutoff {
			delete(zs, m)
			continue
		}
		kept = append(kept, kv{m, sc})
	}
	sort.Slice(kept, func(a, b int) bool { return kept[a].sc < kept[b].sc })
	for _, e := range kept {
		out = append(out, e.m)
	}
	return out
}

func (f *fakeRiskValkey) HSet(context.Context, string, string, string) error { return nil }
func (f *fakeRiskValkey) HGetAll(context.Context, string) (map[string]string, error) {
	return nil, nil
}
func (f *fakeRiskValkey) HDel(context.Context, string, ...string) error { return nil }
func (f *fakeRiskValkey) Ping(context.Context) error                    { return nil }
func (f *fakeRiskValkey) Close() error                                  { return nil }

// Valkey 入账/读取：ZSET 语义（求和、明细、TTL 刷新、键前缀与哈希）。
func TestValkeyStoreAddAndState(t *testing.T) {
	fk := newFakeRiskValkey()
	s := NewValkeyStore(fk, time.Hour, nil, zap.NewNop())
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	if err := s.Add("id1",
		entryAt("SENSITIVE_PATH_PROBE", 15, now.Add(-time.Second)),
		entryAt("WAF", 50, now)); err != nil {
		t.Fatal(err)
	}
	score, entries, err := s.State("id1")
	if err != nil {
		t.Fatal(err)
	}
	if score != 65 || len(entries) != 2 {
		t.Fatalf("score=%d entries=%d", score, len(entries))
	}
	if entries[0].Type != "SENSITIVE_PATH_PROBE" || entries[1].Type != "WAF" || entries[1].Reason != "test" {
		t.Fatalf("member round-trip: %+v", entries)
	}
	// 键纪律：前缀 + 哈希（无原始 identity 明文）
	if len(fk.zsets) != 1 {
		t.Fatalf("keys: %v", fk.zsets)
	}
	for k := range fk.zsets {
		if len(k) <= len(DefaultKeyPrefix)+1 || k[:len(DefaultKeyPrefix)] != DefaultKeyPrefix {
			t.Fatalf("key prefix: %s", k)
		}
		if fk.ttls[k] != (time.Hour + ttlBuffer).Milliseconds() {
			t.Fatalf("ttl: %d", fk.ttls[k])
		}
	}
	// 同毫秒同内容信号不互相覆盖（seq 唯一）
	if err := s.Add("id1", entryAt("WAF", 50, now), entryAt("WAF", 50, now)); err != nil {
		t.Fatal(err)
	}
	if score, _, _ := s.State("id1"); score != 100 { // 65+50+50=165 截断 100
		t.Fatalf("duplicate members must both count: %d", score)
	}
}

// Valkey 滑窗过期与明细上限（Lua 语义在 fake 中镜像验证）。
func TestValkeyStoreWindowAndCap(t *testing.T) {
	fk := newFakeRiskValkey()
	s := NewValkeyStore(fk, time.Hour, nil, zap.NewNop())
	base := time.Now().UTC()
	s.now = func() time.Time { return base }
	_ = s.Add("id1", entryAt("A", 50, base.Add(-2*time.Hour)), entryAt("B", 30, base))
	score, entries, _ := s.State("id1")
	if score != 30 || len(entries) != 1 || entries[0].Type != "B" {
		t.Fatalf("expired must not count: %d %+v", score, entries)
	}
	// 明细上限：MaxEntriesPerIdentity+10 条后裁剪
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	batch := make([]SignalEntry, 0, MaxEntriesPerIdentity+10)
	for i := 0; i < MaxEntriesPerIdentity+10; i++ {
		batch = append(batch, entryAt("T", 1, now.Add(time.Duration(i)*time.Millisecond)))
	}
	_ = s.Add("id2", batch...)
	_, entries, _ = s.State("id2")
	if len(entries) != MaxEntriesPerIdentity {
		t.Fatalf("cap: %d", len(entries))
	}
}

// fail-open：Valkey 故障回退内存（信号与读取均不中断），节流 Warn。
func TestValkeyStoreFailOpen(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	fk := newFakeRiskValkey()
	fk.fail = true
	s := NewValkeyStore(fk, time.Hour, nil, zap.New(core))
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	if err := s.Add("id1", entryAt("WAF", 50, now)); err != nil {
		t.Fatalf("add must fail-open to memory: %v", err)
	}
	score, entries, err := s.State("id1")
	if err != nil || score != 50 || len(entries) != 1 {
		t.Fatalf("state must fail-open to memory: %d %v %v", score, entries, err)
	}
	if logs.Len() == 0 {
		t.Fatal("fail-open must warn (不静默吞错)")
	}
	// Warn 节流：连续故障不洪泛
	for i := 0; i < 5; i++ {
		_ = s.Add("id1", entryAt("WAF", 50, now))
	}
	if logs.Len() > 2 {
		t.Fatalf("warn must be throttled: %d", logs.Len())
	}
	// 悬挂：Eval 阻塞至 opTimeout 内 fail-open
	fk.fail = false
	fk.hang = true
	start := time.Now()
	_ = s.Add("id1", entryAt("WAF", 50, now))
	if elapsed := time.Since(start); elapsed > opTimeout+200*time.Millisecond {
		t.Fatalf("hang must fail-open within opTimeout: %v", elapsed)
	}
}

// 故障窗口内存回退的信号在 Valkey 恢复后被 State 合并（不整体遗忘、不重复计数、时间升序）。
func TestValkeyStoreStateMergesMemoryFallback(t *testing.T) {
	fk := newFakeRiskValkey()
	now := time.Now().UTC()
	mem := NewMemoryStore(time.Hour, 0, zap.NewNop())
	mem.now = func() time.Time { return now }
	s := NewValkeyStore(fk, time.Hour, mem, zap.NewNop())
	s.now = func() time.Time { return now }

	// 故障窗口：两条信号只落内存
	fk.fail = true
	if err := s.Add("id1", entryAt("SENSITIVE_PATH_PROBE", 15, now.Add(-time.Second))); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("id1", entryAt("WAF", 50, now)); err != nil {
		t.Fatal(err)
	}
	// 恢复：新信号落 Valkey
	fk.fail = false
	if err := s.Add("id1", entryAt("AUTH_FAIL", 10, now.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	score, entries, err := s.State("id1")
	if err != nil {
		t.Fatal(err)
	}
	if score != 75 || len(entries) != 3 {
		t.Fatalf("memory fallback signals must merge after recovery: score=%d entries=%d", score, len(entries))
	}
	// 时间升序契约：内存信号（-1s, 0s）在前，Valkey 信号（+1s）在后
	want := []string{"SENSITIVE_PATH_PROBE", "WAF", "AUTH_FAIL"}
	for i, e := range entries {
		if e.Type != want[i] {
			t.Fatalf("merged entries must stay time-ascending: %+v", entries)
		}
	}
	// 再次 State 不重复计数（幂等）
	if score, _, _ := s.State("id1"); score != 75 {
		t.Fatalf("merge must be idempotent: %d", score)
	}
	// 窗口淘汰后内存信号不再合并
	now = now.Add(2 * time.Hour)
	if score, entries, _ := s.State("id1"); score != 0 || len(entries) != 0 {
		t.Fatalf("expired fallback signals must not count: %d %+v", score, entries)
	}
}

// 同一身份仅在内存或仅在 Valkey 有信号时，合并路径行为与单侧一致。
func TestValkeyStoreStateMergeSingleSide(t *testing.T) {
	fk := newFakeRiskValkey()
	now := time.Now().UTC()
	mem := NewMemoryStore(time.Hour, 0, zap.NewNop())
	mem.now = func() time.Time { return now }
	s := NewValkeyStore(fk, time.Hour, mem, zap.NewNop())
	s.now = func() time.Time { return now }

	// 纯 Valkey 侧（无回退历史）：结果与合并前一致
	if err := s.Add("idv", entryAt("WAF", 50, now)); err != nil {
		t.Fatal(err)
	}
	if score, entries, _ := s.State("idv"); score != 50 || len(entries) != 1 {
		t.Fatalf("valkey-only: %d %+v", score, entries)
	}
	// 纯内存侧（故障恢复后无新 Valkey 信号）
	fk.fail = true
	if err := s.Add("idm", entryAt("WAF", 40, now)); err != nil {
		t.Fatal(err)
	}
	fk.fail = false
	if score, entries, _ := s.State("idm"); score != 40 || len(entries) != 1 {
		t.Fatalf("memory-only after recovery: %d %+v", score, entries)
	}
}
