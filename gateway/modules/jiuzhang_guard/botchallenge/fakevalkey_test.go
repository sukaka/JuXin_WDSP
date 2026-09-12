package botchallenge

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/ratelimit"
	"go.uber.org/zap"
)

// fakeBotValkey botchallenge 四个 Lua 脚本语义感知的内存 Valkey 替身
// （与 riskengine fakeRiskValkey 同一纪律：按脚本语义模拟，不验证 Lua 语法；
// fail/hang 注入验证 fail-closed 故障语义）。
type fakeBotValkey struct {
	mu     sync.Mutex
	hashes map[string]map[string]string // 挑战 HASH
	zsets  map[string]map[string]float64
	ttls   map[string]int64
	evals  int
	fail   bool
	hang   bool
}

func newFakeBotValkey() *fakeBotValkey {
	return &fakeBotValkey{
		hashes: map[string]map[string]string{},
		zsets:  map[string]map[string]float64{},
		ttls:   map[string]int64{},
	}
}

func (f *fakeBotValkey) Eval(ctx context.Context, script string, keys []string, args []string) ([]interface{}, error) {
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
	case issueLua:
		return f.evalIssue(keys, args), nil
	case readLua:
		return f.evalRead(keys, args), nil
	case consumeLua:
		return f.evalConsume(keys, args), nil
	case failLua:
		return f.evalFail(keys, args), nil
	}
	return nil, errors.New("unexpected script")
}

func (f *fakeBotValkey) evalIssue(keys, args []string) []interface{} {
	ifKey, cKey := keys[0], keys[1]
	nowMs, _ := strconv.ParseFloat(args[0], 64)
	capN, _ := strconv.Atoi(args[1])
	ttlMs, _ := strconv.ParseInt(args[2], 10, 64)
	expMs, _ := strconv.ParseFloat(args[3], 64)
	member := args[4]
	zs := f.zsets[ifKey]
	if zs == nil {
		zs = map[string]float64{}
		f.zsets[ifKey] = zs
	}
	for m, sc := range zs {
		if sc <= nowMs {
			delete(zs, m)
		}
	}
	if len(zs) >= capN {
		return []interface{}{int64(0), "CAP"}
	}
	if _, ok := f.hashes[cKey]; ok {
		return []interface{}{int64(0), "EXISTS"}
	}
	f.hashes[cKey] = map[string]string{
		"v": "1", "sd": args[5], "hh": args[6], "ep": args[7], "df": args[8],
		"nc": args[9], "exp": args[3], "att": "0",
	}
	f.ttls[cKey] = ttlMs
	zs[member] = expMs
	f.ttls[ifKey] = ttlMs + 60000
	return []interface{}{int64(1), "OK"}
}

func (f *fakeBotValkey) evalRead(keys, args []string) []interface{} {
	cKey, ifKey := keys[0], keys[1]
	member := args[0]
	nowMs, _ := strconv.ParseFloat(args[1], 64)
	out := []interface{}{}
	var flds []string
	if h, ok := f.hashes[cKey]; ok {
		for _, k := range []string{"v", "sd", "hh", "ep", "df", "nc", "exp", "att"} {
			flds = append(flds, k, h[k])
		}
	}
	out = append(out, int64(len(flds)))
	for _, s := range flds {
		out = append(out, s)
	}
	hint := "0"
	if sc, ok := f.zsets[ifKey][member]; ok {
		if sc <= nowMs {
			hint = "1"
		} else {
			hint = "2"
		}
	}
	out = append(out, hint)
	return out
}

// evalCompare 共用比对段（consume/fail 同口径）；返回 (f, reason, ok)。
func (f *fakeBotValkey) evalCompare(keys, args []string) (map[string]string, string) {
	h, ok := f.hashes[keys[0]]
	if !ok {
		return nil, "NOT_FOUND"
	}
	if h["sd"] != args[0] || h["hh"] != args[1] || h["ep"] != args[2] || h["df"] != args[3] || h["nc"] != args[4] {
		return nil, "MISMATCH"
	}
	expMs, _ := strconv.ParseFloat(h["exp"], 64)
	nowMs, _ := strconv.ParseFloat(args[7], 64)
	if expMs <= nowMs {
		// 与 consumeLua/failLua EXPIRED 分支一致：DEL HASH 但保留计量 member（归因 EXPIRED）
		delete(f.hashes, keys[0])
		return nil, "EXPIRED"
	}
	return h, ""
}

func (f *fakeBotValkey) evalConsume(keys, args []string) []interface{} {
	h, reason := f.evalCompare(keys, args)
	if reason != "" {
		return []interface{}{int64(0), reason}
	}
	att, _ := strconv.Atoi(h["att"])
	maxAtt, _ := strconv.Atoi(args[8])
	if att >= maxAtt {
		return []interface{}{int64(0), "EXHAUSTED"}
	}
	delete(f.hashes, keys[0])
	delete(f.zsets[keys[1]], args[6])
	return []interface{}{int64(1), "OK"}
}

func (f *fakeBotValkey) evalFail(keys, args []string) []interface{} {
	h, reason := f.evalCompare(keys, args)
	if reason != "" {
		return []interface{}{int64(0), reason, int64(0)}
	}
	att, _ := strconv.Atoi(h["att"])
	att++
	h["att"] = strconv.Itoa(att)
	maxAtt, _ := strconv.Atoi(args[8])
	if att >= maxAtt {
		delete(f.hashes, keys[0])
		delete(f.zsets[keys[1]], args[6])
		return []interface{}{int64(0), "EXHAUSTED", int64(att)}
	}
	return []interface{}{int64(2), "ATTEMPT", int64(att)}
}

func (f *fakeBotValkey) HSet(context.Context, string, string, string) error { return nil }
func (f *fakeBotValkey) HGetAll(context.Context, string) (map[string]string, error) {
	return nil, nil
}
func (f *fakeBotValkey) HDel(context.Context, string, ...string) error { return nil }
func (f *fakeBotValkey) Ping(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("valkey down")
	}
	return nil
}
func (f *fakeBotValkey) Close() error { return nil }

// keyDump 诊断：当前全部键（键纪律断言用）。
func (f *fakeBotValkey) keyDump() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for k := range f.hashes {
		out = append(out, k)
	}
	for k := range f.zsets {
		out = append(out, k)
	}
	return out
}

// fakeLimiter 限速器替身（按维度键前缀脚本化放行/拒绝/故障）。
type fakeLimiter struct {
	mu       sync.Mutex
	denyKeys map[string]bool // key 子串命中 → 拒绝
	failKeys map[string]bool // key 子串命中 → 故障
	calls    []string
}

func (l *fakeLimiter) Allow(_ context.Context, key string, _ ratelimit.Algorithm, _ int64, _ time.Duration, _ int64) (ratelimit.Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, key)
	for k := range l.failKeys {
		if strings.Contains(key, k) {
			return ratelimit.Result{}, errors.New("limiter down")
		}
	}
	for k := range l.denyKeys {
		if strings.Contains(key, k) {
			return ratelimit.Result{Allowed: false, RetryAfter: 30 * time.Second}, nil
		}
	}
	return ratelimit.Result{Allowed: true}, nil
}

// Peek 调试回显只读查询的替身实现（botchallenge 测试不消费，固定返回不存在）。
func (l *fakeLimiter) Peek(_ context.Context, _ string, _ ratelimit.Algorithm, _ int64, _ time.Duration, _ int64) (int64, bool, error) {
	return 0, false, nil
}

// denyAll 让所有携带指定维度子串的键拒绝（如 "iss-sess" / "vfy-ip"）。
func (l *fakeLimiter) deny(substr string) { l.denyKeys[substr] = true }

// captureSink 事件捕获出口（并发安全）。
type captureSink struct {
	mu     sync.Mutex
	events []events.Event
}

func (c *captureSink) Emit(e events.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return nil
}

func (c *captureSink) byType(t events.Type) []events.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []events.Event{}
	for _, e := range c.events {
		if e.EventType == t {
			out = append(out, e)
		}
	}
	return out
}

// testKeyring 固定测试密钥环（32 字节密钥材料；两个 key 供轮换）。
func testKeyring(t *testing.T, current string, previous ...string) *Keyring {
	t.Helper()
	mk := func(id string) Key {
		return Key{ID: id, Secret: []byte("test-secret-material-" + id + "-0123456789abcdef")}
	}
	prev := []Key{}
	for _, id := range previous {
		prev = append(prev, mk(id))
	}
	kr, err := NewKeyring(mk(current), prev...)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	return kr
}

// testServiceOpts 夹具选项。
type testServiceOpts struct {
	mode    string
	appID   string
	version int
	keyRef  string
	limits  *RateLimits
	capN    int
	keyring *Keyring
	node    string
}

// newTestService 构造测试服务（注入 fake Valkey + fake 限速器 + 捕获事件出口；
// 返回的 now 指针可调时间——Service 与 Store 共用同一时钟）。
func newTestService(t *testing.T, fk *fakeBotValkey, lim *fakeLimiter, sink *captureSink, opts testServiceOpts) (*Service, *time.Time) {
	t.Helper()
	if fk == nil {
		fk = newFakeBotValkey()
	}
	if lim == nil {
		lim = &fakeLimiter{denyKeys: map[string]bool{}, failKeys: map[string]bool{}}
	}
	if sink == nil {
		sink = &captureSink{}
	}
	if opts.mode == "" {
		opts.mode = ModeProtect
	}
	if opts.appID == "" {
		opts.appID = "app-1"
	}
	if opts.version == 0 {
		opts.version = 7
	}
	if opts.keyring == nil {
		opts.keyring = testKeyring(t, "bot-key-a")
	}
	store := NewStore(fk, "")
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		AppID:         opts.appID,
		AppCode:       opts.appID,
		Mode:          opts.mode,
		PolicyVersion: opts.version,
		NonceTTL:      90 * time.Second,
		ClearanceTTL:  900 * time.Second,
		Difficulty:    MinDifficulty, // 10bit——测试求解耗时毫秒级
		MaxAttempts:   3,
		KeyRef:        opts.keyRef,
		Keyring:       opts.keyring,
		Store:         store,
		Limiter:       lim,
		Sink:          sink,
		Node:          "gw-test",
		Logger:        zap.NewNop(),
		InFlightCap:   opts.capN,
	}
	if opts.limits != nil {
		cfg.Limits = *opts.limits
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	svc.now = func() time.Time { return now }
	store.now = func() time.Time { return now }
	return svc, &now
}
