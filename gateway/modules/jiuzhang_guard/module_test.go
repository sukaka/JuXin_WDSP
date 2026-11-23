package jiuzhang_guard

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/cidr"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/l7rules"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/ratelimit"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/temporaryblock"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/trustedproxy"
	"go.uber.org/zap"
)

// newTestGuard 构建内存后端的测试 Guard（绕过 caddy.Provision 的进程级引擎）。
func newTestGuard(t *testing.T, cfg Guard) *Guard {
	t.Helper()
	g := &cfg
	g.logger = zap.NewNop()
	g.resolver = clientip.NewResolver(cfg.MaxProxyChain)
	var err error
	proxies := nilProxies
	for _, p := range cfg.TrustedProxies {
		proxies = append(proxies, p)
	}
	g.proxies = mustProxySet(t, proxies)
	g.protected = mustMatcher(t, cfg.ProtectedAddresses)
	g.allowG, err = buildRuleSet(cfg.GlobalAllow)
	if err != nil {
		t.Fatal(err)
	}
	g.allowA, err = buildRuleSet(cfg.AppAllow)
	if err != nil {
		t.Fatal(err)
	}
	g.denyG, err = buildRuleSet(cfg.GlobalDeny)
	if err != nil {
		t.Fatal(err)
	}
	g.denyA, err = buildRuleSet(cfg.AppDeny)
	if err != nil {
		t.Fatal(err)
	}
	g.urlAllowG, err = buildURLWhitelistSet(cfg.GlobalURLAllow)
	if err != nil {
		t.Fatal(err)
	}
	g.urlAllowA, err = buildURLWhitelistSet(cfg.AppURLAllow)
	if err != nil {
		t.Fatal(err)
	}
	g.policies, err = compilePolicies(cfg.RateLimits)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.L7Rules != nil {
		eng, ruleErrs := l7rules.Compile(cfg.L7Rules)
		for _, re := range ruleErrs {
			t.Logf("l7rules rejected rule %s: %v", re.RuleID, re.Err)
		}
		g.l7 = eng
	}
	logPath := filepath.Join(t.TempDir(), "events.log")
	g.events, err = events.NewLogger(logPath, "test-node")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.events.Close() })
	mem := ratelimit.NewMemoryLimiter(10000)
	eng := &sharedEngine{
		initialized: true,
		memLimiter:  mem,
		limiter:     mem,
		blockCache:  temporaryblock.NewCache(nil, 0),
		failOpen:    true,
		lastErrEmit: map[string]time.Time{},
	}
	g.engine = eng
	g.failOpen = true
	eventsPaths.Store(g, logPath)
	return g
}

var nilProxies []proxyJSON

func mustProxySet(t *testing.T, in []proxyJSON) *trustedproxy.Set {
	t.Helper()
	proxies := make([]trustedproxy.Proxy, 0, len(in))
	for _, p := range in {
		pfx, err := cidr.ParseAddress(p.CIDR)
		if err != nil {
			t.Fatal(err)
		}
		proxies = append(proxies, trustedproxy.Proxy{
			Name: p.Name, Prefix: pfx,
			HeaderType: trustedproxy.HeaderType(p.HeaderType),
			Priority:   p.Priority,
		})
	}
	s, err := trustedproxy.NewSet(proxies)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustMatcher(t *testing.T, addrs []string) *cidr.Matcher {
	t.Helper()
	entries := make([]cidr.Entry, 0, len(addrs))
	for _, a := range addrs {
		pfx, err := cidr.ParseAddress(a)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, cidr.Entry{Prefix: pfx, Meta: a})
	}
	return cidr.NewMatcher(entries)
}

var errEngine = errors.New("rate limit engine down")

func reqCtx() context.Context { return context.Background() }

// 测试 Guard 事件文件路径登记（readEvents 用）。
var eventsPaths sync.Map // *Guard -> string

// nextHandler 记录是否到达下游。
type nextHandler struct{ called *bool }

func (h nextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	*h.called = true
	w.WriteHeader(200)
	return nil
}

func req(remoteAddr string, headers map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "http://waf-test.local/echo?a=1", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	r.Header.Set("X-Request-Id", "11111111-2222-3333-4444-555555555555")
	return r
}

func TestDenyBlocks(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1", AppCode: "shop",
		GlobalDeny: []ruleJSON{{ID: "d1", Address: "203.0.113.66", Priority: 1}},
	})
	called := false
	rec := httptest.NewRecorder()
	err := g.ServeHTTP(rec, req("203.0.113.66:1234", nil), nextHandler{&called})
	if err == nil || called {
		t.Fatalf("deny should block before upstream: err=%v called=%v", err, called)
	}
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != 403 {
		t.Fatalf("expected 403 HandlerError, got %v", err)
	}
	// 事件已记录
	evs := g.readEvents(t)
	if len(evs) != 1 || evs[0].EventType != events.IPDenyMatch || evs[0].AccessRuleID != "d1" {
		t.Fatalf("deny event: %+v", evs)
	}
	if evs[0].Proto != "HTTP/1.1" {
		t.Fatalf("deny event proto = %q, want HTTP/1.1", evs[0].Proto)
	}
}

func TestAllowOverridesDenyAndCC(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1", AppCode: "shop",
		GlobalAllow: []ruleJSON{{ID: "a1", Address: "10.0.0.0/8", Priority: 1}},
		GlobalDeny:  []ruleJSON{{ID: "d1", Address: "10.1.1.1", Priority: 1}},
		RateLimits: []policyJSON{{
			ID: "cc1", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "ALL", RequestsLimit: 1, WindowSeconds: 60, Action: "REJECT", Priority: 1,
		}},
	})
	// 白名单 IP 命中黑名单同层？白优先；且绕过 CC（limit=1 也放行多次）
	for i := 0; i < 3; i++ {
		called := false
		rec := httptest.NewRecorder()
		if err := g.ServeHTTP(rec, req("10.1.1.1:1", nil), nextHandler{&called}); err != nil || !called {
			t.Fatalf("allow should pass (deny+cc bypassed): err=%v", err)
		}
	}
}

func TestProtectedNeverBlocked(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID:              "app1",
		ProtectedAddresses: []string{"192.0.2.10"},
		GlobalDeny:         []ruleJSON{{ID: "d1", Address: "192.0.2.10", Priority: 1}},
	})
	called := false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, req("192.0.2.10:1", nil), nextHandler{&called}); err != nil || !called {
		t.Fatalf("protected address must never be blocked: %v", err)
	}
}

func TestForgedXFFIgnored(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID:      "app1",
		GlobalDeny: []ruleJSON{{ID: "d1", Address: "203.0.113.99", Priority: 1}},
	})
	// 连接源不可信，伪造 XFF 试图伪装成黑名单外 IP → 仍按连接源封禁
	called := false
	rec := httptest.NewRecorder()
	err := g.ServeHTTP(rec, req("203.0.113.99:1", map[string]string{"X-Forwarded-For": "8.8.8.8"}), nextHandler{&called})
	if err == nil || called {
		t.Fatal("forged XFF must not bypass deny")
	}
	// 伪造尝试事件
	found := false
	for _, e := range g.readEvents(t) {
		if e.EventType == events.TrustedProxyInvalid {
			found = true
		}
	}
	if !found {
		t.Fatal("TRUSTED_PROXY_INVALID event expected")
	}
}

func TestTrustedProxyRealIPDeny(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID:          "app1",
		TrustedProxies: []proxyJSON{{Name: "lb", CIDR: "10.0.0.1", HeaderType: "X_FORWARDED_FOR", Priority: 1}},
		GlobalDeny:     []ruleJSON{{ID: "d1", Address: "198.51.100.50", Priority: 1}},
	})
	// 经可信代理，真实 IP 在黑名单 → 拒绝
	called := false
	rec := httptest.NewRecorder()
	err := g.ServeHTTP(rec, req("10.0.0.1:1", map[string]string{"X-Forwarded-For": "198.51.100.50"}), nextHandler{&called})
	if err == nil || called {
		t.Fatal("real ip behind trusted proxy should be denied")
	}
	// 白名单真实 IP → 放行，且 r.RemoteAddr 被改写
	g2 := newTestGuard(t, Guard{
		AppID:          "app1",
		TrustedProxies: []proxyJSON{{Name: "lb", CIDR: "10.0.0.1", HeaderType: "X_FORWARDED_FOR", Priority: 1}},
	})
	r := req("10.0.0.1:1", map[string]string{"X-Forwarded-For": "198.51.100.51"})
	called = false
	if err := g2.ServeHTTP(httptest.NewRecorder(), r, nextHandler{&called}); err != nil || !called {
		t.Fatal("clean ip should pass")
	}
	if r.RemoteAddr != "198.51.100.51:0" || r.Header.Get("X-Real-Ip") != "198.51.100.51" {
		t.Fatalf("remote addr should be rewritten to real ip: %s", r.RemoteAddr)
	}
}

func TestTrustedProxySyncsCaddyClientIPVar(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID:          "app1",
		TrustedProxies: []proxyJSON{{Name: "lb", CIDR: "10.0.0.1", HeaderType: "X_FORWARDED_FOR", Priority: 1}},
	})
	r := req("10.0.0.1:1", map[string]string{"X-Forwarded-For": "198.51.100.52"})
	// 模拟 Caddy accept 时 PrepareRequest 写入的 vars 表（client_ip 固化为连接源 IP）
	vars := map[string]any{caddyhttp.ClientIPVarKey: "10.0.0.1"}
	*r = *r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, vars))
	called := false
	if err := g.ServeHTTP(httptest.NewRecorder(), r, nextHandler{&called}); err != nil || !called {
		t.Fatal("clean ip should pass")
	}
	// coraza-caddy 审计事务优先取该变量——必须与真实 IP 识别结果一致
	if got := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey); got != "198.51.100.52" {
		t.Fatalf("client_ip var should be synced to real ip, got %v", got)
	}
	// 内部头必须携带原始 TCP 对端地址（server 侧回填 connection_ip 用）
	if got := r.Header.Get("X-Jiuzhang-Connection-Addr"); got != "10.0.0.1:1" {
		t.Fatalf("connection addr header = %q, want original peer 10.0.0.1:1", got)
	}
}

func TestTempBlock(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1"})
	g.engine.blockCache.PutLocal(reqCtx(), temporaryblock.Block{
		ID: "tb1", ClientIP: "203.0.113.77", AppID: "app1",
		ExpiresAt: time.Now().Add(time.Hour), Auto: true,
	})
	called := false
	err := g.ServeHTTP(httptest.NewRecorder(), req("203.0.113.77:1", nil), nextHandler{&called})
	if err == nil || called {
		t.Fatal("temp blocked ip should be rejected")
	}
	// 其他应用不受影响（该封禁为 app1 应用级）——同一 Guard AppID=app1 才命中，验证全局逻辑在 temporaryblock 测试中已覆盖
}

func TestCCReject429(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1",
		RateLimits: []policyJSON{{
			ID: "cc1", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "ALL", RequestsLimit: 2, WindowSeconds: 60, BurstCapacity: 2,
			Action: "REJECT", Priority: 1,
		}},
	})
	ip := "203.0.113.88:1"
	for i := 0; i < 2; i++ {
		called := false
		if err := g.ServeHTTP(httptest.NewRecorder(), req(ip, nil), nextHandler{&called}); err != nil || !called {
			t.Fatalf("req %d should pass", i)
		}
	}
	// 第三个请求 429
	rec := httptest.NewRecorder()
	called := false
	if err := g.ServeHTTP(rec, req(ip, nil), nextHandler{&called}); err != nil || called {
		t.Fatalf("third request should be 429: %v", err)
	}
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" || rec.Header().Get("X-Jiuzhang-Request-ID") == "" {
		t.Fatalf("429 response headers: %v %v", rec.Code, rec.Header())
	}
	// 不泄露内部阈值/计数/算法/节点
	body := rec.Body.String()
	for _, leak := range []string{"token", "bucket", "cc1", "test-node", "60"} {
		if contains(body, leak) {
			t.Fatalf("429 body leaks internals: %q contains %q", body, leak)
		}
	}
	// 事件
	found := false
	for _, e := range g.readEvents(t) {
		if e.EventType == events.CCRequestRejected && e.PolicyID == "cc1" {
			found = true
		}
	}
	if !found {
		t.Fatal("CC_REQUEST_REJECTED event expected")
	}
}

func TestCCObserveNotBlocking(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1",
		RateLimits: []policyJSON{{
			ID: "cc-obs", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "ALL", RequestsLimit: 1, WindowSeconds: 60, Action: "OBSERVE", Priority: 1,
		}},
	})
	for i := 0; i < 5; i++ {
		called := false
		if err := g.ServeHTTP(httptest.NewRecorder(), req("203.0.113.90:1", nil), nextHandler{&called}); err != nil || !called {
			t.Fatalf("observe must not block: %v", err)
		}
	}
	count := 0
	for _, e := range g.readEvents(t) {
		if e.EventType == events.CCThresholdExceeded {
			count++
		}
	}
	if count != 4 {
		t.Fatalf("expected 4 threshold events, got %d", count)
	}
}

func TestCCTempBlockCreatesBlock(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1",
		RateLimits: []policyJSON{{
			ID: "cc-tb", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "ALL", RequestsLimit: 1, WindowSeconds: 60,
			Action: "TEMP_BLOCK", BlockDurationSeconds: 900, Priority: 1,
		}},
	})
	ip := "203.0.113.91:1"
	g.ServeHTTP(httptest.NewRecorder(), req(ip, nil), nextHandler{new(bool)})
	// 第二次触发超限 → 429 + 自动封禁
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, req(ip, nil), nextHandler{new(bool)}); err != nil || rec.Code != 429 {
		t.Fatalf("trigger should be 429: %v %d", err, rec.Code)
	}
	// 第三次：已封禁 → 403
	called := false
	err := g.ServeHTTP(httptest.NewRecorder(), req(ip, nil), nextHandler{&called})
	if err == nil || called {
		t.Fatal("blocked ip should be 403")
	}
	hasCreated := false
	for _, e := range g.readEvents(t) {
		if e.EventType == events.CCTempBlockCreated {
			hasCreated = true
		}
	}
	if !hasCreated {
		t.Fatal("CC_TEMP_BLOCK_CREATED event expected")
	}
}

func TestURIMatchTypes(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1",
		RateLimits: []policyJSON{{
			ID: "cc-prefix", Dimension: "CLIENT_IP_AND_URI", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "PREFIX", URIPattern: "/api/", RequestsLimit: 1, WindowSeconds: 60,
			Action: "REJECT", Priority: 1,
		}},
	})
	ip := "203.0.113.92:1"
	// /api/ 下第二个请求 429，其他路径不受影响
	mk := func(path string) *http.Request {
		r := req(ip, nil)
		r.URL.Path = path
		return r
	}
	g.ServeHTTP(httptest.NewRecorder(), mk("/api/login"), nextHandler{new(bool)})
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, mk("/api/order"), nextHandler{new(bool)}); err != nil || rec.Code != 429 {
		t.Fatalf("prefix uri should be limited: %v %d", err, rec.Code)
	}
	called := false
	if err := g.ServeHTTP(httptest.NewRecorder(), mk("/other"), nextHandler{&called}); err != nil || !called {
		t.Fatal("other uri should pass")
	}
}

func TestFailClosedOnEngineError(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1",
		RateLimits: []policyJSON{{
			ID: "cc1", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "ALL", RequestsLimit: 10, WindowSeconds: 60, Action: "REJECT", Priority: 1,
		}},
	})
	g.engine.limiter = &errLimiter{}
	g.failOpen = false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, req("203.0.113.93:1", nil), nextHandler{new(bool)}); err != nil || rec.Code != 429 {
		t.Fatalf("fail-closed should reject: %v %d", err, rec.Code)
	}
	// fail-open 放行
	g.failOpen = true
	called := false
	if err := g.ServeHTTP(httptest.NewRecorder(), req("203.0.113.93:1", nil), nextHandler{&called}); err != nil || !called {
		t.Fatalf("fail-open should pass: %v", err)
	}
	// 告警事件
	found := false
	for _, e := range g.readEvents(t) {
		if e.EventType == events.RateLimitEngineError {
			found = true
		}
	}
	if !found {
		t.Fatal("RATE_LIMIT_ENGINE_ERROR event expected")
	}
}

// errLimiter 模拟引擎故障。
type errLimiter struct{}

func (e *errLimiter) Allow(_ context.Context, _ string, _ ratelimit.Algorithm, _ int64, _ time.Duration, _ int64) (ratelimit.Result, error) {
	return ratelimit.Result{}, errEngine
}

func (e *errLimiter) Peek(_ context.Context, _ string, _ ratelimit.Algorithm, _ int64, _ time.Duration, _ int64) (int64, bool, error) {
	return 0, false, errEngine
}

// fakeValkeyClient Valkey 测试替身：仅记录 Close 调用（命令方法不支持，调用即错）。
type fakeValkeyClient struct{ closed bool }

func (f *fakeValkeyClient) Eval(context.Context, string, []string, []string) ([]interface{}, error) {
	return nil, errors.New("fake valkey: eval unsupported")
}
func (f *fakeValkeyClient) HSet(context.Context, string, string, string) error {
	return errors.New("fake valkey: hset unsupported")
}
func (f *fakeValkeyClient) HGetAll(context.Context, string) (map[string]string, error) {
	return nil, errors.New("fake valkey: hgetall unsupported")
}
func (f *fakeValkeyClient) HDel(context.Context, string, ...string) error {
	return errors.New("fake valkey: hdel unsupported")
}
func (f *fakeValkeyClient) Ping(context.Context) error {
	return errors.New("fake valkey: ping unsupported")
}
func (f *fakeValkeyClient) Close() error { f.closed = true; return nil }

// 共享引擎重建（配置指纹变化）：旧 Valkey 连接必须关闭——不关则每次改 Valkey 配置的
// reload 泄漏一条连接。
func TestGetEngineRebuildClosesOldValkey(t *testing.T) {
	resetSharedEngineForTest()
	t.Cleanup(resetSharedEngineForTest)
	fc := &fakeValkeyClient{}
	engineMu.Lock()
	engineInst = &sharedEngine{
		initialized: true,
		sig:         "stale-sig", // 与下方 Guard 指纹不同 → 强制重建
		valkey:      fc,
		limiter:     ratelimit.NewMemoryLimiter(100),
		blockCache:  temporaryblock.NewCache(nil, 0),
		lastErrEmit: map[string]time.Time{},
	}
	engineMu.Unlock()

	eng, err := getEngine(&Guard{CounterBackend: "memory"})
	if err != nil {
		t.Fatalf("getEngine: %v", err)
	}
	if eng == nil || eng.limiter == nil || eng.blockCache == nil {
		t.Fatal("rebuilt engine incomplete")
	}
	if !fc.closed {
		t.Fatal("old valkey connection must be closed on engine rebuild")
	}
}

// Cleanup 只关闭资源、不置 nil 字段（LOW-G4：配置重载与在途请求并发，请求路径无锁读
// 这些字段，置 nil 构成数据竞态）；sync.Once 保证重复调用安全。
func TestCleanupClosesWithoutNilifying(t *testing.T) {
	dir := t.TempDir()
	apiLog, err := apievents.NewLogger(filepath.Join(dir, "api-events.log"), "test-node")
	if err != nil {
		t.Fatalf("new api events logger: %v", err)
	}
	evLog, err := events.NewLogger(filepath.Join(dir, "events.log"), "test-node")
	if err != nil {
		t.Fatalf("new events logger: %v", err)
	}
	g := &Guard{logger: zap.NewNop(), apiEvents: apiLog, events: evLog}
	if err := g.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if g.events == nil || g.apiEvents == nil {
		t.Fatal("cleanup must keep fields assigned (request-path reads are lock-free)")
	}
	if err := g.Cleanup(); err != nil {
		t.Fatalf("second cleanup must be safe: %v", err)
	}
}

// API 事件记录器关闭时的后台落盘错误必须由 Guard.Cleanup 返回，避免网关
// 配置重载/退出吞掉授权决策事件的持久化失败。
func TestCleanupReportsAPIEventPersistenceFailure(t *testing.T) {
	dir := t.TempDir()
	apiLog, err := apievents.NewLogger(filepath.Join(dir, "api-events.log"), "test-node")
	if err != nil {
		t.Fatalf("new api events logger: %v", err)
	}
	t.Cleanup(func() { _ = apiLog.Close() })

	evLog, err := events.NewLogger(filepath.Join(dir, "events.log"), "test-node")
	if err != nil {
		t.Fatalf("new events logger: %v", err)
	}
	g := &Guard{
		logger:         zap.NewNop(),
		apiEvents:      apiLog,
		events:         evLog,
		apiEventsClose: func() error { return errors.New("api events background write failed") },
	}
	if err := g.Cleanup(); err == nil || !strings.Contains(err.Error(), "api events background write failed") {
		t.Fatalf("cleanup error = %v, want API event persistence failure", err)
	}
}

// HIGH-5 回归：共享引擎重建失败（新配置 Valkey 不可达）时，在线旧引擎必须保持存活——
// 不取消封禁轮询、不关闭旧 Valkey 连接、共享指针仍指向旧实例（Caddy 拒绝新配置但旧
// 配置的 CC/封禁能力不受失败重载影响）。
func TestGetEngineFailedRebuildKeepsOldEngine(t *testing.T) {
	resetSharedEngineForTest()
	t.Cleanup(resetSharedEngineForTest)
	fc := &fakeValkeyClient{}
	pollCancelled := false
	old := &sharedEngine{
		initialized: true,
		sig:         "stale-sig", // 与下方 Guard 指纹不同 → 强制重建
		valkey:      fc,
		limiter:     ratelimit.NewMemoryLimiter(100),
		blockCache:  temporaryblock.NewCache(nil, 0),
		cancelPoll:  func() { pollCancelled = true },
		lastErrEmit: map[string]time.Time{},
	}
	engineMu.Lock()
	engineInst = old
	engineMu.Unlock()

	// 127.0.0.1:1 连接即拒（closed port），valkey.NewClient 初始拨号失败 → init 失败
	_, err := getEngine(&Guard{CounterBackend: "valkey", Valkey: &valkeyJSON{Address: "127.0.0.1:1"}})
	if err == nil {
		t.Fatal("expected init error for unreachable valkey")
	}
	engineMu.Lock()
	cur := engineInst
	engineMu.Unlock()
	if cur != old {
		t.Fatal("failed rebuild must keep the old engine instance alive")
	}
	if pollCancelled {
		t.Fatal("old poll must not be cancelled on failed rebuild")
	}
	if fc.closed {
		t.Fatal("old valkey connection must not be closed on failed rebuild")
	}
	// 旧引擎仍可用（CC/限速不受失败重载影响）
	res, lerr := old.limiter.Allow(context.Background(), "k", ratelimit.TokenBucket, 1, time.Minute, 1)
	if lerr != nil || !res.Allowed {
		t.Fatalf("old engine must remain functional: %v %+v", lerr, res)
	}
}

// M-13：启动首刷失败（fail-open 默认）——Error 日志之外产节流事件，不阻断引擎初始化；
// 同一引擎一分钟内重复失败只产一条（与请求路径 emitEngineErrorThrottled 同节流口径）。
func TestInitialBlockRefreshFailOpenEmitsThrottledEvent(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1"})
	eng := &sharedEngine{
		failOpen:    true,
		blockCache:  temporaryblock.NewCache(temporaryblock.NewStore(&fakeValkeyClient{}, ""), time.Second),
		lastErrEmit: map[string]time.Time{},
	}
	eng.mu.Lock()
	err := eng.initialBlockRefresh(g, context.Background())
	eng.mu.Unlock()
	if err != nil {
		t.Fatalf("fail-open 首刷失败不得阻断: %v", err)
	}
	// 节流：一分钟内第二次失败不再产事件
	eng.mu.Lock()
	err = eng.initialBlockRefresh(g, context.Background())
	eng.mu.Unlock()
	if err != nil {
		t.Fatalf("fail-open 重复首刷失败不得阻断: %v", err)
	}
	var engineErrs []events.Event
	for _, e := range g.readEvents(t) {
		if e.EventType == events.RateLimitEngineError {
			engineErrs = append(engineErrs, e)
		}
	}
	if len(engineErrs) != 1 {
		t.Fatalf("节流事件应恰好一条, got %d", len(engineErrs))
	}
	if !strings.Contains(engineErrs[0].Message, "tempblock initial refresh failed") {
		t.Fatalf("事件 message 应含首刷失败说明: %q", engineErrs[0].Message)
	}
	if engineErrs[0].Action != "ENGINE_ERROR" {
		t.Fatalf("action = %q, want ENGINE_ERROR", engineErrs[0].Action)
	}
}

// M-13：fail-closed 下首刷失败拒绝加载（返回错误，上层回收半成品并拒绝新配置）；
// 事件仍产出可观测。
func TestInitialBlockRefreshFailClosedRejected(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1"})
	eng := &sharedEngine{
		failOpen:    false,
		blockCache:  temporaryblock.NewCache(temporaryblock.NewStore(&fakeValkeyClient{}, ""), time.Second),
		lastErrEmit: map[string]time.Time{},
	}
	eng.mu.Lock()
	err := eng.initialBlockRefresh(g, context.Background())
	eng.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "tempblock initial refresh") {
		t.Fatalf("fail-closed 首刷失败应拒绝加载: %v", err)
	}
	found := false
	for _, e := range g.readEvents(t) {
		if e.EventType == events.RateLimitEngineError {
			found = true
		}
	}
	if !found {
		t.Fatal("fail-closed 首刷失败也应产 RATE_LIMIT_ENGINE_ERROR 事件")
	}
}

// MED-8：max_counter_keys 必须有上限——内存计数/身份行为/风险存储按它 make 预分配，
// 异常大值在 Provision 阶段即可 OOM 杀进程。
func TestValidateMaxCounterKeysBound(t *testing.T) {
	g := &Guard{EventsLog: filepath.Join(t.TempDir(), "events.log")}
	g.MaxCounterKeys = maxCounterKeysLimit + 1
	if err := g.Validate(); err == nil {
		t.Fatal("max_counter_keys above limit must be rejected")
	}
	g.MaxCounterKeys = -1
	if err := g.Validate(); err == nil {
		t.Fatal("negative max_counter_keys must be rejected")
	}
	g.MaxCounterKeys = maxCounterKeysLimit
	if err := g.Validate(); err != nil {
		t.Fatalf("max_counter_keys at limit must pass: %v", err)
	}
	g.MaxCounterKeys = 0
	if err := g.Validate(); err != nil {
		t.Fatalf("zero (default) max_counter_keys must pass: %v", err)
	}
}

// ---------- 测试辅助 ----------

func (g *Guard) readEvents(t *testing.T) []events.Event {
	t.Helper()
	g.events.Close()
	p, _ := eventsPaths.Load(g)
	f, err := os.Open(p.(string))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []events.Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e events.Event
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
