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
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/cidr"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
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
	g.policies, err = compilePolicies(cfg.RateLimits)
	if err != nil {
		t.Fatal(err)
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
