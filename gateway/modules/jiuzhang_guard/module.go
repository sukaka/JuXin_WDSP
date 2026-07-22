// Package jiuzhang_guard 实现九章自主 Caddy 防护模块（阶段5：访问控制与CC防护）。
//
// 请求处理顺序：真实IP识别 → 保护地址 → 全局白 → 应用白 → 全局黑 → 应用黑
// → 临时封禁 → CC限速 → 下一处理器（WAF）。
// 白名单默认绕过黑名单与 CC，不绕过 WAF 与协议校验。
package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/accesscontrol"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/cidr"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/ratelimit"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/temporaryblock"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/trustedproxy"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&Guard{})
}

// ---------- 配置 JSON 结构（与管理后端配置生成器约定一致） ----------

type proxyJSON struct {
	Name             string `json:"name"`
	CIDR             string `json:"cidr"`
	HeaderType       string `json:"header_type"`
	CustomHeaderName string `json:"custom_header_name,omitempty"`
	Priority         int    `json:"priority"`
}

type ruleJSON struct {
	ID             string `json:"id"`
	Address        string `json:"address"`
	Priority       int    `json:"priority"`
	EffectiveFrom  string `json:"effective_from,omitempty"`
	EffectiveUntil string `json:"effective_until,omitempty"`
}

type policyJSON struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Scope                string `json:"scope,omitempty"` // GLOBAL | APPLICATION
	Dimension            string `json:"dimension"`
	Algorithm            string `json:"algorithm"`
	URIMatchType         string `json:"uri_match_type"`
	URIPattern           string `json:"uri_pattern,omitempty"`
	RequestsLimit        int64  `json:"requests_limit"`
	WindowSeconds        int    `json:"window_seconds"`
	BurstCapacity        int64  `json:"burst_capacity,omitempty"`
	Action               string `json:"action"`
	BlockDurationSeconds int    `json:"block_duration_seconds,omitempty"`
	ObserveOnly          bool   `json:"observe_only,omitempty"`
	Priority             int    `json:"priority"`
	EffectiveFrom        string `json:"effective_from,omitempty"`
	EffectiveUntil       string `json:"effective_until,omitempty"`
}

type valkeyJSON struct {
	Address  string `json:"address"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	DB       int    `json:"db"`
}

// Guard 是九章访问控制与CC防护 Caddy HTTP 处理器模块。
type Guard struct {
	// 应用标识（事件归属与 CC 维度）
	AppID   string `json:"app_id"`
	AppCode string `json:"app_code"`

	// 真实IP识别
	TrustedProxies []proxyJSON `json:"trusted_proxies,omitempty"`
	MaxProxyChain  int         `json:"max_proxy_chain,omitempty"`

	// 保护地址（永不封禁）
	ProtectedAddresses []string `json:"protected_addresses,omitempty"`

	// 黑白名单（本路由应用视角：全局 + 本应用）
	GlobalAllow []ruleJSON `json:"global_allow,omitempty"`
	GlobalDeny  []ruleJSON `json:"global_deny,omitempty"`
	AppAllow    []ruleJSON `json:"app_allow,omitempty"`
	AppDeny     []ruleJSON `json:"app_deny,omitempty"`

	// CC 策略（全局 + 本应用，发布时已过滤）
	RateLimits []policyJSON `json:"rate_limits,omitempty"`

	// 计数后端：memory | valkey（默认 valkey，失败按 FailOpen 策略）
	CounterBackend string `json:"counter_backend,omitempty"`
	MaxCounterKeys int    `json:"max_counter_keys,omitempty"`

	// Valkey 连接（临时封禁与共享计数）
	Valkey *valkeyJSON `json:"valkey,omitempty"`

	// 故障策略：默认 true（Fail-open），false 为 Fail-closed
	FailOpen *bool `json:"fail_open,omitempty"`

	// 临时封禁轮询间隔（默认 1s）
	TempBlockPollInterval string `json:"temp_block_poll_interval,omitempty"`

	// 事件输出
	EventsLog   string `json:"events_log"`
	GatewayNode string `json:"gateway_node,omitempty"`

	// 运行时
	logger    *zap.Logger
	resolver  clientip.Resolver
	proxies   *trustedproxy.Set
	protected *cidr.Matcher
	allowG    *accesscontrol.RuleSet
	allowA    *accesscontrol.RuleSet
	denyG     *accesscontrol.RuleSet
	denyA     *accesscontrol.RuleSet
	policies  []*compiledPolicy
	events    *events.Logger
	engine    *sharedEngine
	failOpen  bool // 本实例故障策略（Provision 时确定，配置重载即可切换）
}

// compiledPolicy 编译后的 CC 策略。
type compiledPolicy struct {
	cfg   policyJSON
	uriRe *regexp.Regexp
	from  *time.Time
	until *time.Time
}

// CaddyModule 返回模块信息。
func (Guard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jiuzhang_guard",
		New: func() caddy.Module { return new(Guard) },
	}
}

// ---------- 共享引擎（进程级：Valkey 连接/临时封禁缓存/内存计数器） ----------

type sharedEngine struct {
	mu          sync.Mutex
	initialized bool
	sig         string // 配置指纹（backend/addr/密码/DB/maxKeys）
	valkey      counters.ValkeyClient
	limiter     ratelimit.Limiter
	memLimiter  *ratelimit.MemoryLimiter
	blockStore  *temporaryblock.Store
	blockCache  *temporaryblock.Cache
	failOpen    bool
	cancelPoll  context.CancelFunc
	// 引擎错误告警节流（每分钟每类最多一条事件）
	lastErrEmit map[string]time.Time
}

var (
	engineMu   sync.Mutex
	engineInst *sharedEngine
)

// engineFingerprint 用于判断共享引擎是否需重建（凭据/后端变化）。
func engineFingerprint(g *Guard) string {
	backend := g.CounterBackend
	if backend == "" {
		backend = "valkey"
	}
	addr, user, pass, db := "", "", "", 0
	if g.Valkey != nil {
		addr = g.Valkey.Address
		user = g.Valkey.Username
		pass = g.Valkey.Password
		db = g.Valkey.DB
	}
	return fmt.Sprintf("%s|%s|%s|%s|%d|%d", backend, addr, user, pass, db, g.MaxCounterKeys)
}

// getEngine 初始化或复用共享引擎；失败不缓存半初始化实例，配置指纹变化时重建。
func getEngine(g *Guard) (*sharedEngine, error) {
	engineMu.Lock()
	defer engineMu.Unlock()
	sig := engineFingerprint(g)
	if engineInst != nil && engineInst.initialized && engineInst.sig == sig &&
		engineInst.limiter != nil && engineInst.blockCache != nil {
		return engineInst, nil
	}
	// 停止旧轮询
	if engineInst != nil && engineInst.cancelPoll != nil {
		engineInst.cancelPoll()
		engineInst.cancelPoll = nil
	}
	e := &sharedEngine{lastErrEmit: map[string]time.Time{}, sig: sig}
	if err := e.init(g); err != nil {
		engineInst = nil
		return nil, err
	}
	if e.limiter == nil || e.blockCache == nil {
		engineInst = nil
		return nil, fmt.Errorf("engine init incomplete")
	}
	engineInst = e
	return engineInst, nil
}

// resetSharedEngineForTest 测试辅助：清空进程级引擎。
func resetSharedEngineForTest() {
	engineMu.Lock()
	defer engineMu.Unlock()
	if engineInst != nil && engineInst.cancelPoll != nil {
		engineInst.cancelPoll()
	}
	engineInst = nil
}

func (e *sharedEngine) init(g *Guard) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failOpen = g.FailOpen == nil || *g.FailOpen
	e.memLimiter = ratelimit.NewMemoryLimiter(g.MaxCounterKeys)
	backend := g.CounterBackend
	if backend == "" {
		backend = "valkey"
	}
	if backend == "valkey" && g.Valkey != nil && g.Valkey.Address != "" {
		cli, err := counters.NewValkeyClient(counters.ValkeyConfig{
			Address:  g.Valkey.Address,
			Username: g.Valkey.Username,
			Password: g.Valkey.Password,
			DB:       g.Valkey.DB,
		})
		if err != nil {
			return fmt.Errorf("valkey init: %w", err)
		}
		e.valkey = cli
		e.limiter = ratelimit.NewValkeyLimiter(cli, "")
		e.blockStore = temporaryblock.NewStore(cli, "")
		poll, _ := time.ParseDuration(g.TempBlockPollInterval)
		e.blockCache = temporaryblock.NewCache(e.blockStore, poll)
		ctx, cancel := context.WithCancel(context.Background())
		e.cancelPoll = cancel
		if err := e.blockCache.Refresh(ctx); err != nil {
			// 启动时同步失败不阻断（缓存可空，下一轮重试），但必须可观测
			slog.Error("jiuzhang_guard tempblock initial refresh failed", "error", err)
		}
		e.blockCache.Start(ctx)
	} else {
		// 纯内存模式：临时封禁仅进程内有效（单节点模式）
		e.blockCache = temporaryblock.NewCache(nil, 0)
		e.limiter = e.memLimiter
	}
	e.initialized = true
	return nil
}

// ---------- Provision / Validate ----------

// Provision 解析配置并初始化运行时。
func (g *Guard) Provision(ctx caddy.Context) error {
	g.logger = ctx.Logger()
	if g.EventsLog == "" {
		return fmt.Errorf("events_log is required")
	}
	if g.GatewayNode == "" {
		g.GatewayNode = "gateway-unknown"
	}
	g.resolver = clientip.NewResolver(g.MaxProxyChain)
	g.failOpen = g.FailOpen == nil || *g.FailOpen

	// 可信代理
	proxies := make([]trustedproxy.Proxy, 0, len(g.TrustedProxies))
	for _, p := range g.TrustedProxies {
		pfx, err := cidr.ParseAddress(p.CIDR)
		if err != nil {
			return fmt.Errorf("trusted proxy %q: %w", p.Name, err)
		}
		proxies = append(proxies, trustedproxy.Proxy{
			Name:             p.Name,
			Prefix:           pfx,
			HeaderType:       trustedproxy.HeaderType(p.HeaderType),
			CustomHeaderName: p.CustomHeaderName,
			Priority:         p.Priority,
		})
	}
	set, err := trustedproxy.NewSet(proxies)
	if err != nil {
		return err
	}
	g.proxies = set

	// 保护地址
	entries := make([]cidr.Entry, 0, len(g.ProtectedAddresses))
	for _, a := range g.ProtectedAddresses {
		pfx, err := cidr.ParseAddress(a)
		if err != nil {
			return fmt.Errorf("protected address %q: %w", a, err)
		}
		entries = append(entries, cidr.Entry{Prefix: pfx, Meta: a})
	}
	g.protected = cidr.NewMatcher(entries)

	// 黑白名单
	if g.allowG, err = buildRuleSet(g.GlobalAllow); err != nil {
		return fmt.Errorf("global allow: %w", err)
	}
	if g.allowA, err = buildRuleSet(g.AppAllow); err != nil {
		return fmt.Errorf("app allow: %w", err)
	}
	if g.denyG, err = buildRuleSet(g.GlobalDeny); err != nil {
		return fmt.Errorf("global deny: %w", err)
	}
	if g.denyA, err = buildRuleSet(g.AppDeny); err != nil {
		return fmt.Errorf("app deny: %w", err)
	}

	// CC 策略
	policies, err := compilePolicies(g.RateLimits)
	if err != nil {
		return err
	}
	g.policies = policies

	// 事件记录器
	el, err := events.NewLogger(g.EventsLog, g.GatewayNode)
	if err != nil {
		return err
	}
	g.events = el

	// 共享引擎
	eng, err := getEngine(g)
	if err != nil {
		return err
	}
	g.engine = eng
	return nil
}

// Validate 配置校验。
func (g *Guard) Validate() error {
	if g.EventsLog == "" {
		return fmt.Errorf("events_log is required")
	}
	for _, p := range g.RateLimits {
		if p.RequestsLimit <= 0 || p.WindowSeconds <= 0 {
			return fmt.Errorf("rate limit %q: limit/window must be positive", p.ID)
		}
	}
	return nil
}

// Cleanup 关闭事件记录器（共享引擎随进程生命周期，不在配置重载时关闭）。
func (g *Guard) Cleanup() error {
	if g.events != nil {
		return g.events.Close()
	}
	return nil
}

// buildRuleSet 解析规则 JSON。
func buildRuleSet(rules []ruleJSON) (*accesscontrol.RuleSet, error) {
	out := make([]accesscontrol.Rule, 0, len(rules))
	for _, r := range rules {
		pfx, err := cidr.ParseAddress(r.Address)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		rule := accesscontrol.Rule{
			ID:       r.ID,
			Address:  r.Address,
			Prefix:   pfx,
			Priority: r.Priority,
		}
		if r.EffectiveFrom != "" {
			t, err := time.Parse(time.RFC3339, r.EffectiveFrom)
			if err != nil {
				return nil, fmt.Errorf("rule %q: bad effective_from", r.ID)
			}
			rule.EffectiveFrom = &t
		}
		if r.EffectiveUntil != "" {
			t, err := time.Parse(time.RFC3339, r.EffectiveUntil)
			if err != nil {
				return nil, fmt.Errorf("rule %q: bad effective_until", r.ID)
			}
			rule.EffectiveUntil = &t
		}
		out = append(out, rule)
	}
	return accesscontrol.NewRuleSet(out)
}

// maxURIPatternLen 正则/模式长度上限（配合 RE2 线性时间引擎防正则拒绝服务）。
const maxURIPatternLen = 256

// compilePolicies 编译 CC 策略（优先级升序）。
func compilePolicies(in []policyJSON) ([]*compiledPolicy, error) {
	out := make([]*compiledPolicy, 0, len(in))
	for _, p := range in {
		cp := &compiledPolicy{cfg: p}
		switch p.Dimension {
		case "CLIENT_IP", "APPLICATION", "CLIENT_IP_AND_URI", "CLIENT_IP_AND_APPLICATION":
		default:
			return nil, fmt.Errorf("policy %q: unknown dimension %q", p.ID, p.Dimension)
		}
		switch p.Algorithm {
		case string(ratelimit.TokenBucket), string(ratelimit.SlidingWindow):
		default:
			return nil, fmt.Errorf("policy %q: unknown algorithm %q", p.ID, p.Algorithm)
		}
		switch p.Action {
		case "LOG", "OBSERVE", "REJECT", "TEMP_BLOCK":
		default:
			return nil, fmt.Errorf("policy %q: unknown action %q", p.ID, p.Action)
		}
		if p.Action == "TEMP_BLOCK" && p.BlockDurationSeconds <= 0 {
			return nil, fmt.Errorf("policy %q: block_duration required for TEMP_BLOCK", p.ID)
		}
		if len(p.URIPattern) > maxURIPatternLen {
			return nil, fmt.Errorf("policy %q: uri_pattern too long", p.ID)
		}
		switch p.URIMatchType {
		case "", "ALL":
		case "EXACT", "PREFIX":
			if p.URIPattern == "" {
				return nil, fmt.Errorf("policy %q: uri_pattern required", p.ID)
			}
		case "REGEX":
			re, err := regexp.Compile(p.URIPattern)
			if err != nil {
				return nil, fmt.Errorf("policy %q: bad regex: %w", p.ID, err)
			}
			cp.uriRe = re
		default:
			return nil, fmt.Errorf("policy %q: unknown uri_match_type %q", p.ID, p.URIMatchType)
		}
		if p.EffectiveFrom != "" {
			t, err := time.Parse(time.RFC3339, p.EffectiveFrom)
			if err != nil {
				return nil, fmt.Errorf("policy %q: bad effective_from", p.ID)
			}
			cp.from = &t
		}
		if p.EffectiveUntil != "" {
			t, err := time.Parse(time.RFC3339, p.EffectiveUntil)
			if err != nil {
				return nil, fmt.Errorf("policy %q: bad effective_until", p.ID)
			}
			cp.until = &t
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].cfg.Priority < out[j].cfg.Priority })
	return out, nil
}

// ---------- 请求处理 ----------

// ServeHTTP 主流程。
func (g *Guard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	now := time.Now().UTC()
	requestID := r.Header.Get("X-Request-Id")

	// 1. 真实IP识别
	res := g.resolver.Resolve(r, g.proxies)
	if !res.ClientIP.IsValid() {
		// 连接源不可解析：拒绝（无法实施任何基于IP的防护）
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("unparseable remote addr"))
	}
	base := g.eventBase(r, requestID, res)
	if res.HeaderInvalid {
		g.emit(base, events.ForwardedHeaderInvalid, "CONNECTION_FALLBACK", 0)
	}
	if res.ChainTooLong {
		g.emit(base, events.ForwardedChainTooLong, "CONNECTION_FALLBACK", 0)
	}
	// 伪造检测：携带代理头但连接源不可信 → TRUSTED_PROXY_INVALID
	if res.TrustedProxyUsed == "" && hasProxyHeaders(r) {
		g.emit(base, events.TrustedProxyInvalid, "IGNORED", 0)
	}

	clientIP := res.ClientIP
	// 下游（WAF/日志/代理）统一使用真实IP
	r.RemoteAddr = net.JoinHostPort(clientIP.String(), "0")
	r.Header.Set("X-Real-Ip", clientIP.String())

	// 2. 保护地址：仅当「客户端 IP」命中时跳过 ACL/CC（仍过 WAF）。
	// 连接源（LB/本机反代）不得用于旁路真实客户端的访问控制。
	if g.protected.Contains(clientIP) {
		return next.ServeHTTP(w, r)
	}

	// 3. 临时封禁查询（人工封禁优先于白名单；自动 CC 封禁可由白名单绕过）
	var autoBlock *temporaryblock.Block
	if blk, ok := g.engine.blockCache.Blocked(clientIP, g.AppID); ok {
		if !blk.Auto {
			ev := base
			ev.Action = "TEMP_BLOCK"
			ev.PolicyID = blk.ID
			exp := blk.ExpiresAt
			ev.BlockExpiresAt = &exp
			g.emit(ev, events.CCRequestRejected, "TEMP_BLOCK", http.StatusForbidden)
			return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("temporarily blocked"))
		}
		b := blk
		autoBlock = &b
	}

	// 4. 黑白名单（白名单命中跳过黑名单与 CC，不跳过 WAF；不绕过人工临时封禁）
	dec := accesscontrol.Evaluate(clientIP, now, g.allowG, g.allowA, g.denyG, g.denyA)
	switch dec.Action {
	case accesscontrol.ActionAllow:
		ev := base
		ev.AccessRuleID = dec.RuleID
		g.emit(ev, events.IPAllowMatch, "ALLOW", 0)
		return next.ServeHTTP(w, r)
	case accesscontrol.ActionDeny:
		ev := base
		ev.AccessRuleID = dec.RuleID
		g.emit(ev, events.IPDenyMatch, "DENY", http.StatusForbidden)
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("access denied"))
	}

	// 5. 自动临时封禁（未被白名单绕过）
	if autoBlock != nil {
		ev := base
		ev.Action = "TEMP_BLOCK"
		ev.PolicyID = autoBlock.ID
		exp := autoBlock.ExpiresAt
		ev.BlockExpiresAt = &exp
		g.emit(ev, events.CCRequestRejected, "TEMP_BLOCK", http.StatusForbidden)
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("temporarily blocked"))
	}

	// 6. CC 限速
	if handled, err := g.enforceRateLimits(w, r, clientIP, base, now); handled {
		return err
	}

	// 7. 放行（进入 WAF 等后续处理器）
	return next.ServeHTTP(w, r)
}

// enforceRateLimits 执行 CC 策略；handled=true 表示已响应。
func (g *Guard) enforceRateLimits(w http.ResponseWriter, r *http.Request, clientIP netip.Addr, base events.Event, now time.Time) (bool, error) {
	path := r.URL.Path
	for _, p := range g.policies {
		if p.from != nil && now.Before(*p.from) {
			continue
		}
		if p.until != nil && !now.Before(*p.until) {
			continue
		}
		if !p.matchURI(path) {
			continue
		}
		key := p.cfg.ID + ":" + p.dimensionKey(clientIP, g.AppID)
		res, err := g.engine.limiter.Allow(r.Context(), key,
			ratelimit.Algorithm(p.cfg.Algorithm), p.cfg.RequestsLimit,
			time.Duration(p.cfg.WindowSeconds)*time.Second, p.cfg.BurstCapacity)
		if err != nil {
			// 故障策略：Fail-open 放行 / Fail-closed 拒绝；均告警（节流）
			g.emitEngineErrorThrottled(base, p, err)
			if g.failOpen {
				continue
			}
			g.writeTooMany(w, r, base.RequestID, 60)
			g.emit(withPolicy(base, p), events.CCRequestRejected, "REJECT", http.StatusTooManyRequests)
			return true, nil
		}
		if res.Allowed {
			continue
		}
		// 超限
		ev := withPolicy(base, p)
		ev.CurrentCount = res.Current
		ev.LimitValue = p.cfg.RequestsLimit
		ev.WindowSeconds = p.cfg.WindowSeconds
		if p.cfg.ObserveOnly || p.cfg.Action == "LOG" || p.cfg.Action == "OBSERVE" {
			g.emit(ev, events.CCThresholdExceeded, "OBSERVE", 0)
			continue
		}
		switch p.cfg.Action {
		case "REJECT":
			retrySec := int(res.RetryAfter.Seconds()) + 1
			g.emit(ev, events.CCRequestRejected, "REJECT", http.StatusTooManyRequests)
			g.writeTooMany(w, r, base.RequestID, retrySec)
			return true, nil
		case "TEMP_BLOCK":
			exp := now.Add(time.Duration(p.cfg.BlockDurationSeconds) * time.Second)
			// 全局策略写全局 ban key（AppID 空），应用策略写本应用
			banAppID := g.AppID
			if strings.EqualFold(p.cfg.Scope, "GLOBAL") {
				banAppID = ""
			}
			blk := temporaryblock.Block{
				ID:        p.cfg.ID,
				ClientIP:  clientIP.String(),
				AppID:     banAppID,
				ExpiresAt: exp,
				Reason:    "cc_threshold_exceeded",
				Auto:      true,
			}
			if err := g.engine.blockCache.PutLocal(r.Context(), blk); err != nil {
				g.emitEngineErrorThrottled(base, p, err)
			}
			ev.BlockExpiresAt = &exp
			g.emit(ev, events.CCTempBlockCreated, "TEMP_BLOCK", 0)
			g.emit(ev, events.CCRequestRejected, "TEMP_BLOCK", http.StatusTooManyRequests)
			g.writeTooMany(w, r, base.RequestID, p.cfg.BlockDurationSeconds)
			return true, nil
		}
	}
	return false, nil
}

// matchURI URI 匹配。
func (p *compiledPolicy) matchURI(path string) bool {
	switch p.cfg.URIMatchType {
	case "", "ALL":
		return true
	case "EXACT":
		return path == p.cfg.URIPattern
	case "PREFIX":
		return strings.HasPrefix(path, p.cfg.URIPattern)
	case "REGEX":
		return p.uriRe.MatchString(path)
	}
	return false
}

// dimensionKey 按限速维度生成键（哈希化，禁止拼接原始输入）。
// CLIENT_IP_AND_URI 使用策略的 URI 模式而非具体路径：
// 策略本身即 URI 分组，用具体路径会导致随机 URI 绕过与键爆炸。
func (p *compiledPolicy) dimensionKey(clientIP netip.Addr, appID string) string {
	switch p.cfg.Dimension {
	case "CLIENT_IP":
		return counters.HashParts("ip", clientIP.String())
	case "APPLICATION":
		return counters.HashParts("app", appID)
	case "CLIENT_IP_AND_URI":
		pattern := p.cfg.URIPattern
		if pattern == "" {
			pattern = "*"
		}
		return counters.HashParts("ipuri", clientIP.String(), pattern)
	case "CLIENT_IP_AND_APPLICATION":
		return counters.HashParts("ipapp", clientIP.String(), appID)
	}
	return counters.HashParts("ip", clientIP.String())
}

// ---------- 响应与事件辅助 ----------

// writeTooMany 429 响应（Retry-After + Request ID，不暴露内部阈值/计数/算法/节点）。
func (g *Guard) writeTooMany(w http.ResponseWriter, r *http.Request, requestID string, retryAfterSec int) {
	if retryAfterSec <= 0 {
		retryAfterSec = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSec))
	w.Header().Set("X-Jiuzhang-Request-ID", requestID)
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		body, _ := json.Marshal(map[string]string{
			"error":      "too_many_requests",
			"message":    "请求过于频繁，请稍后重试",
			"request_id": requestID,
		})
		_, _ = w.Write(body)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	// 静态模板，Request ID 为服务端生成 UUID，仍做 HTML 转义（纵深防御）
	fmt.Fprintf(w, `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>请求过于频繁</title></head>`+
		`<body><h1>429 请求过于频繁</h1><p>请稍后重试。</p><p>请求编号：%s</p></body></html>`, html.EscapeString(requestID))
}

// eventBase 构造事件公共字段。
func (g *Guard) eventBase(r *http.Request, requestID string, res clientip.Result) events.Event {
	return events.Event{
		RequestID:     requestID,
		OccurredAt:    time.Now().UTC(),
		ApplicationID: g.AppID,
		AppCode:       g.AppCode,
		ClientIP:      res.ClientIP.String(),
		ConnectionIP:  res.ConnectionIP.String(),
		Domain:        r.Host,
		Method:        r.Method,
		Path:          r.URL.RequestURI(),
		GatewayNode:   g.GatewayNode,
	}
}

// withPolicy 附加策略字段。
func withPolicy(e events.Event, p *compiledPolicy) events.Event {
	e.PolicyID = p.cfg.ID
	return e
}

// emit 输出事件（失败记录到网关日志，不阻断请求）。
func (g *Guard) emit(e events.Event, t events.Type, action string, status int) {
	e.EventType = t
	if action != "" {
		e.Action = action
	}
	if status != 0 {
		e.ResponseStatus = status
	}
	if err := g.events.Emit(e); err != nil {
		g.logger.Error("guard: emit event failed", zap.String("type", string(t)), zap.Error(err))
	}
}

// emitEngineErrorThrottled 引擎错误告警（每分钟每策略最多一条，防日志洪泛）。
func (g *Guard) emitEngineErrorThrottled(base events.Event, p *compiledPolicy, err error) {
	g.engine.mu.Lock()
	last, ok := g.engine.lastErrEmit[p.cfg.ID]
	if !ok || time.Since(last) > time.Minute {
		g.engine.lastErrEmit[p.cfg.ID] = time.Now()
	}
	g.engine.mu.Unlock()
	if ok && time.Since(last) <= time.Minute {
		return
	}
	ev := withPolicy(base, p)
	ev.Message = err.Error()
	g.emit(ev, events.RateLimitEngineError, "ENGINE_ERROR", 0)
}

// hasProxyHeaders 请求是否携带代理头（伪造检测用）。
func hasProxyHeaders(r *http.Request) bool {
	return r.Header.Get("X-Forwarded-For") != "" ||
		r.Header.Get("X-Real-IP") != "" ||
		r.Header.Get("Forwarded") != ""
}

// 接口断言
var _ caddyhttp.MiddlewareHandler = (*Guard)(nil)
var _ caddy.Provisioner = (*Guard)(nil)
var _ caddy.Validator = (*Guard)(nil)
var _ caddy.CleanerUpper = (*Guard)(nil)
