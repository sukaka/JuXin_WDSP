package detectors

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 同凭据环境异常检测（访问微模型·环境维度，docs/API_MICRO_MODELS.md §2.3 与 §4 第 7 项）：
// 账号接管（ATO）主要检出面——同凭据跨 IP 跳变 + 同凭据并发度异常。
// 纪律：仅凭据维度（CredentialKey）聚合，匿名流量直接跳过（IP 属环境维度，不得冒充身份）；
// 两条规则均为 OBSERVE 级信号只 AddMatch，动作统一由决策引擎输出；
// IP 只以加盐指纹入集合，凭据明文不出解析层，证据去敏（不含任何 IP/凭据）。
const (
	// DefaultCredentialIPSpreadLimit 同凭据滑窗 distinct IP 默认阈值。
	DefaultCredentialIPSpreadLimit = 3
	// DefaultCredentialConcurrencyLimit 同凭据并发度默认阈值。
	DefaultCredentialConcurrencyLimit = 8
	// envAnomalyMaxKeys 游标/集合 LRU 定容（与 window.go 同一纪律，单节点限制亦同）。
	envAnomalyMaxKeys = 10000
	// maxSpreadIPsPerWindow 单键单窗口 distinct IP 指纹集合上限：防 botnet 泛洪撑爆内存；
	// 达上限后不再新增（已远超判定阈值，不影响检测结论）。
	maxSpreadIPsPerWindow = 1024
)

// ---------- 同凭据跨 IP 跳变 ----------

// ipSpreadEntry 单凭据窗口状态：窗口起点 + distinct IP 指纹集合（HMAC 指纹，不落明文）。
type ipSpreadEntry struct {
	windowStart time.Time
	ips         map[string]struct{}
}

// ipSpreadTracker 凭据 → 窗口内 distinct IP 指纹集合（LRU 定容）。
type ipSpreadTracker struct {
	mu      sync.Mutex
	entries *lru
	now     func() time.Time
}

func newIPSpreadTracker(capacity int, now func() time.Time) *ipSpreadTracker {
	if now == nil {
		now = time.Now
	}
	return &ipSpreadTracker{entries: newLRU(capacity), now: now}
}

// add 记录一次来源 IP 指纹，返回当前窗口 distinct 数。窗口对齐与滚动纪律同 windowTracker
// （自然分钟对齐，跨窗口重置集合）。
func (t *ipSpreadTracker) add(key, ipfp string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cur := t.now().UTC().Truncate(windowSize)
	var e *ipSpreadEntry
	if v, ok := t.entries.get(key); ok {
		e = v.(*ipSpreadEntry)
	} else {
		e = &ipSpreadEntry{windowStart: cur, ips: map[string]struct{}{}}
		t.entries.set(key, e)
	}
	if !e.windowStart.Equal(cur) {
		e.windowStart = cur
		e.ips = map[string]struct{}{}
	}
	if len(e.ips) < maxSpreadIPsPerWindow {
		e.ips[ipfp] = struct{}{}
	}
	return len(e.ips)
}

// defaultIPSpreadTracker 包级默认跨 IP 跳变追踪器。
var defaultIPSpreadTracker = newIPSpreadTracker(envAnomalyMaxKeys, nil)

// CheckCredentialIPSpread 同凭据跨 IP 跳变：滑窗 distinct IP ≥ limit → auth.credential_ip_spread
// （OBSERVE/MEDIUM，只 AddMatch 不定案）。
// 冷启动说明：不同于 RATE_SPIKE 的双门槛（历史窗口样本 + 突增倍数），本规则「distinct 数
// 达到阈值」本身即门槛——窗口内前 limit-1 个不同 IP 天然不报，无需历史基线，无冷启动问题。
// Evidence 只含 distinct 数与窗口，不含任何 IP（明文或指纹均不含）。
func CheckCredentialIPSpread(ctx *dsctx.RequestContext, r *http.Request, credKey, salt string, limit int) {
	if ctx == nil || r == nil || credKey == "" {
		return
	}
	if limit <= 0 {
		limit = DefaultCredentialIPSpreadLimit
	}
	ip := remoteIPString(r.RemoteAddr)
	if ip == "" {
		// 无来源环境事实（如进程内构造的请求），跳过
		return
	}
	distinct := ipSpreadAdd(ctx, credKey, Fingerprint(salt, ip))
	if distinct < limit {
		return
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "authentication",
		RuleID:   "auth.credential_ip_spread",
		Category: "OBSERVE",
		Severity: "MEDIUM",
		Message:  "credential used from multiple source ips",
		Evidence: map[string]string{
			"distinct_ips": strconv.Itoa(distinct),
			"window":       "1m",
		},
		ScoreDelta: 15,
	})
}

// remoteIPString 从 RemoteAddr 提取客户端 IP（guard 入口已将其改写为真实客户端 IP，见 module.go）。
func remoteIPString(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil || host == "" {
		host = remoteAddr
	}
	return host
}

// ---------- 同凭据并发度 ----------

// credentialConcurrencyTracker 同凭据 in-flight 计数（LRU 定容；键被淘汰时计数随之丢失——
// 万级活跃凭据场景下的有界近似，OBSERVE 信号可接受）。
type credentialConcurrencyTracker struct {
	mu      sync.Mutex
	entries *lru // key → int（in-flight 数）
}

// defaultCredentialConcurrency 包级默认同凭据并发计数器。
var defaultCredentialConcurrency = &credentialConcurrencyTracker{entries: newLRU(envAnomalyMaxKeys)}

// acquire 入口并发 +1，返回当前并发数。
func (t *credentialConcurrencyTracker) acquire(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 1
	if v, ok := t.entries.get(key); ok {
		n = v.(int) + 1
	}
	t.entries.set(key, n)
	return n
}

// release 出口并发 -1（键已被 LRU 淘汰时计数已丢失，无需回退）。
func (t *credentialConcurrencyTracker) release(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.entries.get(key)
	if !ok {
		return
	}
	if c := v.(int); c > 1 {
		t.entries.set(key, c-1)
	} else {
		t.entries.set(key, 0)
	}
}

// AcquireCredentialInFlight 请求入口同凭据并发 +1，返回当前并发数与释放函数（出口调用一次，幂等）。
// 匿名（credKey 为空）不跟踪，返回 0 与空释放函数。
// 记账生命周期：pipeline 包本身无请求生命周期钩子（Process 为单次同步调用），最接近的
// 真实 in-flight 埋点是 guard serveNext 放行链路——入口 Acquire、覆盖检测+下游转发全程、
// 出口 defer release（见 jiuzhang_guard/apiprotect.go）。
// 注入 ConcurrencyStore 时改由注入实现记账（释放函数闭包绑定同一实现，配置重载不串账）。
func AcquireCredentialInFlight(credKey string) (int, func()) {
	return acquireCredentialInFlight(credKey, nil)
}

// AcquireCredentialInFlightWithStores 使用调用方 Guard 实例绑定的并发存储；stores=nil
// 明确走默认内存，避免多实例之间共享或残留进程级覆盖。
func AcquireCredentialInFlightWithStores(credKey string, stores *StoreOverrides) (int, func()) {
	return acquireCredentialInFlight(credKey, stores)
}

func acquireCredentialInFlight(credKey string, stores *StoreOverrides) (int, func()) {
	if credKey == "" {
		return 0, func() {}
	}
	if stores != nil && stores.Concurrency != nil {
		s := stores.Concurrency
		n := s.Acquire(credKey)
		var once sync.Once
		return n, func() {
			once.Do(func() { s.Release(credKey) })
		}
	}
	t := defaultCredentialConcurrency
	n := t.acquire(credKey)
	var once sync.Once
	return n, func() {
		once.Do(func() { t.release(credKey) })
	}
}

// current 读取当前并发数（检测判定用；lru.get 会移动节点，故用互斥锁）。
func (t *credentialConcurrencyTracker) current(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if v, ok := t.entries.get(key); ok {
		return v.(int)
	}
	return 0
}

// CheckCredentialConcurrency 同凭据并发度异常：in-flight ≥ limit → auth.credential_concurrency
// （OBSERVE/LOW，只 AddMatch 不定案）。并发数由 AcquireCredentialInFlight 在请求生命周期
// 入口记账；未走记账的路径计数为 0 不报（宁可漏报，不误报）。
func CheckCredentialConcurrency(ctx *dsctx.RequestContext, credKey string, limit int) {
	if ctx == nil || credKey == "" {
		return
	}
	if limit <= 0 {
		limit = DefaultCredentialConcurrencyLimit
	}
	n := credentialInflightCurrent(ctx, credKey)
	if n < limit {
		return
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "authentication",
		RuleID:   "auth.credential_concurrency",
		Category: "OBSERVE",
		Severity: "LOW",
		Message:  "credential used by concurrent requests",
		Evidence: map[string]string{
			"inflight":  strconv.Itoa(n),
			"threshold": strconv.Itoa(limit),
		},
		ScoreDelta: 10,
	})
}

// ---------- 时段 / UA 族 / 多信号叠加 ----------

const (
	// unusualHourMinSamples 身份累计观测次数下限，不足不报时段异常。
	unusualHourMinSamples = 50
	// unusualHourShare 当前小时历史占比低于该阈值视为异常（且该小时计数为 0 或极低）。
	unusualHourShare = 0.02
)

// hourHistEntry 同凭据 24 小时桶累计（进程内近似基线）。
type hourHistEntry struct {
	buckets [24]int
	total   int
}

type hourHistTracker struct {
	mu      sync.Mutex
	entries *lru
	now     func() time.Time
}

func newHourHistTracker(cap int, now func() time.Time) *hourHistTracker {
	if now == nil {
		now = time.Now
	}
	return &hourHistTracker{entries: newLRU(cap), now: now}
}

var defaultHourHist = newHourHistTracker(envAnomalyMaxKeys, nil)

// CheckCredentialUnusualHour 同凭据非常规小时：累计样本足够且当前 UTC 小时历史占比极低 → OBSERVE。
func CheckCredentialUnusualHour(ctx *dsctx.RequestContext, credKey string) {
	if ctx == nil || credKey == "" {
		return
	}
	h := defaultHourHist.now().UTC().Hour()
	share, total := defaultHourHist.observe(credKey, h)
	if total < unusualHourMinSamples {
		return
	}
	if share > unusualHourShare {
		return
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "authentication",
		RuleID:     "auth.credential_unusual_hour",
		Category:   "OBSERVE",
		Severity:   "LOW",
		Message:    "credential active in unusual hour vs own baseline",
		Evidence:   map[string]string{"hour_utc": strconv.Itoa(h), "samples": strconv.Itoa(total)},
		ScoreDelta: 10,
	})
}

func (t *hourHistTracker) observe(key string, hour int) (share float64, total int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if hour < 0 || hour > 23 {
		hour = 0
	}
	var e *hourHistEntry
	if v, ok := t.entries.get(key); ok {
		e = v.(*hourHistEntry)
	} else {
		e = &hourHistEntry{}
		t.entries.set(key, e)
	}
	// 先用更新前分布判定（不含本请求），再记账
	total = e.total
	if total > 0 {
		share = float64(e.buckets[hour]) / float64(total)
	}
	e.buckets[hour]++
	e.total++
	return share, total
}

// uaFamilyEntry 同凭据最近 UA 族指纹。
type uaFamilyEntry struct {
	family string
}

type uaFamilyTracker struct {
	mu      sync.Mutex
	entries *lru
}

var defaultUAFamily = &uaFamilyTracker{entries: newLRU(envAnomalyMaxKeys)}

// uaFamily 粗粒度 UA 族（不存完整 UA）。
func uaFamily(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case ua == "":
		return "empty"
	case strings.Contains(ua, "curl/") || strings.Contains(ua, "wget") || strings.Contains(ua, "python-requests") ||
		strings.Contains(ua, "go-http-client") || strings.Contains(ua, "httpclient") || strings.Contains(ua, "okhttp"):
		return "script"
	case strings.Contains(ua, "bot") || strings.Contains(ua, "spider") || strings.Contains(ua, "crawler"):
		return "bot"
	case strings.Contains(ua, "edg/") || strings.Contains(ua, "chrome/") || strings.Contains(ua, "firefox/") ||
		strings.Contains(ua, "safari/") || strings.Contains(ua, "msie") || strings.Contains(ua, "trident/"):
		return "browser"
	default:
		return "other"
	}
}

// CheckCredentialUAChange 同凭据 UA 族突变（browser↔script 等）→ OBSERVE。
func CheckCredentialUAChange(ctx *dsctx.RequestContext, r *http.Request, credKey string) {
	if ctx == nil || r == nil || credKey == "" {
		return
	}
	fam := uaFamily(r.Header.Get("User-Agent"))
	prev, changed := defaultUAFamily.observe(credKey, fam)
	if !changed || prev == "" {
		return
	}
	// empty→* 或首次不报；仅族切换时报
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "authentication",
		RuleID:     "auth.credential_ua_change",
		Category:   "OBSERVE",
		Severity:   "MEDIUM",
		Message:    "credential user-agent family changed",
		Evidence:   map[string]string{"from": prev, "to": fam},
		ScoreDelta: 15,
	})
}

func (t *uaFamilyTracker) observe(key, family string) (prev string, changed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if v, ok := t.entries.get(key); ok {
		e := v.(*uaFamilyEntry)
		prev = e.family
		if prev != family {
			changed = true
			e.family = family
		}
		return prev, changed
	}
	t.entries.set(key, &uaFamilyEntry{family: family})
	return "", false
}

// CheckEnvAnomalyStack 同一请求上环境异常信号 ≥2 → 叠加信号（疑似接管），仍 OBSERVE。
// 在其它环境检测之后调用，扫描 ctx.Matches。
func CheckEnvAnomalyStack(ctx *dsctx.RequestContext) {
	if ctx == nil {
		return
	}
	n := 0
	for _, m := range ctx.Matches {
		switch m.RuleID {
		case "auth.credential_ip_spread", "auth.credential_concurrency",
			"auth.credential_unusual_hour", "auth.credential_ua_change",
			"auth.credential_cross_app", "auth.credential_device_spread":
			n++
		}
	}
	if n < 2 {
		return
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "authentication",
		RuleID:     "auth.env_anomaly_stack",
		Category:   "OBSERVE",
		Severity:   "HIGH",
		Message:    "multiple environment anomalies for same credential",
		Evidence:   map[string]string{"env_signal_count": strconv.Itoa(n)},
		ScoreDelta: 20,
	})
}
