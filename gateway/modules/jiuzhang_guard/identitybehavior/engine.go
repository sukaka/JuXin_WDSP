package identitybehavior

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"go.uber.org/zap"
)

// Options 引擎装配参数（Guard 实例级固定值，事件归属用）。
type Options struct {
	AppID       string
	AppCode     string
	GatewayNode string
	Salt        string // identity_salt（HMAC 盐；空 = 未加盐固定域分隔前缀，与 detectors.Fingerprint 同语义）
	Logger      *zap.Logger
	// SignalSink 侦察信号汇聚回调（WDSP 阶段3 Risk Engine 挂点；nil = 无汇聚，零行为变化）。
	// 在 End 评估产出全部信号后调用（含 HEADLESS-001）；回调内任何异常由 End 的 recover 兜底。
	SignalSink func(identityKey string, signals []Signal)
}

// headlessSignalThrottle HEADLESS-001 信号节流（60s / identity，防每请求重复计分）。
const headlessSignalThrottle = time.Minute

// Engine 身份引擎 + 行为检测 + 侦察检测的请求链挂点（本阶段纯 OBSERVE）。
// Begin 解析身份并包装 ResponseWriter 记状态码；End 在请求收束时原子记账、
// 评估信号并按节流发事件——任何失败 fail-open（zap 告警），请求永不因引擎失败而失败。
type Engine struct {
	cfg    *Config
	store  Store
	events *EventLogger
	opts   Options
	logger *zap.Logger
	now    func() time.Time

	signalSink func(identityKey string, signals []Signal)
	headlessMu sync.Mutex
	headless   *lru // identity -> 上次 HEADLESS 信号时间（60s 节流）
}

// degradationMetricsSource 是存储实现可选提供的低基数降级快照能力。
// 内存存储不实现该能力，调用方应将零值视为“无远端降级指标”。
type degradationMetricsSource interface {
	DegradationMetrics() ValkeyDegradationMetrics
}

// NewEngine 装配引擎（cfg 为 Compile 产物；store/events 由装配层按配置选定实现）。
func NewEngine(cfg *Config, store Store, events *EventLogger, opts Options) *Engine {
	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Engine{
		cfg:        cfg,
		store:      store,
		events:     events,
		opts:       opts,
		logger:     logger,
		now:        time.Now,
		signalSink: opts.SignalSink,
		headless:   newLRU(throttleCapLRU),
	}
}

// DegradationMetrics 返回底层远端存储的降级计数快照。
// 这是供装配层或运维采集器读取的 adapter hook，不创建额外的 HTTP/API 出口；
// 未接入支持该能力的存储时返回零值。
func (e *Engine) DegradationMetrics() ValkeyDegradationMetrics {
	if e == nil || e.store == nil {
		return ValkeyDegradationMetrics{}
	}
	source, ok := e.store.(degradationMetricsSource)
	if !ok {
		return ValkeyDegradationMetrics{}
	}
	return source.DegradationMetrics()
}

// throttleCapLRU HEADLESS 信号节流 LRU 容量（identity 键量级与内存存储一致）。
const throttleCapLRU = 50000

// SetSignalSink 设置侦察信号汇聚回调（阶段3 Risk Engine 装配期一次性注入；nil = 无汇聚）。
func (e *Engine) SetSignalSink(sink func(identityKey string, signals []Signal)) {
	if e == nil {
		return
	}
	e.signalSink = sink
}

// Whitelisted 身份行为白名单判定（IP CIDR / UA 子串；供风险策略处置等外部跳过点复用同一口径）。
func (e *Engine) Whitelisted(ip netip.Addr, ua string) bool {
	return e != nil && e.cfg != nil && e.cfg.Whitelisted(ip, ua)
}

// identityResultKey 请求上下文中的身份解析结果键（Begin 写入，供统一 RequestContext 桥接）。
type identityResultKey struct{}

// IdentityFrom 取请求上下文身份（identity_behavior 未启用或白名单跳过时为 nil）。
func IdentityFrom(ctx context.Context) *Identity {
	v, _ := ctx.Value(identityResultKey{}).(*Identity)
	return v
}

// Observation 单请求观测上下文（Begin 产出，End 消费；请求级数据在 Begin 一次性捕获——
// End 不依赖下游可能改写的请求状态）。
type Observation struct {
	identity        *Identity
	requestID       string
	domain          string
	method          string
	path            string
	paramSig        string
	accountKey      string
	objectKey       string
	sensitivePrefix string // 命中的敏感路径前缀（空 = 未命中）
	writer          *statusWriter
}

// Begin 请求入口：白名单命中返回 (w, nil) 零开销；否则解析身份写入请求上下文、
// 包装 ResponseWriter 记状态码，返回观测上下文（调用方 defer End）。
func (e *Engine) Begin(w http.ResponseWriter, r *http.Request, res clientip.Result) (http.ResponseWriter, *Observation) {
	if e == nil || e.cfg == nil {
		return w, nil
	}
	if e.cfg.Whitelisted(res.ClientIP, r.Header.Get("User-Agent")) {
		return w, nil
	}
	id := ResolveIdentity(r, e.opts.Salt, res.ClientIP.String())
	*r = *r.WithContext(context.WithValue(r.Context(), identityResultKey{}, id))
	sw := &statusWriter{ResponseWriter: w}
	accountKey, objectKey := "", ""
	if !enumerationExcludedPath(r.URL.Path) {
		// 分页字段不整请求跳过（MED-1：「&page=1 即免疫枚举检测」一键绕过）——
		// 剔除分页字段后照常提取账号/对象标识，翻页本身的变化不计入标识轮换
		idQuery := identifierQuery(r.URL.Query())
		accountKey = identifierKey(idQuery, e.cfg.AccountIdentifierFields)
		objectKey = identifierKey(idQuery, e.cfg.ObjectIdentifierFields)
	}
	obs := &Observation{
		identity:        id,
		requestID:       r.Header.Get("X-Request-Id"),
		domain:          stripPort(r.Host),
		method:          r.Method,
		path:            r.URL.Path,
		paramSig:        ParamSignature(r.URL.Query()),
		accountKey:      accountKey,
		objectKey:       objectKey,
		sensitivePrefix: e.cfg.SensitivePathPrefix(r.URL.Path),
		writer:          sw,
	}
	return sw, obs
}

// End 请求收束：读状态码（wrapper 未采集到时从返回错误链兜底，见下）→ Store.Observe
// 原子记账 → 阈值评估 → 发事件（按节流）。
// panic 恢复 + zap Error（fail-open）；存储/事件失败仅告警，请求不受影响。
//
// chainErr 为防护链返回错误（serveGuard 命名返回值）：前置拦截（人工/自动临时封禁、
// IP deny、risk BLOCK、Coraza 中断）经 caddyhttp.Error 返回时响应在 statusWriter 链
// 之外写出，obs.writer.status 恒 0——与 accesslog.go 同一口径从错误链取 HandlerError
// 状态码兜底，避免被拦截请求全部 status=0 入账。
func (e *Engine) End(r *http.Request, obs *Observation, chainErr error) {
	defer func() {
		if rec := recover(); rec != nil {
			e.logger.Error("identitybehavior: panic in end (fail-open)",
				zap.Any("panic", rec), zap.String("path", obsPath(obs)))
		}
	}()
	if e == nil || obs == nil || obs.identity == nil {
		return
	}
	status := obs.writer.status
	if status == 0 && chainErr != nil {
		var he caddyhttp.HandlerError
		if errors.As(chainErr, &he) {
			status = he.StatusCode
		}
	}
	snap, err := e.store.Observe(ObserveInput{
		IdentityKey:    obs.identity.Key,
		Method:         obs.method,
		URI:            obs.path,
		Status:         status,
		ParamSignature: obs.paramSig,
		SensitivePath:  obs.sensitivePrefix != "",
		AccountKey:     obs.accountKey,
		ObjectKey:      obs.objectKey,
		At:             time.Now().UTC(),
	})
	if err != nil {
		// 存储实现内部已 fail-open，到达此处为防御性兜底（如实告警，不静默）
		e.logger.Warn("identitybehavior: store observe failed (fail-open)",
			zap.Error(err), zap.String("path", obs.path))
		return
	}
	snap.IdentityConfidence = obs.identity.Confidence
	base := e.baseRecord(obs)
	e.events.EmitIdentityObservation(base, obs.identity.Credentials)
	e.events.EmitBehaviorSnapshot(base, snap)
	sigs := EvaluateRecon(e.cfg, snap, obs.sensitivePrefix)
	if sig, ok := e.evaluateHeadless(obs); ok {
		sigs = append(sigs, sig)
	}
	for _, sig := range sigs {
		e.events.EmitReconSignal(base, sig)
	}
	// 阶段3 Risk Engine：信号汇聚身份风险累加器（sink 由装配层注入；nil = 无汇聚零变化）；
	// H-08：对请求携带的全部候选凭据键一并入账，防附加假 Authorization 绕过 X-API-Key/Cookie 风险累计。
	if e.signalSink != nil && len(sigs) > 0 {
		for _, key := range obs.identity.CandidateKeys(e.opts.Salt) {
			e.signalSink(key, sigs)
		}
	}
}

// evaluateHeadless HEADLESS-001（阶段3 新增第 8 条规则）：UA 含 headless 标记
// （与 bot 分类复用同一词表项 headlessUAMarker）→ HEADLESS 信号。60s / identity 节流
// （防每请求重复计分）；分值走 scores 表（默认 10，显式 0 = 规则关闭）。
func (e *Engine) evaluateHeadless(obs *Observation) (Signal, bool) {
	if !e.cfg.active(SignalHeadless) {
		return Signal{}, false
	}
	if !strings.Contains(strings.ToLower(obs.identity.UserAgent), headlessUAMarker) {
		return Signal{}, false
	}
	now := e.now().UTC()
	e.headlessMu.Lock()
	defer e.headlessMu.Unlock()
	if v, ok := e.headless.get(obs.identity.Key); ok {
		if now.Sub(v.(time.Time)) < headlessSignalThrottle {
			return Signal{}, false
		}
	}
	e.headless.set(obs.identity.Key, now)
	return Signal{
		RuleCode:    RuleHeadless,
		RuleVersion: RuleVersion,
		Signal:      SignalHeadless,
		ScoreDelta:  e.cfg.score(SignalHeadless),
		Mode:        e.cfg.Mode,
		Reason:      "user-agent contains headless marker",
		Window:      "request",
		Metadata:    map[string]any{"ua_marker": headlessUAMarker},
	}, true
}

// baseRecord 构建事件公共字段（应用归属来自装配参数；身份字段来自解析结果）。
func (e *Engine) baseRecord(obs *Observation) CommonRecord {
	id := obs.identity
	return CommonRecord{
		RequestID:          obs.requestID,
		OccurredAt:         time.Now().UTC(),
		AppID:              e.opts.AppID,
		AppCode:            e.opts.AppCode,
		Domain:             obs.domain,
		Method:             obs.method,
		Path:               obs.path,
		IdentityKey:        id.Key,
		IdentityType:       id.Type,
		IdentityConfidence: id.Confidence,
		IdentityEvidence:   append([]string(nil), id.Evidence...),
		ClientIP:           id.ClientIP,
		UserAgent:          id.UserAgent,
		TLSFingerprint:     id.TLSFingerprint,
		BrowserFingerprint: id.BrowserFingerprint,
	}
}

// Close 关闭事件记录器与存储（Valkey 共享连接不在此关闭——归共享引擎所有）。
// 幂等且不置 nil 字段（LOW-G4）：配置重载 Cleanup 与在途请求并发，End 无锁读
// e.events/e.store，置 nil 构成数据竞态并可 nil 解引用；关闭后在途写入按 fail-open
// 告警处理（EventLogger 写已关闭文件仅 Warn，内存/Valkey Store 的 Close 为 no-op）。
func (e *Engine) Close() error {
	var firstErr error
	if e.events != nil {
		if err := e.events.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if e.store != nil {
		if err := e.store.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func obsPath(obs *Observation) string {
	if obs == nil {
		return ""
	}
	return obs.path
}

// stripPort 取 Host 去端口（域名归属；仅当冒号后全为数字才按端口截断，防 IPv6 误截）。
func stripPort(host string) string {
	if i := strings.LastIndex(host, ":"); i > 0 {
		if _, err := strconv.Atoi(host[i+1:]); err == nil {
			host = host[:i]
		}
	}
	return strings.ToLower(host)
}

// statusWriter ResponseWriter 包装：仅记首个最终状态码（1xx 信息响应不算），
// 其余全部透传；Unwrap/Flush/Hijack 保证 ResponseController 与 WebSocket 升级可用
// （与 accesslog captureResponseWriter 同一透传纪律）。
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 && (code < 100 || code >= 200) {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

// Flush 透传底层 Flusher（SSE/流式响应依赖；Flush 隐式提交 200）。
func (w *statusWriter) Flush() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap 返回底层 writer（http.ResponseController 依赖）。
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack 透传连接劫持（WebSocket 升级需要；底层不支持时如实报错）。
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying writer does not support hijacking")
	}
	return h.Hijack()
}
