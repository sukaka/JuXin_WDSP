package botchallenge

import (
	"encoding/hex"
	"net/http"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/ratelimit"
	"go.uber.org/zap"
)

// service.go Service 主流程：挑战签发（Offer）、通行校验（ValidateClearance）、
// 事件出口与 Cookie 写入。verify 端点处理逻辑见 verify.go；HTML 渲染见 render.go。
//
// B3 挂点接口（请求链接入契约，本阶段不接线）：
//   - Offer(w, r, cc, reason)：PROTECT 判定挑战时调用；写本地 403 挑战页或
//     429/503（fail-closed），发 BOT_CHALLENGE_OFFERED / BOT_STATE_UNAVAILABLE 事件；
//     不反向代理。调用点：CC 之后、API 动态防护之前（任务书 §3.2）。
//   - ServeNamespace(w, r, cc)：保留命名空间分发（verify 之外一律本地 404，
//     错误方法 405）；返回 true = 已处理。全部结局不反向代理。
//   - ValidateClearance(r, cc)：Bot 步骤入口先行校验通行；成功返回 *Clearance
//     （B3 放行本步骤并继续完整后续防护链）；错误按 ErrClearance* 分类
//     （Missing=无通行正常流，Expired/Revoked/Invalid=重新挑战）。
//   - LogObservedOffer(r, cc, reason)：OBSERVE 模式只记录不挑战。

// ---------- 事件 ----------

// emittedFlows clearance_accepted/expired 节流（每 flow 每节点只记一次；有界 LRU
// 防伪造 flow 洪泛撑爆内存）。
type emittedFlows struct {
	m *counters.MemoryMap
}

func newEmittedFlows(maxKeys int) *emittedFlows {
	return &emittedFlows{m: counters.NewMemoryMap(maxKeys)}
}

// mark 首次出现返回 true（MemoryMap.GetOrCreate 仅在缺失时调 factory，锁内判定并发安全）。
func (e *emittedFlows) mark(flowID string) bool {
	if flowID == "" {
		return false
	}
	first := false
	e.m.GetOrCreate(flowID, func() interface{} { first = true; return struct{}{} })
	return first
}

// noteTerminal 终止事实回调（B3：cc.RecordTerminal 非 nil 时调用）。
// 调用纪律：必须在对应结局的事件 emit **之前**——事件挂载的 final_decision
// 由 cc.FinalDecision 供应器取终止后的完整终态。
func noteTerminal(cc CallContext, securityAction string, status int, reasons ...string) {
	if cc.RecordTerminal != nil {
		cc.RecordTerminal(securityAction, status, true, reasons)
	}
}

// emit 事件出口（对齐 guard events.Logger 通道形状；发送失败仅 zap Warn，
// 不阻断请求——与 g.emit 同一纪律）。cc.FinalDecision 非 nil 时挂载
// final_decision 终态快照（B3；供应器在 RecordTerminal 之后取值）。
func (s *Service) emit(r *http.Request, cc CallContext, t events.Type, action string, status int, detail *events.BotDetail) {
	if s.cfg.Sink == nil {
		return
	}
	if detail != nil {
		detail.PolicyVersion = s.cfg.PolicyVersion
		detail.PolicyEpoch = s.policyEpoch()
		detail.Mode = s.cfg.Mode
	}
	ev := events.Event{
		RequestID:     cc.RequestID,
		OccurredAt:    s.now().UTC(),
		ApplicationID: s.cfg.AppID,
		AppCode:       s.cfg.AppCode,
		ClientIP:      cc.ClientIP,
		ConnectionIP:  cc.ConnectionIP,
		Method:        r.Method,
		Path:          r.URL.RequestURI(),
		Proto:         r.Proto,
		GatewayNode:   s.cfg.Node,
		EventType:     t,
		Action:        action,
		Bot:           detail,
	}
	if cc.FinalDecision != nil {
		ev.FinalDecision = cc.FinalDecision()
	}
	if r != nil {
		ev.Domain = r.Host
	}
	if status != 0 {
		ev.ResponseStatus = status
	}
	if err := s.cfg.Sink.Emit(ev); err != nil {
		s.logger.Warn("botchallenge: 事件发送失败（不阻断请求）", zap.String("type", string(t)), zap.Error(err))
	}
}

// ---------- Cookie ----------

// setBotCookie 写 __Host- Cookie（Secure/HttpOnly/SameSite=Lax/Path=/无 Domain——
// __Host- 前缀契约；仅 HTTPS 启用由部署侧保证，此处恒带 Secure）。
func setBotCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	w.Header().Add("Set-Cookie", c.String())
}

// readCookie 读取指定 Cookie（不存在 → 空串）。
func readCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// ---------- 速率 ----------

// rateKey 限速键材料（HashParts 哈希，禁止原始 IP/会话拼键）。
func rateKey(dim string, parts ...string) string {
	all := append([]string{dim}, parts...)
	return dim + ":" + counters.HashParts(all...)
}

// allowRate 三维限速判定（dim = iss/vfy；session 为空跳过会话维）。
// 返回 (allowed, retryAfter, error)；限速器故障 = 依赖不可用（ErrStateUnavailable，
// fail-closed——限速失控则状态洪峰无闸）。
func (s *Service) allowRate(dim, clientIP, sessDigest string) (bool, time.Duration, error) {
	type rule struct {
		key   string
		limit int64
	}
	rules := []rule{}
	if dim == "iss" {
		if sessDigest != "" {
			rules = append(rules, rule{rateKey("iss-sess", sessDigest), s.limits.IssuePerSession})
		}
		rules = append(rules,
			rule{rateKey("iss-ip", clientIP), s.limits.IssuePerIP},
			rule{rateKey("iss-app", s.cfg.AppID), s.limits.IssuePerApp})
	} else {
		if sessDigest != "" {
			rules = append(rules, rule{rateKey("vfy-sess", sessDigest), s.limits.VerifyPerSession})
		}
		rules = append(rules,
			rule{rateKey("vfy-ip", clientIP), s.limits.VerifyPerIP},
			rule{rateKey("vfy-app", s.cfg.AppID), s.limits.VerifyPerApp})
	}
	maxRetry := time.Duration(0)
	for _, rl := range rules {
		ctx, cancel := contextWithOpTimeout()
		res, err := s.cfg.Limiter.Allow(ctx, rl.key, ratelimit.SlidingWindow, rl.limit, rateWindow, 0)
		cancel()
		if err != nil {
			return false, 0, errUnavailable("rate limiter", err)
		}
		if !res.Allowed {
			if res.RetryAfter > maxRetry {
				maxRetry = res.RetryAfter
			}
			return false, maxRetry, nil
		}
	}
	return true, 0, nil
}

// errUnavailable 依赖故障包装（errors.Is → ErrStateUnavailable）。
func errUnavailable(op string, err error) error {
	return &unavailableError{op: op, err: err}
}

type unavailableError struct {
	op  string
	err error
}

func (e *unavailableError) Error() string {
	return ErrStateUnavailable.Error() + " (" + e.op + "): " + e.err.Error()
}
func (e *unavailableError) Unwrap() error { return ErrStateUnavailable }

// ---------- 挑战签发（Offer） ----------

// Offer 签发挑战（B3 挂点；仅 PROTECT 到达——OBSERVE 由 LogObservedOffer 记录）。
// 结局：403 挑战页 / 429（速率）/ 503（容量或依赖故障，Retry-After）；
// 全部本地响应，不反向代理；失败路径绝不设置 clearance。
func (s *Service) Offer(w http.ResponseWriter, r *http.Request, cc CallContext, reason string) {
	now := s.now()

	// 会话：有效 Cookie 复用，否则新签发（256 bit 随机）。
	sid, sessDigest := "", ""
	if v := readCookie(r, SessionCookieName); v != "" {
		if parsed, err := s.parseSession(v); err == nil {
			sid = parsed
			sessDigest = sessionDigest(parsed)
		}
	}
	// sessCookieVal 非空 = 需随响应下发新会话 Cookie（必须在 WriteHeader 之前写入——
	// 每条响应路径（含 429/503）都显式调用 writeSessCookie，不用 defer）。
	sessCookieVal := ""
	if sid == "" {
		var err error
		sid, sessCookieVal, err = s.mintSession()
		if err != nil {
			s.failOffer(w, r, cc, "KEY_UNAVAILABLE", err)
			return
		}
		sessDigest = sessionDigest(sid)
	}
	writeSessCookie := func() {
		if sessCookieVal != "" {
			setBotCookie(w, SessionCookieName, sessCookieVal, s.sessionTTL())
		}
	}

	// 速率上限（会话/真实客户端 IP/应用三维）。
	ok, retry, err := s.allowRate("iss", cc.ClientIP, sessDigest)
	if err != nil {
		writeSessCookie()
		s.failOffer(w, r, cc, "STORE_ERROR", err)
		return
	}
	if !ok {
		retrySec := retryAfterRateLimited
		if retry > 0 && int(retry.Seconds())+1 > retrySec {
			retrySec = int(retry.Seconds()) + 1
		}
		// B3 终止事实：RATE_LIMIT（与 disposition.go 枚举同词；先于事件 emit）
		noteTerminal(cc, "RATE_LIMIT", http.StatusTooManyRequests, "BOT_ISSUE_RATE_LIMITED")
		s.emit(r, cc, events.BotStateUnavailable, "CHALLENGE", http.StatusTooManyRequests,
			&events.BotDetail{Reason: "ISSUE_RATE_LIMITED"})
		writeSessCookie()
		writeStatusPage(w, http.StatusTooManyRequests, retrySec, "请求过于频繁", "安全验证服务繁忙，请稍后重试。", cc.RequestID)
		return
	}

	// 挑战 ID + nonce（crypto/rand，≥128bit）。
	cidRaw := make([]byte, challengeIDBytes)
	nonceRaw := make([]byte, nonceBytes)
	if err := randRead(cidRaw); err != nil {
		writeSessCookie()
		s.failOffer(w, r, cc, "INTERNAL", err)
		return
	}
	if err := randRead(nonceRaw); err != nil {
		writeSessCookie()
		s.failOffer(w, r, cc, "INTERNAL", err)
		return
	}
	challengeID := hex.EncodeToString(cidRaw)
	nonce := hex.EncodeToString(nonceRaw)
	hostDigest := counters.HashParts(normalizeHost(r.Host))

	// 状态写共享 Valkey（容量有界；服务端只存摘要/题目参数/代次/过期/尝试数）。
	st := ChallengeState{
		SessionDigest: sessDigest,
		HostDigest:    hostDigest,
		PolicyEpoch:   s.policyEpoch(),
		Difficulty:    s.cfg.Difficulty,
		Nonce:         nonce,
		ExpiresAt:     now.Add(s.cfg.NonceTTL),
	}
	ok, err = s.cfg.Store.Issue(s.cfg.AppID, challengeID, st, s.cfg.NonceTTL, s.capN)
	if err != nil {
		writeSessCookie()
		s.failOffer(w, r, cc, "STORE_ERROR", err)
		return
	}
	if !ok {
		// B3 终止事实：容量耗尽 503 fail-closed（BLOCK 语义，同 jwt_trust UNAVAILABLE 503 口径）
		noteTerminal(cc, "BLOCK", http.StatusServiceUnavailable, "BOT_STATE_UNAVAILABLE")
		s.emit(r, cc, events.BotStateUnavailable, "CHALLENGE", http.StatusServiceUnavailable,
			&events.BotDetail{Reason: "INFLIGHT_CAP_REACHED"})
		writeSessCookie()
		writeStatusPage(w, http.StatusServiceUnavailable, retryAfterUnavailable, "服务暂不可用", "安全验证容量已达上限，请稍后重试。", cc.RequestID)
		return
	}

	// 渲染挑战页（CSP nonce 每响应随机；Cache-Control no-store；frame-ancestors none）。
	cspRaw := make([]byte, cspNonceBytes)
	if err := randRead(cspRaw); err != nil {
		writeSessCookie()
		s.failOffer(w, r, cc, "INTERNAL", err)
		return
	}
	fl := flowID(challengeID)
	writeSessCookie()
	s.renderChallenge(w, r, challengePageParams{
		ChallengeID: challengeID,
		Nonce:       nonce,
		Difficulty:  s.cfg.Difficulty,
		AppID:       s.cfg.AppID,
		Host:        normalizeHost(r.Host),
		VerifyPath:  VerifyPath,
		BudgetMS:    computeBudgetMS,
		RequestID:   cc.RequestID,
	}, hex.EncodeToString(cspRaw))
	// B3 终止事实：CHALLENGE（403 挑战页，响应来源 GATEWAY 未访问源站；
	// 与 disposition.go DisActionChallenge 同词；先于事件 emit——
	// 挑战完成后的业务请求是新 Request ID，两者经 flow_id 脱敏关联、分开统计）
	noteTerminal(cc, "CHALLENGE", http.StatusForbidden, "BOT_CHALLENGE_OFFERED")
	s.emit(r, cc, events.BotChallengeOffered, "CHALLENGE", http.StatusForbidden,
		&events.BotDetail{Reason: reason, FlowID: fl})
}

// failOffer 签发失败统一出口（503 + Retry-After + state_unavailable 事件；
// PROTECT fail-closed——任务书 §5.4，仅适用于 Bot 步骤）。
func (s *Service) failOffer(w http.ResponseWriter, r *http.Request, cc CallContext, reason string, err error) {
	s.logger.Warn("botchallenge: 挑战签发失败（fail-closed 503）",
		zap.String("reason", reason), zap.Error(err), zap.String("app", s.cfg.AppCode))
	// B3 终止事实：BLOCK（fail-closed 拒绝，同 jwt_trust UNAVAILABLE 503 口径；先于 emit）
	noteTerminal(cc, "BLOCK", http.StatusServiceUnavailable, "BOT_STATE_UNAVAILABLE")
	s.emit(r, cc, events.BotStateUnavailable, "CHALLENGE", http.StatusServiceUnavailable,
		&events.BotDetail{Reason: reason})
	writeStatusPage(w, http.StatusServiceUnavailable, retryAfterUnavailable, "服务暂不可用", "安全验证服务暂时不可用，请稍后重试。", cc.RequestID)
}

// LogObservedOffer OBSERVE 模式记录（不签发、不挑战、不改变请求——B3 调用）。
func (s *Service) LogObservedOffer(r *http.Request, cc CallContext, reason string) {
	s.emit(r, cc, events.BotChallengeOffered, "OBSERVE", 0, &events.BotDetail{Reason: reason})
}

// ---------- 通行校验（ValidateClearance，B3 挂点） ----------

// ValidateClearance 校验请求通行 Cookie（B3 在 Bot 步骤入口调用；PROTECT/OBSERVE 共用）。
// 成功返回 *Clearance 并发 clearance_accepted（每 flow 每节点一次）；
// 失败返回 ErrClearance* 分类错误（Expired/Revoked/Invalid 发节流事件，Missing 静默）。
func (s *Service) ValidateClearance(r *http.Request, cc CallContext) (*Clearance, error) {
	raw := readCookie(r, ClearanceCookieName)
	if raw == "" {
		return nil, ErrClearanceMissing
	}
	now := s.now()
	p, err := s.parseClearance(raw, now)
	flowForThrottle := ""
	if p != nil {
		flowForThrottle = p.Fl
	}
	if err != nil {
		// 过期单独归因（其余签名/结构/key_id 问题统一 Invalid，不区分提示）
		if flowForThrottle == "" {
			flowForThrottle = flowIDFromRawToken(raw)
		}
		if isTokenExpired(raw, now) {
			if s.emitted.mark(flowForThrottle) {
				s.emit(r, cc, events.BotChallengeExpired, "REJECT", 0,
					&events.BotDetail{Reason: "CLEARANCE_EXPIRED", FlowID: flowForThrottle})
			}
			return nil, ErrClearanceExpired
		}
		if s.emitted.mark(flowForThrottle) {
			s.emit(r, cc, events.BotVerifyRejected, "REJECT", 0,
				&events.BotDetail{Reason: "CLEARANCE_INVALID", FlowID: flowForThrottle})
		}
		return nil, ErrClearanceInvalid
	}
	// 绑定校验：应用 / Host / 策略代次（撤销）/ 会话。
	if p.App != s.cfg.AppID || p.Hh != counters.HashParts(normalizeHost(r.Host)) {
		s.emitClearanceBindingRejected(r, cc, p.Fl)
		return nil, ErrClearanceInvalid
	}
	if p.Ep != s.policyEpoch() {
		if s.emitted.mark(p.Fl) {
			s.emit(r, cc, events.BotVerifyRejected, "REJECT", 0,
				&events.BotDetail{Reason: "CLEARANCE_EPOCH_REVOKED", FlowID: p.Fl})
		}
		return nil, ErrClearanceRevoked
	}
	sess := readCookie(r, SessionCookieName)
	if sess == "" {
		return nil, ErrClearanceInvalid
	}
	sid, err := s.parseSession(sess)
	if err != nil || sessionDigest(sid) != p.Sd {
		s.emitClearanceBindingRejected(r, cc, p.Fl)
		return nil, ErrClearanceInvalid
	}
	cl := &Clearance{
		FlowID:    p.Fl,
		SessionID: p.Sd,
		IssuedAt:  time.Unix(p.Iat, 0).UTC(),
		ExpiresAt: time.Unix(p.Exp, 0).UTC(),
		KeyID:     p.Kid,
	}
	if s.emitted.mark(p.Fl) {
		s.emit(r, cc, events.BotClearanceAccepted, "PASS", 0,
			&events.BotDetail{Reason: "CLEARANCE_OK", FlowID: p.Fl, KeyID: p.Kid})
	}
	return cl, nil
}

// emitClearanceBindingRejected 跨应用/Host/会话绑定失败（节流每 flow 一次）。
func (s *Service) emitClearanceBindingRejected(r *http.Request, cc CallContext, flow string) {
	if s.emitted.mark(flow) {
		s.emit(r, cc, events.BotVerifyRejected, "REJECT", 0,
			&events.BotDetail{Reason: "CLEARANCE_BINDING_MISMATCH", FlowID: flow})
	}
}

// flowIDFromRawToken 未验签提取 flow_id（仅用于事件节流键，不作任何信任依据；
// 提取失败返回空串——此时不发节流事件）。
func flowIDFromRawToken(raw string) string {
	var p clearancePayload
	// 仅解码 payload 段（不验签；值只进入有界 LRU，洪泛至多挤占 4096 条）
	parts := splitToken(raw)
	if parts == nil {
		return ""
	}
	if err := decodePayload(parts[1], &p); err != nil {
		return ""
	}
	if len(p.Fl) > 32 {
		return ""
	}
	return p.Fl
}

// isTokenExpired 未验签提取 exp 判定过期（仅用于事件归因；安全判定以验签后为准）。
func isTokenExpired(raw string, now time.Time) bool {
	parts := splitToken(raw)
	if parts == nil {
		return false
	}
	var p clearancePayload
	if err := decodePayload(parts[1], &p); err != nil {
		return false
	}
	return p.Exp != 0 && !now.Before(time.Unix(p.Exp, 0).Add(clockSkew))
}
