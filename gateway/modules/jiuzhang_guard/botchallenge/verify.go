package botchallenge

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"go.uber.org/zap"
)

// verify.go POST /_wdsp/bot/v1/verify 本地端点处理逻辑（任务书 §3.2/§5.1/§5.3）。
//
// 固定协议的本地控制端点：
//   - 仅 POST（其他方法 405 + Allow）；保留命名空间内未知子路径本地 404；
//     全部结局只写本地响应，结构上不可能反向代理（handler 无 next 句柄）；
//   - 正文固定 application/json、8 KiB 上限、尽力读取超时（2s）；
//   - 严格同源 Origin（缺失默认拒绝）+ Host 与会话绑定 + Fetch Metadata 校验；
//   - 结构化错误 400/403/409/429/503（失败绝不设置 clearance）；
//     成功 204 + __Host-wdsp-bot-clearance Cookie。

// verifyRequest 请求体（严格解码——未知字段拒绝；无 difficulty/nonce 字段：
// 难度由服务端状态决定，nonce 只存在服务端状态与签发页，客户端无从降难度/换题）。
type verifyRequest struct {
	ChallengeID string `json:"challenge_id"`
	Solution    string `json:"solution"`
}

// 结构化错误码（线契约；message 为静态文本，不回显任何外部输入）。
const (
	errBodyInvalid      = "BODY_INVALID"
	errOriginRequired   = "ORIGIN_REQUIRED"
	errOriginMismatch   = "ORIGIN_MISMATCH"
	errFetchRejected    = "FETCH_METADATA_REJECTED"
	errSessionInvalid   = "SESSION_INVALID"
	errRateLimited      = "RATE_LIMITED"
	errChallengeGone    = "CHALLENGE_NOT_FOUND" // 未知/已消费（重放）/已清理
	errChallengeExpired = "CHALLENGE_EXPIRED"
	errBindingMismatch  = "BINDING_MISMATCH"
	errBadSolution      = "BAD_SOLUTION"
	errAttemptsExhaust  = "ATTEMPTS_EXHAUSTED"
	errStateUnavailable = "STATE_UNAVAILABLE"
)

// verifyErrorMessages 静态错误文案（不含外部输入；客户端可按 code 本地化）。
var verifyErrorMessages = map[string]string{
	errBodyInvalid:      "请求格式非法",
	errOriginRequired:   "缺少同源 Origin 头",
	errOriginMismatch:   "Origin 与站点不一致",
	errFetchRejected:    "请求来源元数据非法",
	errSessionInvalid:   "验证会话无效，请重新加载页面",
	errRateLimited:      "验证请求过于频繁，请稍后重试",
	errChallengeGone:    "验证挑战不存在或已完成，请重新加载页面",
	errChallengeExpired: "验证挑战已过期，请重新加载页面",
	errBindingMismatch:  "验证上下文不匹配",
	errBadSolution:      "计算结果不正确",
	errAttemptsExhaust:  "验证尝试次数已用尽，请重新加载页面",
	errStateUnavailable: "验证服务暂时不可用，请稍后重试",
}

// ServeNamespace 保留命名空间分发（B3 挂点：路径命中 /_wdsp/bot/v1/ 时调用）。
// 精确 verify 路径 → ServeVerify；其余子路径本地 404；均不反向代理。
// 返回 true = 本请求已由 Bot 端点处理（调用方不得再传递）。
func (s *Service) ServeNamespace(w http.ResponseWriter, r *http.Request, cc CallContext) bool {
	if normalizer.CanonicalPath(r.URL.Path) == VerifyPath {
		s.ServeVerify(w, r, cc)
		return true
	}
	// 未知子路径本地 404（墓碑行为：已关闭应用的旧挑战提交绝不落入业务源站）
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("404 not found"))
	return true
}

// ServeVerify verify 端点处理（固定 POST；成功 204+clearance，失败结构化错误）。
func (s *Service) ServeVerify(w http.ResponseWriter, r *http.Request, cc CallContext) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	// 固定方法（其他 405）
	if r.Method != http.MethodPost {
		h.Set("Allow", http.MethodPost)
		s.writeVerifyError(w, http.StatusMethodNotAllowed, errBodyInvalid)
		return
	}
	// 读取超时（尽力而为：HTTP/2 等不支持 SetReadDeadline 时忽略，8KiB 上限仍是硬边界）
	_ = http.NewResponseController(w).SetReadDeadline(s.now().Add(verifyReadTimeout))
	// 正文类型固定 application/json
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil || mt != "application/json" {
			s.writeVerifyError(w, http.StatusBadRequest, errBodyInvalid)
			return
		}
	}
	// 8 KiB 正文上限 + 严格解码
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxVerifyBodyBytes))
	if err != nil {
		s.writeVerifyError(w, http.StatusBadRequest, errBodyInvalid)
		return
	}
	var req verifyRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		s.writeVerifyError(w, http.StatusBadRequest, errBodyInvalid)
		return
	}
	if !validChallengeID(req.ChallengeID) || !validSolution(req.Solution) {
		s.writeVerifyError(w, http.StatusBadRequest, errBodyInvalid)
		return
	}

	// 来源校验：严格同源 Origin（缺失默认拒绝）+ Fetch Metadata（存在即强校验）。
	if !s.checkOrigin(r) {
		reason := errOriginMismatch
		if r.Header.Get("Origin") == "" {
			reason = errOriginRequired
		}
		s.emitVerifyRejected(r, cc, reason, http.StatusForbidden, "", 0)
		s.writeVerifyError(w, http.StatusForbidden, reason)
		return
	}
	if !checkFetchMetadata(r) {
		s.emitVerifyRejected(r, cc, errFetchRejected, http.StatusForbidden, "", 0)
		s.writeVerifyError(w, http.StatusForbidden, errFetchRejected)
		return
	}

	// 会话 Cookie（签名 + 过期；无效 403）。
	sid := ""
	if v := readCookie(r, SessionCookieName); v != "" {
		sid, _ = s.parseSession(v)
	}
	if sid == "" {
		s.emitVerifyRejected(r, cc, errSessionInvalid, http.StatusForbidden, "", 0)
		s.writeVerifyError(w, http.StatusForbidden, errSessionInvalid)
		return
	}
	sessDigest := sessionDigest(sid)

	// 速率上限（会话/IP/应用三维；限速器故障 fail-closed 503）。
	ok, _, rerr := s.allowRate("vfy", cc.ClientIP, sessDigest)
	if rerr != nil {
		s.failVerifyUnavailable(w, r, cc, "STORE_ERROR", rerr)
		return
	}
	if !ok {
		s.emitVerifyRejected(r, cc, errRateLimited, http.StatusTooManyRequests, "", 0)
		s.writeVerifyErrorRetry(w, http.StatusTooManyRequests, errRateLimited, retryAfterRateLimited)
		return
	}

	// 读取挑战状态（单 Lua 往返；存储故障 503 fail-closed）。
	rd, err := s.cfg.Store.Read(s.cfg.AppID, req.ChallengeID)
	if err != nil {
		s.failVerifyUnavailable(w, r, cc, "STORE_ERROR", err)
		return
	}
	fl := flowID(req.ChallengeID)
	if rd.State == nil {
		if rd.Hint == "EXPIRED" {
			s.emit(r, cc, events.BotChallengeExpired, "REJECT", http.StatusConflict,
				&events.BotDetail{Reason: errChallengeExpired, FlowID: fl})
			s.writeVerifyError(w, http.StatusConflict, errChallengeExpired)
			return
		}
		s.emitVerifyRejected(r, cc, errChallengeGone, http.StatusConflict, fl, 0)
		s.writeVerifyError(w, http.StatusConflict, errChallengeGone)
		return
	}
	st := rd.State

	// 绑定校验：会话摘要 / Host / 策略代次（任一不符 403；跨应用由键作用域隔离）。
	if st.SessionDigest != sessDigest ||
		st.HostDigest != counters.HashParts(normalizeHost(r.Host)) ||
		st.PolicyEpoch != s.policyEpoch() {
		s.emitVerifyRejected(r, cc, errBindingMismatch, http.StatusForbidden, fl, 0)
		s.writeVerifyError(w, http.StatusForbidden, errBindingMismatch)
		return
	}

	// PoW 判定（标准 SHA-256；difficulty 取服务端状态——客户端无法降难度）。
	pass, err := CheckSolution(req.ChallengeID, st.Nonce, s.cfg.AppID, r.Host, req.Solution, st.Difficulty)
	if err != nil {
		s.writeVerifyError(w, http.StatusBadRequest, errBodyInvalid)
		return
	}
	if !pass {
		// 错误解答原子记账（达 max_attempts 作废；绑定字段不符 = 状态被改写，不记账）
		fr, ferr := s.cfg.Store.FailAttempt(s.cfg.AppID, req.ChallengeID, st, s.cfg.MaxAttempts)
		if ferr != nil {
			s.failVerifyUnavailable(w, r, cc, "STORE_ERROR", ferr)
			return
		}
		switch fr.Reason {
		case "ATTEMPT":
			s.emitVerifyRejected(r, cc, errBadSolution, http.StatusForbidden, fl, fr.Attempts)
			s.writeVerifyError(w, http.StatusForbidden, errBadSolution)
		case "EXHAUSTED":
			s.emitVerifyRejected(r, cc, errAttemptsExhaust, http.StatusConflict, fl, fr.Attempts)
			s.writeVerifyError(w, http.StatusConflict, errAttemptsExhaust)
		case "EXPIRED":
			s.emit(r, cc, events.BotChallengeExpired, "REJECT", http.StatusConflict,
				&events.BotDetail{Reason: errChallengeExpired, FlowID: fl})
			s.writeVerifyError(w, http.StatusConflict, errChallengeExpired)
		default: // NOT_FOUND / MISMATCH
			s.emitVerifyRejected(r, cc, errChallengeGone, http.StatusConflict, fl, 0)
			s.writeVerifyError(w, http.StatusConflict, errChallengeGone)
		}
		return
	}

	// 原子比较并消费（跨节点/并发至多一次成功；Lua 内重查绑定/过期/尝试数）。
	cr, err := s.cfg.Store.Consume(s.cfg.AppID, req.ChallengeID, st, s.cfg.MaxAttempts)
	if err != nil {
		s.failVerifyUnavailable(w, r, cc, "STORE_ERROR", err)
		return
	}
	if !cr.Consumed {
		if cr.Reason == "EXPIRED" {
			s.emit(r, cc, events.BotChallengeExpired, "REJECT", http.StatusConflict,
				&events.BotDetail{Reason: errChallengeExpired, FlowID: fl})
			s.writeVerifyError(w, http.StatusConflict, errChallengeExpired)
			return
		}
		s.emitVerifyRejected(r, cc, errChallengeGone, http.StatusConflict, fl, 0)
		s.writeVerifyError(w, http.StatusConflict, errChallengeGone)
		return
	}

	// 签发通行（密钥不可用 503，绝不静默放行；失败绝不设置 clearance）。
	clearance, err := s.issueClearance(st.HostDigest, st.SessionDigest, fl, s.now())
	if err != nil {
		s.failVerifyUnavailable(w, r, cc, "KEY_UNAVAILABLE", err)
		return
	}
	setBotCookie(w, ClearanceCookieName, clearance, s.cfg.ClearanceTTL)
	s.emit(r, cc, events.BotVerifySuccess, "PASS", http.StatusNoContent,
		&events.BotDetail{Reason: "VERIFY_OK", FlowID: fl, Attempts: st.Attempts + 1, KeyID: s.signingKeyID()})
	w.WriteHeader(http.StatusNoContent)
}

// signingKeyID 当前签名 key_id（事件溯源用；非密钥材料）。
func (s *Service) signingKeyID() string {
	if k, ok := s.signingKey(); ok {
		return k.ID
	}
	return ""
}

// checkOrigin 严格同源校验（任务书 §5.3：缺 Origin 默认拒绝；scheme 必须 https，
// host 与请求 Host 精确匹配——不开放跨域，不写浏览器例外）。
func (s *Service) checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// checkFetchMetadata Fetch Metadata 校验（与一次性 nonce + 会话绑定联合；
// Sec-Fetch-Site 存在时必须为 same-origin/same-site，cross-site 拒绝；
// 缺失容忍（旧浏览器）——Origin 强制校验仍是主闸）。
func checkFetchMetadata(r *http.Request) bool {
	switch site := r.Header.Get("Sec-Fetch-Site"); site {
	case "", "same-origin", "same-site":
		return true
	default:
		return false
	}
}

// emitVerifyRejected verify_rejected 事件（reason 为结构化错误码）。
func (s *Service) emitVerifyRejected(r *http.Request, cc CallContext, reason string, status int, flow string, attempts int) {
	s.emit(r, cc, events.BotVerifyRejected, "REJECT", status,
		&events.BotDetail{Reason: reason, FlowID: flow, Attempts: attempts})
}

// failVerifyUnavailable 依赖故障统一出口（503 + Retry-After + state_unavailable 事件；
// PROTECT fail-closed 例外——任务书 §5.4）。
func (s *Service) failVerifyUnavailable(w http.ResponseWriter, r *http.Request, cc CallContext, reason string, err error) {
	s.logger.Warn("botchallenge: verify 依赖不可用（fail-closed 503）",
		zap.String("reason", reason), zap.Error(err), zap.String("app", s.cfg.AppCode))
	s.emit(r, cc, events.BotStateUnavailable, "REJECT", http.StatusServiceUnavailable,
		&events.BotDetail{Reason: reason})
	s.writeVerifyErrorRetry(w, http.StatusServiceUnavailable, errStateUnavailable, retryAfterUnavailable)
}

// writeVerifyError 结构化错误（JSON；静态文案；Cache-Control no-store 已在入口设置；
// 任何失败路径都不设置 clearance Cookie）。
func (s *Service) writeVerifyError(w http.ResponseWriter, status int, code string) {
	s.writeVerifyErrorRetry(w, status, code, 0)
}

func (s *Service) writeVerifyErrorRetry(w http.ResponseWriter, status int, code string, retryAfter int) {
	msg := verifyErrorMessages[code]
	if msg == "" {
		msg = "验证失败"
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	if retryAfter > 0 {
		h.Set("Retry-After", strconv.Itoa(retryAfter))
	}
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]string{"error": code, "message": msg})
	_, _ = w.Write(body)
}

// writeStatusPage 挑战签发失败的浏览器可读页（静态内容；RequestID HTML 转义；
// CSP 禁一切外部资源——与挑战页同一缓存/嵌入纪律）。
func writeStatusPage(w http.ResponseWriter, status int, retryAfter int, title, msg, requestID string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Frame-Options", "DENY")
	if retryAfter > 0 {
		h.Set("Retry-After", strconv.Itoa(retryAfter))
	}
	w.WriteHeader(status)
	writeChallengeErrorHTML(w, title, msg, requestID)
}

// validChallengeID 挑战 ID 词形（128bit hex）。
func validChallengeID(s string) bool {
	if len(s) != challengeIDBytes*2 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
