// apia2a.go Phase 9C-1 A2A（Agent-to-Agent）协议安全与 AgBOM 资产发现在 jiuzhang_guard 的挂点实现：
//   - 配置段 api_a2a_policy 严格解码（DisallowUnknownFields）+ 全量校验，fail-closed 拒载；
//   - 未配置或 mode==OFF 时请求链路零开销直通；
//   - 请求阶段在 serveNext（JWT 强制处置之后）执行调用方白名单、RFC 8693 委派深度/作用域衰减、
//     递归循环熔断与 Lethal Trifecta 污点阻断，不经白名单/L7 allow 绕过；
//   - 响应阶段对 GET /.well-known/agent.json 与 /.well-known/agent-card.json 挂接零阻塞非缓冲
//     tee 窥视器（<=256KiB 未压缩 2xx JSON），提取并脱敏 Agent Card，经有界 LRU 去重后上报
//     A2A_AGENT_CARD_DISCOVERED 事件；
//   - 与 MCP 工具调用联动：MCP CONFIDENTIAL 工具读取写入 A2A Lethal Trifecta 污点追踪器，
//     阻断后续跨协议外发动作。
package jiuzhang_guard

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/a2aguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/mcpguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"go.uber.org/zap"
)

func (g *Guard) validateA2APolicy() error {
	if len(g.APIA2APolicy) == 0 {
		return nil
	}
	_, err := a2aguard.ParseAndValidatePolicy(g.APIA2APolicy)
	return err
}

func (g *Guard) assembleA2A() error {
	if len(g.APIA2APolicy) == 0 {
		g.apiA2A = nil
		return nil
	}
	pol, err := a2aguard.ParseAndValidatePolicy(g.APIA2APolicy)
	if err != nil {
		return err
	}
	if pol.Mode == a2aguard.ModeOff {
		g.apiA2A = nil
		return nil
	}
	eng, err := a2aguard.NewEngine(pol, a2aguard.EngineOptions{})
	if err != nil {
		return err
	}
	g.apiA2A = eng
	if g.logger != nil {
		g.logger.Info("a2a security policy loaded",
			zap.String("app_id", pol.ApplicationID),
			zap.String("mode", pol.Mode),
			zap.Int("policy_version", pol.Version),
			zap.Bool("card_discovery_enabled", pol.CardDiscoveryEnabled),
			zap.Int("path_prefixes", len(pol.A2APathPrefixes)),
			zap.Int("allowed_caller_agents", len(pol.AllowedCallerAgents)),
			zap.Int("max_delegation_depth", pol.MaxDelegationDepth),
			zap.Bool("enforce_scope_attenuation", pol.EnforceScopeAttenuation),
			zap.Int("loop_window_seconds", pol.LoopWindowSeconds),
			zap.Int("max_calls_per_task_window", pol.MaxCallsPerTaskWindow),
			zap.Bool("lethal_trifecta_enabled", pol.LethalTrifectaEnabled))
	}
	return nil
}

// a2aCallerKey 派生跨 REST/MCP/A2A 一致的调用主体/会话追踪键（不含凭据明文）。
func (g *Guard) a2aCallerKey(r *http.Request) string {
	if jwtRes, ok := jwtResultFrom(r.Context()); ok && jwtRes.Status == jwtverify.StatusVerified {
		if jwtRes.VerifiedPrincipalID != "" {
			return "jwt:" + jwtRes.VerifiedPrincipalID
		}
		if jwtRes.VerifiedAZP != "" {
			return "azp:" + jwtRes.VerifiedAZP
		}
	}
	if cred := detectors.CredentialKey(r, g.IdentitySalt); cred != "" {
		return cred
	}
	if sess := strings.TrimSpace(r.Header.Get("Mcp-Session-Id")); sess != "" {
		return "mcpsess:" + detectors.Fingerprint(g.IdentitySalt, "a2a-mcp-sess:"+sess)
	}
	if cres, ok := clientIPResultFrom(r.Context()); ok && cres.ClientIP.IsValid() {
		return "ip:" + cres.ClientIP.String()
	}
	if addr, err := clientip.ConnectionIP(r); err == nil && addr.IsValid() {
		return "ip:" + addr.String()
	}
	return ""
}

// peekA2ABody 有界读取 A2A POST 请求体（<=256KiB）并无损还原 r.Body 给下游管线与源站。
func peekA2ABody(r *http.Request) []byte {
	if r == nil || r.Body == nil || r.Method != http.MethodPost {
		return nil
	}
	if r.ContentLength > a2aguard.MaxJSONRPCBodyBytes {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, int64(a2aguard.MaxJSONRPCBodyBytes)+1))
	if err != nil {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), r.Body))
		return nil
	}
	if len(b) > a2aguard.MaxJSONRPCBodyBytes {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), r.Body))
		return nil
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(b))
	return b
}

// enforceA2ARequest 在 serveNext（JWT 强制处置之后）执行 A2A 请求阶段检测与处置。
func (g *Guard) enforceA2ARequest(w http.ResponseWriter, r *http.Request) (bool, error) {
	if g.apiA2A == nil {
		return false, nil
	}
	var body []byte
	if r.Method == http.MethodPost && g.apiA2A.MatchA2APath(r.URL.Path) {
		body = peekA2ABody(r)
	}
	var jwtPtr *jwtverify.VerificationResult
	if jwtRes, ok := jwtResultFrom(r.Context()); ok {
		cp := jwtRes
		jwtPtr = &cp
	}
	dec := g.apiA2A.EvaluateRequest(a2aguard.EvalInput{
		AppID:         g.AppID,
		Method:        r.Method,
		Path:          r.URL.Path,
		Body:          body,
		HeaderAgentID: r.Header.Get("X-A2A-Agent-ID"),
		CallerKey:     g.a2aCallerKey(r),
		JWT:           jwtPtr,
	})
	if !dec.Matched {
		return false, nil
	}
	return g.handleA2ADecision(w, r, dec)
}

// observeAndCheckMCPForA2A 将允许放行的 MCP CONFIDENTIAL 工具调用馈入 A2A Lethal Trifecta 污点追踪器，
// 并在 MCP 工具本身命中 external_egress_patterns 且主体已受污染时执行跨协议 Lethal Trifecta 处置。
func (g *Guard) observeAndCheckMCPForA2A(w http.ResponseWriter, r *http.Request, ctx *dsctx.RequestContext) (bool, error) {
	if g.apiA2A == nil || ctx == nil {
		return false, nil
	}
	call := mcpguard.CallFromContext(ctx)
	if call == nil || call.Tool == nil {
		return false, nil
	}
	callerKey := g.a2aCallerKey(r)
	if callerKey == "" {
		return false, nil
	}
	if call.Tool.DataClassification == mcpguard.ClassificationConfidential {
		g.apiA2A.RecordConfidentialTaint(g.AppID, callerKey, "mcp:confidential:"+call.Tool.Name)
	} else if pat, hit := g.apiA2A.MatchesConfidentialPattern(call.Tool.Name); hit {
		g.apiA2A.RecordConfidentialTaint(g.AppID, callerKey, "mcp:"+pat)
	}

	var jwtPtr *jwtverify.VerificationResult
	if jwtRes, ok := jwtResultFrom(r.Context()); ok {
		cp := jwtRes
		jwtPtr = &cp
	}
	dec := g.apiA2A.CheckExternalEgress(g.AppID, callerKey, "tools/call", call.Tool.Name, jwtPtr, r.Header.Get("X-A2A-Agent-ID"))
	if !dec.Matched {
		return false, nil
	}
	dec.IsJSONRPC = true
	dec.RPCIDRaw = mcpRequestIDRaw(ctx)
	return g.handleA2ADecision(w, r, dec)
}

func (g *Guard) handleA2ADecision(w http.ResponseWriter, r *http.Request, dec a2aguard.EvalDecision) (bool, error) {
	pol := g.apiA2A.Policy()
	dispo := DispositionFrom(r.Context())
	method := dec.RPCMethod
	if method == "" {
		method = r.Method
	}
	ev := g.a2aEventBase(r, &events.A2ADetail{
		PolicyVersion:   pol.Version,
		Mode:            pol.Mode,
		Method:          method,
		AgentName:       dec.AgentName,
		DelegationDepth: dec.DelegationDepth,
		RuleID:          dec.RuleID,
		ActionTaken:     dec.ActionTaken,
		Reason:          dec.Reason,
	})
	if !dec.Block {
		dispo.RecordStep(ExecutorAPI, StepObserved, "a2a:"+dec.RuleID)
		g.emit(ev, events.A2AObserved, "OBSERVE", 0)
		return false, nil
	}

	reqID := ev.RequestID
	if dec.IsJSONRPC {
		g.writeA2AJSONRPCError(w, reqID, dec)
	} else {
		g.writeA2ABlockedJSON(w, reqID, dec)
	}
	disAction := DisActionBlock
	if dec.HTTPStatus == http.StatusTooManyRequests {
		disAction = DisActionRateLimit
	}
	dispo.RecordTerminal(ExecutorAPI, disAction, dec.HTTPStatus, true,
		[]string{strings.ToUpper(strings.ReplaceAll(dec.RuleID, ".", "_"))},
		[]string{"a2aguard:" + dec.RuleID})
	ev.FinalDecision = dispo.JSON()
	g.emit(ev, events.Type(dec.EventType), "BLOCK", dec.HTTPStatus)
	accessLogAnnotate(r.Context(), wafActionBlock)
	return true, nil
}

func (g *Guard) a2aEventBase(r *http.Request, detail *events.A2ADetail) events.Event {
	reqID := r.Header.Get("X-Request-Id")
	if reqID == "" {
		reqID = r.Header.Get("X-Jiuzhang-Request-ID")
	}
	ev := events.Event{
		RequestID:     reqID,
		OccurredAt:    time.Now().UTC(),
		ApplicationID: g.AppID,
		AppCode:       g.AppCode,
		Domain:        r.Host,
		Method:        r.Method,
		Path:          r.URL.RequestURI(),
		Proto:         r.Proto,
		GatewayNode:   g.GatewayNode,
		A2A:           detail,
	}
	if cres, ok := clientIPResultFrom(r.Context()); ok {
		ev.ClientIP = cres.ClientIP.String()
		ev.ConnectionIP = cres.ConnectionIP.String()
		ev.ClientIPSource = string(cres.Source)
		ev.TrustedProxyUsed = cres.TrustedProxyUsed
		ev.ForwardedChainSummary = cres.ChainSummary
	} else if addr, err := clientip.ConnectionIP(r); err == nil && addr.IsValid() {
		ev.ClientIP = addr.String()
		ev.ConnectionIP = addr.String()
	}
	return ev
}

var a2aErrorMessages = map[int]string{
	a2aguard.CodeLoopKilled:        "a2a recursive call loop limit exceeded",
	a2aguard.CodeLethalTrifecta:    "a2a request blocked by lethal trifecta protection",
	a2aguard.CodeCallerAgentDenied: "a2a caller agent not authorized",
	a2aguard.CodeDelegationDepth:   "a2a delegation chain depth exceeded",
	a2aguard.CodeDelegationScope:   "a2a delegation scope escalation rejected",
}

func (g *Guard) writeA2AJSONRPCError(w http.ResponseWriter, requestID string, dec a2aguard.EvalDecision) {
	msg, ok := a2aErrorMessages[dec.JSONRPCCode]
	if !ok {
		msg = "a2a request rejected by protection policy"
	}
	status := dec.HTTPStatus
	if status != http.StatusForbidden && status != http.StatusTooManyRequests {
		status = http.StatusForbidden
	}
	idRaw := dec.RPCIDRaw
	if idRaw == "" {
		idRaw = "null"
	}
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	if status == http.StatusTooManyRequests && g.apiA2A != nil {
		h.Set("Retry-After", strconv.Itoa(g.apiA2A.Policy().LoopWindowSeconds))
	}
	body := []byte(`{"jsonrpc":"2.0","id":` + idRaw +
		`,"error":{"code":` + strconv.Itoa(dec.JSONRPCCode) +
		`,"message":` + strconv.Quote(msg) +
		`,"data":{"source":"jiuzhang-wdsp","rule_id":` + strconv.Quote(dec.RuleID) +
		`,"request_id":` + strconv.Quote(requestID) + `}}}`)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil && g.logger != nil {
		g.logger.Warn("a2a json-rpc error response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}

func (g *Guard) writeA2ABlockedJSON(w http.ResponseWriter, requestID string, dec a2aguard.EvalDecision) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	body, _ := json.Marshal(map[string]string{
		"code":       "A2A_LETHAL_TRIFECTA",
		"message":    "a2a request blocked by lethal trifecta protection",
		"rule_id":    dec.RuleID,
		"request_id": requestID,
	})
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write(body); err != nil && g.logger != nil {
		g.logger.Warn("a2a blocked json response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}

// wrapA2AAgentCardResponse 仅对 GET /.well-known/agent.json 与 /.well-known/agent-card.json
// 挂接非缓冲 tee 窥视器（<=256KiB 未压缩 2xx JSON），不延迟不阻塞正常响应。
func (g *Guard) wrapA2AAgentCardResponse(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, *a2aAgentCardSniffer) {
	if g.apiA2A == nil || !g.apiA2A.ShouldObserveAgentCard(r.Method, r.URL.Path) {
		return w, nil
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	fallbackURL := ""
	if r.Host != "" {
		fallbackURL = scheme + "://" + r.Host + r.URL.Path
	}
	s := &a2aAgentCardSniffer{
		ResponseWriter: w,
		guard:          g,
		req:            r,
		fallbackURL:    fallbackURL,
	}
	return s, s
}

// a2aAgentCardSniffer 轻量非缓冲 tee 响应窥视器（最多复制 256KiB+1 字节，不延迟响应写出）。
type a2aAgentCardSniffer struct {
	http.ResponseWriter
	guard           *Guard
	req             *http.Request
	fallbackURL     string
	status          int
	contentType     string
	contentEncoding string
	oversized       bool
	buf             bytes.Buffer
}

func (s *a2aAgentCardSniffer) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		s.ResponseWriter.WriteHeader(code)
		return
	}
	if s.status == 0 {
		s.status = code
		s.captureHeaders()
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *a2aAgentCardSniffer) Write(p []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
		s.captureHeaders()
	}
	if !s.oversized && a2aguard.IsUncompressedJSONResponse(s.status, s.contentType, s.contentEncoding) {
		if s.buf.Len()+len(p) > a2aguard.MaxAgentCardBytes {
			s.oversized = true
			s.buf.Reset()
		} else {
			_, _ = s.buf.Write(p)
		}
	}
	return s.ResponseWriter.Write(p)
}

func (s *a2aAgentCardSniffer) captureHeaders() {
	h := s.ResponseWriter.Header()
	s.contentType = h.Get("Content-Type")
	s.contentEncoding = h.Get("Content-Encoding")
}

func (s *a2aAgentCardSniffer) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
		return
	}
	_ = http.NewResponseController(s.ResponseWriter).Flush()
}

func (s *a2aAgentCardSniffer) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return http.NewResponseController(s.ResponseWriter).Hijack()
}

func (s *a2aAgentCardSniffer) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Finish 在下游响应完成后提取并脱敏 Agent Card，去重通过则上报 A2A_AGENT_CARD_DISCOVERED 事件。
func (s *a2aAgentCardSniffer) Finish() {
	if s == nil || s.guard == nil || s.guard.apiA2A == nil || s.oversized || s.buf.Len() == 0 {
		return
	}
	card, ok := s.guard.apiA2A.ObserveAgentCard(
		s.guard.AppID, s.status, s.contentType, s.contentEncoding, s.buf.Bytes(), s.fallbackURL,
	)
	if !ok || card == nil {
		return
	}
	pol := s.guard.apiA2A.Policy()
	ev := s.guard.a2aEventBase(s.req, &events.A2ADetail{
		PolicyVersion: pol.Version,
		Mode:          pol.Mode,
		Method:        s.req.Method,
		AgentName:     card.Name,
		AgentURL:      card.URL,
		AgentVersion:  card.Version,
		Skills:        card.Skills,
		AuthSchemes:   card.AuthSchemes,
		ActionTaken:   a2aguard.ActionDiscovered,
	})
	s.guard.emit(ev, events.A2AAgentCardDiscovered, "OBSERVE", s.status)
}
