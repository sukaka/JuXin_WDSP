// apisemantic.go Phase 9C-2 本地离线 ONNX/SLM 语义防火墙在 jiuzhang_guard 的挂点实现：
//   - 配置段 semantic_guard_policy 严格解码（DisallowUnknownFields）+ 全量校验，fail-closed 拒载；
//   - 未配置或 mode==OFF 时 g.semanticGuard==nil，请求链路零开销直通；
//   - 三通道检测：
//     1) LLM 提示词通道（inspect_llm_prompts）：从已保全 LLM 请求体提取全部 messages/prompt/input/system 文本；
//     2) MCP 内容通道（inspect_mcp_content）：检查 MCP tools/call 参数文本与完整缓冲的 MCP 响应文本；
//     3) Web 灰区通道（inspect_web_grayzone）：仅当 RequestContext RiskScore >= 10 或存在非 INFO
//        OBSERVE 命中且未被硬阻断时触发（对干净流量零开销、零 sidecar 调用）；
//   - 故障策略：PROTECT + FAIL_CLOSED 下 sidecar 不可用/超时/满载/熔断打开时返回 HTTP 503 JSON
//     {"error":"semantic_guard_unavailable","request_id":...}（绝不伪装为 403 攻击阻断）并发出 SEMANTIC_UNAVAILABLE；
//   - 证据与事件纪律：绝不写入原始提示词、参数或请求/响应体文本，仅记录元数据。
package jiuzhang_guard

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/classifier"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/mcpguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
	"github.com/jiuzhang-waf/gateway/dynamic_security/pipeline"
	"github.com/jiuzhang-waf/gateway/dynamic_security/semantic"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"go.uber.org/zap"
)

const (
	semanticExtIsMCPRequest = "semantic.is_mcp_request"
	// maxSemanticExtractBytes 单请求/响应提取语义文本时的中间字节上限（防止大 JSON 内存膨胀）。
	maxSemanticExtractBytes = 64 << 10
	// maxSemanticWalkDepth / maxSemanticWalkNodes 递归提取 JSON 文本叶子时的遍历护栏。
	maxSemanticWalkDepth = 10
	maxSemanticWalkNodes = 512
	// webGrayzoneMinRiskScore Web 灰区复检触发风险分下限（干净流量 RiskScore=0 零开销跳过）。
	webGrayzoneMinRiskScore = 10
)

// sensitiveWebParamKeys 在拼接 Web 灰区样本时显式剥离凭据/敏感字段，避免凭据送入本地分类器。
var sensitiveWebParamKeys = map[string]bool{
	"password":      true,
	"passwd":        true,
	"pwd":           true,
	"secret":        true,
	"token":         true,
	"access_token":  true,
	"refresh_token": true,
	"id_token":      true,
	"api_key":       true,
	"apikey":        true,
	"authorization": true,
	"cookie":        true,
	"session_id":    true,
	"sessionid":     true,
}

func (g *Guard) validateSemanticGuardPolicy() error {
	if len(g.SemanticGuardPolicy) == 0 {
		return nil
	}
	_, err := semantic.ParseAndValidatePolicy(g.SemanticGuardPolicy)
	return err
}

func (g *Guard) assembleSemanticGuard() error {
	if len(g.SemanticGuardPolicy) == 0 {
		g.semanticGuard = nil
		return nil
	}
	pol, err := semantic.ParseAndValidatePolicy(g.SemanticGuardPolicy)
	if err != nil {
		return err
	}
	if pol.Mode == semantic.ModeOff {
		g.semanticGuard = nil
		return nil
	}
	if g.semanticSocketOverride != "" {
		if err := pol.SetTestSocketPath(g.semanticSocketOverride); err != nil {
			return err
		}
	}
	eng, err := semantic.NewEngine(pol)
	if err != nil {
		return err
	}
	g.semanticGuard = eng
	if g.logger != nil {
		g.logger.Info("semantic guard policy loaded",
			zap.String("app_id", pol.ApplicationID),
			zap.String("mode", pol.Mode),
			zap.Int("policy_version", pol.Version),
			zap.String("socket_path", pol.SocketPath),
			zap.Int("timeout_ms", pol.TimeoutMS),
			zap.Int("max_concurrency", pol.MaxConcurrency),
			zap.Int("max_input_runes", pol.MaxInputRunes),
			zap.Float64("observe_threshold", pol.ObserveThreshold),
			zap.Float64("block_threshold", pol.BlockThreshold),
			zap.String("fail_policy", pol.FailPolicy),
			zap.Bool("inspect_llm_prompts", pol.InspectLLMPrompts),
			zap.Bool("inspect_mcp_content", pol.InspectMCPContent),
			zap.Bool("inspect_web_grayzone", pol.InspectWebGrayzone))
	}
	return nil
}

// semanticShouldCaptureResponse 判断当前非 API 分类请求是否因 MCP 响应语义检测需要进入缓冲捕获路径。
// 对普通非 MCP 流量恒返回 false（零额外缓冲开销）。
func (g *Guard) semanticShouldCaptureResponse(ctx *dsctx.RequestContext) bool {
	if g.semanticGuard == nil || ctx == nil {
		return false
	}
	pol := g.semanticGuard.Policy()
	if pol == nil || !pol.InspectMCPContent {
		return false
	}
	return isSemanticMCPRequest(ctx, nil, nil)
}

// evaluateSemanticAPIRequest 在统一 API 管线请求相位之后、最终分流之前执行语义检测，
// 写入 DetectorMatch 并通过 decision.Decide 结合 api_exceptions 统一裁决。
// 返回 handled=true 表示已直接写出 503 semantic_guard_unavailable 响应。
func (g *Guard) evaluateSemanticAPIRequest(
	w http.ResponseWriter,
	r *http.Request,
	res *pipeline.Result,
	bodySample []byte,
	apiExcRefs []decision.ExceptionRef,
	start time.Time,
) (bool, error) {
	if g.semanticGuard == nil || res == nil || res.Context == nil {
		return false, nil
	}
	pol := g.semanticGuard.Policy()
	if pol == nil || pol.Mode == semantic.ModeOff {
		return false, nil
	}

	// 标记 MCP 请求供响应相位复用（即使未配置 api_mcp_bindings，也可识别 JSON-RPC tools/call）
	mcpArgs, isMCP := extractMCPRequestArgsText(res.Context, bodySample)
	if isMCP {
		res.Context.SetExtension(semanticExtIsMCPRequest, true)
	}

	channel, text := selectSemanticRequestInput(pol, r, res.Context, res.Parsed, bodySample, mcpArgs, isMCP)
	if channel == "" || text == "" {
		return false, nil
	}

	out := g.semanticGuard.Evaluate(r.Context(), res.Context.RequestID, channel, text)
	if out.Match != nil {
		res.Context.AddMatch(*out.Match)
	}

	// 1. PROTECT + FAIL_CLOSED 且 sidecar 不可用/超时/满载/熔断打开：直接返回 503（绝不伪装 403）
	if out.FailClosedBlock {
		g.bridgeRequestContext(r, res.Context)
		g.enrichContextIdentifiers(r, res.Context, res.Parsed)
		*r = *r.WithContext(r.Context())
		dispo := DispositionFrom(r.Context())
		dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusServiceUnavailable, true,
			[]string{"SEMANTIC_GUARD_UNAVAILABLE"}, []string{"semantic:" + semantic.RuleSidecarUnavailable})
		g.emitSemanticEvent(r, pol, out, events.SemanticUnavailable, "REJECT", http.StatusServiceUnavailable, dispo.JSON())
		g.emitAPIEvent(r, res, &apiEventTail{status: http.StatusServiceUnavailable, latencyMS: time.Since(start).Milliseconds()})
		g.writeSemanticUnavailableResponse(w, res.Context.RequestID)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return true, nil
	}

	// 2. FAIL_OPEN / OBSERVE 下 sidecar 不可用：记录 SEMANTIC_UNAVAILABLE 并放行
	if out.Unavailable {
		dispo := DispositionFrom(r.Context())
		dispo.RecordStep(ExecutorAPI, StepObserved, "semantic:"+out.Reason)
		g.emitSemanticEvent(r, pol, out, events.SemanticUnavailable, "OBSERVE", 0, nil)
		// 不提升原有决策动作，保持非阻断放行
		return false, nil
	}

	// 3. 无命中（safe 或低于 observe_threshold）
	if out.Match == nil {
		return false, nil
	}

	// 4. 命中观察或阻断：通过统一决策引擎执行 api_exceptions 豁免核查并更新 FinalAction
	act := decision.Decide(res.Context, decision.Input{
		Mode:            apiDecisionMode(g.APIProtectionMode),
		RateLimitAction: normalizedAPIRateLimitAction(g.APIRateLimitAction),
		Exceptions:      apiExcRefs,
	})
	res.FinalAction = act

	// 若策略本身处于 PROTECT 且语义 BLOCK 未被 api_exceptions 豁免，则确保定案为 ActionBlock
	// （即便全局 api_protection_mode 仍为 OBSERVE，也不削弱显式开启 PROTECT 的语义策略）
	if out.Blocked && semanticBlockMatched(res.Context.CopyMatches()) != "" {
		res.Context.SetFinalAction(dsctx.ActionBlock)
		res.FinalAction = dsctx.ActionBlock
		// SEMANTIC_BLOCKED 事件在 switch res.FinalAction -> ActionBlock 分支与 RecordTerminal 一并输出
		return false, nil
	}

	if out.Observed {
		dispo := DispositionFrom(r.Context())
		dispo.RecordStep(ExecutorAPI, StepObserved, "semantic:"+out.RuleID)
		g.emitSemanticEvent(r, pol, out, events.SemanticObserved, "OBSERVE", 0, nil)
	}
	return false, nil
}

// evaluateSemanticMCPResponse 在响应相位对完整缓冲的 MCP JSON-RPC 响应正文执行间接注入语义检测。
// 返回 handled=true 表示已写出抑制响应（403 阻断或 503 故障拒绝）并完成事件输出。
func (g *Guard) evaluateSemanticMCPResponse(
	w http.ResponseWriter,
	r *http.Request,
	res *pipeline.Result,
	decodedBody []byte,
	tail *apiEventTail,
) bool {
	if g.semanticGuard == nil || res == nil || res.Context == nil || len(decodedBody) == 0 {
		return false
	}
	pol := g.semanticGuard.Policy()
	if pol == nil || pol.Mode == semantic.ModeOff || !pol.InspectMCPContent {
		return false
	}
	if !isSemanticMCPRequest(res.Context, res.Parsed, nil) {
		return false
	}
	text := extractMCPResponseText(decodedBody)
	if text == "" {
		return false
	}

	dispo := DispositionFrom(r.Context())
	out := g.semanticGuard.Evaluate(r.Context(), res.Context.RequestID, semantic.ChannelMCPContent, text)
	if out.Match != nil {
		res.Context.AddMatch(*out.Match)
	}

	if out.FailClosedBlock {
		tail.status = http.StatusServiceUnavailable
		dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusServiceUnavailable, true,
			[]string{"SEMANTIC_GUARD_UNAVAILABLE"}, []string{"semantic:" + semantic.RuleSidecarUnavailable})
		g.emitSemanticEvent(r, pol, out, events.SemanticUnavailable, "REJECT", http.StatusServiceUnavailable, dispo.JSON())
		g.emitAPIEvent(r, res, tail)
		g.writeSemanticUnavailableResponse(w, res.Context.RequestID)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return true
	}
	if out.Unavailable {
		dispo.RecordStep(ExecutorAPI, StepObserved, "semantic:"+out.Reason)
		g.emitSemanticEvent(r, pol, out, events.SemanticUnavailable, "OBSERVE", 0, nil)
		return false
	}
	if out.Blocked {
		res.Context.SetFinalAction(dsctx.ActionBlock)
		res.FinalAction = dsctx.ActionBlock
		tail.status = http.StatusForbidden
		matches := res.Context.CopyMatches()
		dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusForbidden, true,
			[]string{"SEMANTIC_GUARD_BLOCKED"}, apiEnforcementRuleRefs(matches))
		g.emitSemanticEvent(r, pol, out, events.SemanticBlocked, "BLOCK", http.StatusForbidden, dispo.JSON())
		g.emitAPIEvent(r, res, tail)
		if mcpguard.CallFromContext(res.Context) != nil {
			g.setMCPOAuthChallenge(w, r, res.Context, http.StatusForbidden)
			g.writeMCPErrorResponse(w, res.Context.RequestID, mcpguard.CodeResultBlocked, http.StatusForbidden, mcpRequestIDRaw(res.Context))
		} else {
			g.writeSemanticBlockedResponse(w, res.Context.RequestID, out.RuleID)
		}
		accessLogAnnotate(r.Context(), wafActionBlock)
		return true
	}
	if out.Observed {
		dispo.RecordStep(ExecutorAPI, StepObserved, "semantic:"+out.RuleID)
		g.emitSemanticEvent(r, pol, out, events.SemanticObserved, "OBSERVE", 0, nil)
	}
	return false
}

// enforceSemanticStandaloneRequest 在未开启 api_dynamic_protection 但显式启用了
// semantic_guard_policy 时提供独立的 LLM/MCP 请求侧语义防护（Web 灰区依赖管线风险分，此路径不触发）。
func (g *Guard) enforceSemanticStandaloneRequest(w http.ResponseWriter, r *http.Request) (bool, error) {
	if g.semanticGuard == nil || r == nil || r.Method != http.MethodPost {
		return false, nil
	}
	pol := g.semanticGuard.Policy()
	if pol == nil || pol.Mode == semantic.ModeOff || (!pol.InspectLLMPrompts && !pol.InspectMCPContent) {
		return false, nil
	}
	body := peekSemanticBody(r)
	if len(body) == 0 {
		return false, nil
	}

	var channel, text string
	if pol.InspectMCPContent {
		if argsText, isMCP := extractMCPRequestArgsText(nil, body); isMCP && argsText != "" {
			channel = semantic.ChannelMCPContent
			text = argsText
		}
	}
	if channel == "" && pol.InspectLLMPrompts {
		if prompt := extractLLMPromptFromJSONBody(body); prompt != "" {
			channel = semantic.ChannelLLMPrompt
			text = prompt
		}
	}
	if channel == "" || text == "" {
		return false, nil
	}

	reqID := semanticRequestID(r)
	dispo := DispositionFrom(r.Context())
	out := g.semanticGuard.Evaluate(r.Context(), reqID, channel, text)
	if out.FailClosedBlock {
		dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusServiceUnavailable, true,
			[]string{"SEMANTIC_GUARD_UNAVAILABLE"}, []string{"semantic:" + semantic.RuleSidecarUnavailable})
		g.emitSemanticEvent(r, pol, out, events.SemanticUnavailable, "REJECT", http.StatusServiceUnavailable, dispo.JSON())
		g.writeSemanticUnavailableResponse(w, reqID)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return true, nil
	}
	if out.Unavailable {
		dispo.RecordStep(ExecutorAPI, StepObserved, "semantic:"+out.Reason)
		g.emitSemanticEvent(r, pol, out, events.SemanticUnavailable, "OBSERVE", 0, nil)
		return false, nil
	}
	if out.Blocked {
		dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusForbidden, true,
			[]string{"SEMANTIC_GUARD_BLOCKED"}, []string{"semantic:" + out.RuleID})
		g.emitSemanticEvent(r, pol, out, events.SemanticBlocked, "BLOCK", http.StatusForbidden, dispo.JSON())
		g.writeSemanticBlockedResponse(w, reqID, out.RuleID)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return true, nil
	}
	if out.Observed {
		dispo.RecordStep(ExecutorAPI, StepObserved, "semantic:"+out.RuleID)
		g.emitSemanticEvent(r, pol, out, events.SemanticObserved, "OBSERVE", 0, nil)
	}
	return false, nil
}

func peekSemanticBody(r *http.Request) []byte {
	if r == nil || r.Body == nil || r.Method != http.MethodPost {
		return nil
	}
	const limit = 256 << 10 // 256 KiB
	if r.ContentLength > limit {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), r.Body))
		return nil
	}
	if len(b) > limit {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), r.Body))
		return nil
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(b))
	return b
}

// semanticBlockMatched 返回首条未豁免的 semantic BLOCK 明细的 RuleID（空串表示无语义阻断贡献）。
func semanticBlockMatched(matches []dsctx.DetectorMatch) string {
	for _, m := range matches {
		if m.Excepted || m.Detector != semantic.DetectorName {
			continue
		}
		if strings.EqualFold(m.Category, "BLOCK") {
			if m.RuleID != "" {
				return m.RuleID
			}
			return semantic.RulePromptInjection
		}
	}
	return ""
}

// semanticMatchForRule 从 matches 中查找对应规则的 semantic 明细，供事件装配读取脱敏证据字段。
func semanticMatchForRule(matches []dsctx.DetectorMatch, ruleID string) *dsctx.DetectorMatch {
	for i := len(matches) - 1; i >= 0; i-- {
		m := matches[i]
		if m.Detector == semantic.DetectorName && !m.Excepted && (ruleID == "" || m.RuleID == ruleID) {
			cp := m
			return &cp
		}
	}
	return nil
}

// emitSemanticBlockedFromMatch 在 apiprotect ActionBlock 终态分支输出 SEMANTIC_BLOCKED 访问控制事件。
func (g *Guard) emitSemanticBlockedFromMatch(r *http.Request, matches []dsctx.DetectorMatch, ruleID string, finalDecision json.RawMessage) {
	if g.semanticGuard == nil {
		return
	}
	pol := g.semanticGuard.Policy()
	m := semanticMatchForRule(matches, ruleID)
	out := semantic.EvalOutcome{
		RuleID:      ruleID,
		Blocked:     true,
		ActionTaken: "BLOCKED",
		Reason:      "score_exceeds_block_threshold",
	}
	if m != nil && m.Evidence != nil {
		out.Channel = m.Evidence["channel"]
		out.Result.Label = m.Evidence["label"]
		out.Result.ModelID = m.Evidence["model_id"]
		if s, err := strconv.ParseFloat(m.Evidence["score"], 64); err == nil {
			out.Result.Score = s
		}
		if ms, err := strconv.ParseInt(m.Evidence["latency_ms"], 10, 64); err == nil {
			out.Result.LatencyMS = ms
		}
		if rn, err := strconv.Atoi(m.Evidence["input_runes"]); err == nil {
			out.Result.InputRunes = rn
		}
	}
	g.emitSemanticEvent(r, pol, out, events.SemanticBlocked, "BLOCK", http.StatusForbidden, finalDecision)
}

func (g *Guard) emitSemanticEvent(
	r *http.Request,
	pol *semantic.Policy,
	out semantic.EvalOutcome,
	evType events.Type,
	action string,
	status int,
	finalDecision json.RawMessage,
) {
	if g.events == nil || r == nil {
		return
	}
	detail := &events.SemanticDetail{
		Channel:     out.Channel,
		RuleID:      out.RuleID,
		Label:       out.Result.Label,
		Score:       out.Result.Score,
		ModelID:     out.Result.ModelID,
		LatencyMS:   out.Result.LatencyMS,
		InputRunes:  out.Result.InputRunes,
		ActionTaken: out.ActionTaken,
		Reason:      out.Reason,
	}
	if pol != nil {
		detail.PolicyVersion = pol.Version
		detail.Mode = pol.Mode
		detail.FailPolicy = pol.FailPolicy
	}
	ev := events.Event{
		RequestID:     semanticRequestID(r),
		OccurredAt:    time.Now().UTC(),
		ApplicationID: g.AppID,
		AppCode:       g.AppCode,
		Domain:        r.Host,
		Method:        r.Method,
		Path:          r.URL.RequestURI(),
		Proto:         r.Proto,
		GatewayNode:   g.GatewayNode,
		Semantic:      detail,
		FinalDecision: finalDecision,
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
	g.emit(ev, evType, action, status)
}

func semanticRequestID(r *http.Request) string {
	if r == nil {
		return ""
	}
	if id := r.Header.Get("X-Request-Id"); id != "" {
		return id
	}
	return r.Header.Get("X-Jiuzhang-Request-ID")
}

// writeSemanticUnavailableResponse PROTECT + FAIL_CLOSED 不可用响应：
// 严格返回 HTTP 503 与 "semantic_guard_unavailable"，绝不伪装成 403 攻击阻断。
func (g *Guard) writeSemanticUnavailableResponse(w http.ResponseWriter, requestID string) {
	h := w.Header()
	h.Del("Content-Length")
	h.Del("Content-Encoding")
	h.Del("ETag")
	h.Del("Content-MD5")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	body, _ := json.Marshal(map[string]string{
		"error":      "semantic_guard_unavailable",
		"message":    "semantic firewall sidecar unavailable under fail-closed policy",
		"request_id": requestID,
	})
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusServiceUnavailable)
	if _, err := w.Write(body); err != nil && g.logger != nil {
		g.logger.Warn("semantic unavailable 503 response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}

// writeSemanticBlockedResponse 语义防火墙 PROTECT 高置信攻击阻断响应：403 JSON（不含任何提示词原文）。
func (g *Guard) writeSemanticBlockedResponse(w http.ResponseWriter, requestID, ruleID string) {
	h := w.Header()
	h.Del("Content-Length")
	h.Del("Content-Encoding")
	h.Del("ETag")
	h.Del("Content-MD5")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	body, _ := json.Marshal(map[string]string{
		"code":       "SEMANTIC_GUARD_BLOCKED",
		"message":    "request blocked by local semantic firewall",
		"rule_id":    ruleID,
		"request_id": requestID,
	})
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write(body); err != nil && g.logger != nil {
		g.logger.Warn("semantic blocked 403 response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}

// ---------- 三通道选择与文本提取（严格不读 Cookie / Authorization） ----------

func selectSemanticRequestInput(
	pol *semantic.Policy,
	r *http.Request,
	ctx *dsctx.RequestContext,
	parsed *parser.Parsed,
	bodySample []byte,
	mcpArgs string,
	isMCP bool,
) (channel string, text string) {
	// 1. MCP 内容通道（tools/call 参数）
	if pol.InspectMCPContent && isMCP && mcpArgs != "" {
		return semantic.ChannelMCPContent, mcpArgs
	}
	// 2. LLM 提示词通道
	if pol.InspectLLMPrompts && !isMCP && isSemanticLLMRequest(ctx, parsed) {
		if prompt := extractLLMPromptText(bodySample, parsed); prompt != "" {
			return semantic.ChannelLLMPrompt, prompt
		}
	}
	// 3. Web 灰区通道（仅 RiskScore >= 10 或存在非 INFO OBSERVE 命中；干净流量零开销直返）
	if pol.InspectWebGrayzone && isWebGrayzoneCandidate(ctx) {
		if sample := extractWebGrayzoneText(r, bodySample); sample != "" {
			return semantic.ChannelWebGrayzone, sample
		}
	}
	return "", ""
}

func isWebGrayzoneCandidate(ctx *dsctx.RequestContext) bool {
	if ctx == nil {
		return false
	}
	if ctx.RiskScore >= webGrayzoneMinRiskScore {
		return true
	}
	for _, m := range ctx.CopyMatches() {
		if m.Excepted || m.Detector == semantic.DetectorName {
			continue
		}
		cat := strings.ToUpper(strings.TrimSpace(m.Category))
		sev := strings.ToUpper(strings.TrimSpace(m.Severity))
		if cat == "OBSERVE" && sev != "" && sev != "INFO" {
			return true
		}
	}
	return false
}

func isSemanticLLMRequest(ctx *dsctx.RequestContext, parsed *parser.Parsed) bool {
	if ctx != nil {
		if v, ok := ctx.GetExtension("api.llm_kind"); ok {
			if s, _ := v.(string); s != "" && s != string(classifier.LLMKindMCP) {
				return true
			}
		}
		if ctx.GetLLMObservation() != nil {
			return true
		}
	}
	if parsed != nil {
		llm := classifier.ClassifyLLM(parsed)
		return llm.IsLLM && llm.Kind != classifier.LLMKindMCP
	}
	return false
}

func isSemanticMCPRequest(ctx *dsctx.RequestContext, parsed *parser.Parsed, bodySample []byte) bool {
	if ctx != nil {
		if v, ok := ctx.GetExtension(semanticExtIsMCPRequest); ok {
			if b, _ := v.(bool); b {
				return true
			}
		}
		if mcpguard.CallFromContext(ctx) != nil {
			return true
		}
		if v, ok := ctx.GetExtension("api.llm_kind"); ok {
			if s, _ := v.(string); s == string(classifier.LLMKindMCP) {
				return true
			}
		}
	}
	if parsed != nil {
		if llm := classifier.ClassifyLLM(parsed); llm.IsLLM && llm.Kind == classifier.LLMKindMCP {
			return true
		}
	}
	if len(bodySample) > 0 {
		_, isMCP := extractMCPRequestArgsText(nil, bodySample)
		return isMCP
	}
	return false
}

// extractLLMPromptText 从完整保全请求体中提取所有 LLM 提示词文本（覆盖多轮 messages 与超过 256 字符的长提示词）；
// 请求体不可得时回退 parser.Parsed.JSONValues。
func extractLLMPromptText(bodySample []byte, parsed *parser.Parsed) string {
	if len(bodySample) > 0 {
		if s := extractLLMPromptFromJSONBody(bodySample); s != "" {
			return s
		}
	}
	if parsed == nil || len(parsed.JSONValues) == 0 {
		return ""
	}
	keys := []string{
		"system",
		"instructions",
		"prompt",
		"input",
		"messages[].content",
		"messages[].content[].text",
	}
	var parts []string
	total := 0
	for _, k := range keys {
		v := strings.TrimSpace(parsed.JSONValues[k])
		if v == "" {
			continue
		}
		if total+len(v) > maxSemanticExtractBytes {
			break
		}
		parts = append(parts, v)
		total += len(v)
	}
	return strings.Join(parts, "\n")
}

func extractLLMPromptFromJSONBody(body []byte) string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return ""
	}
	var parts []string
	total := 0
	appendText := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || total >= maxSemanticExtractBytes {
			return
		}
		rem := maxSemanticExtractBytes - total
		if len(s) > rem {
			s = s[:rem]
		}
		parts = append(parts, s)
		total += len(s)
	}

	for _, field := range []string{"system", "instructions", "prompt", "input"} {
		switch v := obj[field].(type) {
		case string:
			appendText(v)
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					appendText(s)
				} else if m, ok := item.(map[string]any); ok {
					if t, ok := m["text"].(string); ok {
						appendText(t)
					} else if c, ok := m["content"].(string); ok {
						appendText(c)
					}
				}
			}
		}
	}

	if msgs, ok := obj["messages"].([]any); ok {
		for _, item := range msgs {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			switch content := m["content"].(type) {
			case string:
				appendText(content)
			case []any:
				for _, block := range content {
					bm, ok := block.(map[string]any)
					if !ok {
						continue
					}
					if t, ok := bm["text"].(string); ok {
						appendText(t)
					} else if t, ok := bm["input_text"].(string); ok {
						appendText(t)
					}
				}
			}
		}
	}
	return strings.Join(parts, "\n")
}

// extractMCPRequestArgsText 判断请求是否为 MCP JSON-RPC，并在为 tools/call 时提取 arguments 中的全部文本。
func extractMCPRequestArgsText(ctx *dsctx.RequestContext, bodySample []byte) (argsText string, isMCP bool) {
	if call := mcpguard.CallFromContext(ctx); call != nil {
		isMCP = true
		method := call.Method
		if method == "" && call.Message != nil {
			method = call.Message.Method
		}
		if method == "tools/call" && call.Message != nil && len(call.Message.Params) > 0 {
			return extractMCPArgumentsJSON(call.Message.Params), true
		}
		return "", true
	}
	trimmed := bytes.TrimSpace(bodySample)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return "", false
	}
	var env struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return "", false
	}
	if env.JSONRPC != "2.0" {
		return "", false
	}
	switch {
	case env.Method == "tools/call":
		return extractMCPArgumentsJSON(env.Params), true
	case strings.HasPrefix(env.Method, "tools/") ||
		strings.HasPrefix(env.Method, "resources/") ||
		strings.HasPrefix(env.Method, "prompts/"):
		return "", true
	default:
		return "", false
	}
}

func extractMCPArgumentsJSON(params json.RawMessage) string {
	if len(params) == 0 {
		return ""
	}
	var p map[string]any
	if err := json.Unmarshal(params, &p); err != nil {
		return ""
	}
	args, ok := p["arguments"]
	if !ok || args == nil {
		return ""
	}
	return collectJSONTextLeaves(args)
}

// extractMCPResponseText 从完整缓冲的 MCP JSON-RPC 响应体中提取 result 成员内的文本叶子。
func extractMCPResponseText(body []byte) string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return ""
	}
	var env map[string]any
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return ""
	}
	result, ok := env["result"]
	if !ok || result == nil {
		return ""
	}
	return collectJSONTextLeaves(result)
}

func collectJSONTextLeaves(root any) string {
	var parts []string
	total := 0
	nodes := 0
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if v == nil || depth > maxSemanticWalkDepth || nodes >= maxSemanticWalkNodes || total >= maxSemanticExtractBytes {
			return
		}
		nodes++
		switch t := v.(type) {
		case string:
			s := strings.TrimSpace(t)
			if s == "" {
				return
			}
			rem := maxSemanticExtractBytes - total
			if len(s) > rem {
				s = s[:rem]
			}
			parts = append(parts, s)
			total += len(s)
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if sensitiveWebParamKeys[strings.ToLower(k)] {
					continue
				}
				walk(t[k], depth+1)
				if nodes >= maxSemanticWalkNodes || total >= maxSemanticExtractBytes {
					return
				}
			}
		case []any:
			for _, el := range t {
				walk(el, depth+1)
				if nodes >= maxSemanticWalkNodes || total >= maxSemanticExtractBytes {
					return
				}
			}
		}
	}
	walk(root, 0)
	return strings.Join(parts, "\n")
}

// extractWebGrayzoneText 为 Web 灰区样本构造脱敏文本（URL 路径 + 脱敏 Query + 文本请求体），
// 严禁包含 Cookie / Authorization / 密码 / Token 字段。
func extractWebGrayzoneText(r *http.Request, bodySample []byte) string {
	if r == nil {
		return ""
	}
	var parts []string
	total := 0
	appendPart := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || total >= maxSemanticExtractBytes {
			return
		}
		rem := maxSemanticExtractBytes - total
		if len(s) > rem {
			s = s[:rem]
		}
		parts = append(parts, s)
		total += len(s)
	}

	if r.URL != nil {
		appendPart(r.URL.Path)
		if r.URL.RawQuery != "" {
			if vals, err := url.ParseQuery(r.URL.RawQuery); err == nil {
				keys := make([]string, 0, len(vals))
				for k := range vals {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					if sensitiveWebParamKeys[strings.ToLower(k)] {
						continue
					}
					for _, v := range vals[k] {
						appendPart(k + "=" + v)
					}
				}
			}
		}
	}

	if len(bodySample) > 0 {
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		switch {
		case strings.Contains(ct, "json") || (len(bytes.TrimSpace(bodySample)) > 0 && bytes.TrimSpace(bodySample)[0] == '{'):
			var root any
			if err := json.Unmarshal(bodySample, &root); err == nil {
				appendPart(collectJSONTextLeaves(root))
			}
		case strings.Contains(ct, "application/x-www-form-urlencoded"):
			if vals, err := url.ParseQuery(string(bodySample)); err == nil {
				keys := make([]string, 0, len(vals))
				for k := range vals {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					if sensitiveWebParamKeys[strings.ToLower(k)] {
						continue
					}
					for _, v := range vals[k] {
						appendPart(k + "=" + v)
					}
				}
			}
		case strings.HasPrefix(ct, "text/") || strings.Contains(ct, "xml") || strings.Contains(ct, "graphql"):
			appendPart(string(bodySample))
		}
	}
	return strings.Join(parts, "\n")
}
