package a2aguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
)

// a2aMethods 受检的 A2A JSON-RPC 方法集合（冻结契约）。
var a2aMethods = map[string]struct{}{
	"tasks/send":          {},
	"tasks/sendSubscribe": {},
	"tasks/get":           {},
	"tasks/cancel":        {},
	"message/send":        {},
	"message/stream":      {},
}

// IsA2AMethod 判断 JSON-RPC method 是否属于 A2A 协议核心方法集合。
func IsA2AMethod(method string) bool {
	_, ok := a2aMethods[method]
	return ok
}

// RPCRequest 解析后的 A2A JSON-RPC 2.0 请求摘要。
type RPCRequest struct {
	Method       string
	IDRaw        string
	TaskID       string
	ParamsRaw    json.RawMessage
	ParamsTokens []string
}

// ParseA2ARPC 解析 POST 请求体中的 A2A JSON-RPC 2.0 请求（有界 <=256KiB）。
// 非 JSON 对象、非 A2A 方法或超出体积上限返回 (nil, false)。
func ParseA2ARPC(body []byte) (*RPCRequest, bool) {
	if len(body) == 0 || len(body) > MaxJSONRPCBodyBytes {
		return nil, false
	}
	var env struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, false
	}
	if env.JSONRPC != "" && env.JSONRPC != "2.0" {
		return nil, false
	}
	method := strings.TrimSpace(env.Method)
	if !IsA2AMethod(method) {
		return nil, false
	}
	idRaw := sanitizeJSONRPCID(env.ID)
	taskID, tokens := extractParamsInfo(env.Params)
	return &RPCRequest{
		Method:       method,
		IDRaw:        idRaw,
		TaskID:       taskID,
		ParamsRaw:    env.Params,
		ParamsTokens: tokens,
	}, true
}

func sanitizeJSONRPCID(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > 128 {
		return "null"
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return "null"
	}
	var s string
	if json.Unmarshal(trimmed, &s) == nil {
		b, err := json.Marshal(s)
		if err == nil {
			return string(b)
		}
		return "null"
	}
	var num json.Number
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&num); err == nil && !dec.More() {
		if _, err := strconv.ParseInt(num.String(), 10, 64); err == nil {
			return num.String()
		}
		if _, err := strconv.ParseFloat(num.String(), 64); err == nil {
			return num.String()
		}
	}
	return "null"
}

const (
	maxParamsWalkDepth = 8
	maxParamsWalkNodes = 256
	maxParamTokenLen   = 512
)

func extractParamsInfo(raw json.RawMessage) (taskID string, tokens []string) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return "", nil
	}
	var doc any
	if err := json.Unmarshal(trimmed, &doc); err != nil {
		return "", nil
	}
	if obj, ok := doc.(map[string]any); ok {
		taskID = extractTaskID(obj)
	}
	nodes := 0
	walkParamsTokens(doc, 0, &nodes, &tokens)
	return taskID, tokens
}

func extractTaskID(obj map[string]any) string {
	for _, k := range []string{"id", "taskId", "task_id"} {
		if v, ok := obj[k].(string); ok {
			if clean := stripControlChars(v, 128); clean != "" {
				return clean
			}
		}
	}
	if msg, ok := obj["message"].(map[string]any); ok {
		for _, k := range []string{"taskId", "task_id", "contextId", "context_id"} {
			if v, ok := msg[k].(string); ok {
				if clean := stripControlChars(v, 128); clean != "" {
					return clean
				}
			}
		}
	}
	return ""
}

func walkParamsTokens(v any, depth int, nodes *int, out *[]string) {
	if v == nil || depth > maxParamsWalkDepth || *nodes >= maxParamsWalkNodes {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			*nodes++
			if *nodes > maxParamsWalkNodes {
				return
			}
			if k != "" {
				if len(k) > maxParamTokenLen {
					*out = append(*out, k[:maxParamTokenLen])
				} else {
					*out = append(*out, k)
				}
			}
			walkParamsTokens(val, depth+1, nodes, out)
		}
	case []any:
		for _, el := range t {
			*nodes++
			if *nodes > maxParamsWalkNodes {
				return
			}
			walkParamsTokens(el, depth+1, nodes, out)
		}
	case string:
		if t != "" {
			if len(t) > maxParamTokenLen {
				*out = append(*out, t[:maxParamTokenLen])
			} else {
				*out = append(*out, t)
			}
		}
	}
}

// EvalInput A2A 请求相位评估输入。
type EvalInput struct {
	AppID         string
	Method        string // HTTP method
	Path          string // request URL path
	Body          []byte // preserved POST body (nil for non-POST)
	HeaderAgentID string // X-A2A-Agent-ID（仅在 JWT VERIFIED 时参与白名单校验）
	CallerKey     string // (appID, callerKey) 维度滑窗与污点追踪键
	JWT           *jwtverify.VerificationResult
}

// EvalDecision A2A 请求相位评估结论。
type EvalDecision struct {
	Matched         bool
	Block           bool
	IsJSONRPC       bool
	RPCMethod       string
	RPCIDRaw        string
	EventType       string
	RuleID          string
	HTTPStatus      int
	JSONRPCCode     int
	ActionTaken     string
	AgentName       string
	DelegationDepth int
	Reason          string
}

// EvaluateRequest 对入站请求执行 A2A 委派链校验、循环熔断与 Lethal Trifecta 污点检测。
func (e *Engine) EvaluateRequest(in EvalInput) EvalDecision {
	if e == nil || e.policy.Mode == ModeOff {
		return EvalDecision{}
	}
	now := e.now()
	appID := in.AppID
	if appID == "" {
		appID = e.policy.ApplicationID
	}
	canonPath := normalizer.CanonicalPath(in.Path)

	var rpcReq *RPCRequest
	isRPC := false
	if strings.EqualFold(in.Method, http.MethodPost) && e.MatchA2APath(canonPath) {
		rpcReq, isRPC = ParseA2ARPC(in.Body)
	}

	// 1. Lethal Trifecta 污点标记：请求路径或 A2A 方法/参数命中 confidential_read_patterns → 标记污点。
	if e.policy.LethalTrifectaEnabled && in.CallerKey != "" {
		if pat, hit := e.MatchesConfidentialPattern(canonPath); hit {
			e.taintTracker.MarkTainted(appID, in.CallerKey, "path:"+pat, now)
		} else if isRPC {
			if pat, hit := e.matchRPCTokens(rpcReq, e.MatchesConfidentialPattern); hit {
				e.taintTracker.MarkTainted(appID, in.CallerKey, "a2a:"+pat, now)
			}
		}
	}

	// 2. A2A JSON-RPC 请求检查链（调用方白名单 → 委派深度 → 作用域衰减 → 递归循环 → Lethal Trifecta）。
	if isRPC {
		jwtVerified := in.JWT != nil && in.JWT.Status == jwtverify.StatusVerified
		depth := 0
		agentName := ""
		if jwtVerified {
			depth = len(in.JWT.DelegationChain)
			agentName = verifiedCallerName(in.JWT, in.HeaderAgentID)
		}

		// (a) 调用方 Agent 白名单（仅接受密码学验签后的主体/azp/act 或验签状态下的 X-A2A-Agent-ID）。
		if len(e.allowedAgents) > 0 {
			if !jwtVerified {
				return e.makeViolation(true, rpcReq, EventBlocked, RuleCallerAgentDenied,
					http.StatusForbidden, CodeCallerAgentDenied, agentName, depth, "caller_jwt_unverified")
			}
			if !e.callerAllowed(in.JWT, in.HeaderAgentID) {
				return e.makeViolation(true, rpcReq, EventBlocked, RuleCallerAgentDenied,
					http.StatusForbidden, CodeCallerAgentDenied, agentName, depth, "caller_agent_not_allowed")
			}
		}

		// (b) RFC 8693 委派深度上限检查（严格仅消费 VERIFIED JWT 的 DelegationChain）。
		if jwtVerified && depth > e.policy.MaxDelegationDepth {
			return e.makeViolation(true, rpcReq, EventBlocked, RuleDelegationDepthExceeded,
				http.StatusForbidden, CodeDelegationDepth, agentName, depth,
				fmt.Sprintf("delegation depth %d exceeds max %d", depth, e.policy.MaxDelegationDepth))
		}

		// (c) RFC 8693 作用域衰减（Scope Attenuation）与特权通配符拒绝（depth >= 1）。
		if jwtVerified && e.policy.EnforceScopeAttenuation && depth >= 1 {
			if reason, violated := checkScopeAttenuation(in.JWT.VerifiedScopes, in.JWT.DelegationScopes); violated {
				return e.makeViolation(true, rpcReq, EventBlocked, RuleDelegationScopeEscalation,
					http.StatusForbidden, CodeDelegationScope, agentName, depth, reason)
			}
		}

		// (d) 递归调用循环检测（有界滑窗 (appID, callerKey, taskID_or_path)）。
		taskOrPath := rpcReq.TaskID
		if taskOrPath == "" {
			taskOrPath = canonPath + ":" + rpcReq.Method
		}
		window := time.Duration(e.policy.LoopWindowSeconds) * time.Second
		if count, exceeded := e.loopTracker.RecordAndCheck(appID, in.CallerKey, taskOrPath, window, e.policy.MaxCallsPerTaskWindow, now); exceeded {
			return e.makeViolation(true, rpcReq, EventLoopKilled, RuleRecursiveLoopDetected,
				http.StatusTooManyRequests, CodeLoopKilled, agentName, depth,
				fmt.Sprintf("loop threshold exceeded: %d/%d in %ds", count, e.policy.MaxCallsPerTaskWindow, e.policy.LoopWindowSeconds))
		}

		// (e) Lethal Trifecta 外部外发动作检测（同一会话/主体已被机密读取污染 + 命中 external_egress_patterns）。
		if e.policy.LethalTrifectaEnabled && in.CallerKey != "" {
			egressPat, egressHit := e.MatchesExternalEgressPattern(canonPath)
			if !egressHit {
				egressPat, egressHit = e.matchRPCTokens(rpcReq, e.MatchesExternalEgressPattern)
			}
			if egressHit {
				if src, tainted := e.taintTracker.IsTainted(appID, in.CallerKey, now); tainted {
					return e.makeViolation(true, rpcReq, EventLethalTrifecta, RuleLethalTrifectaBlocked,
						http.StatusForbidden, CodeLethalTrifecta, agentName, depth,
						fmt.Sprintf("tainted(%s)->egress(%s)", src, egressPat))
				}
			}
		}

		return EvalDecision{
			IsJSONRPC:       true,
			RPCMethod:       rpcReq.Method,
			RPCIDRaw:        rpcReq.IDRaw,
			AgentName:       agentName,
			DelegationDepth: depth,
		}
	}

	// 3. 非 A2A 路径上的 Lethal Trifecta 外部外发动作检测（如已污染主体直接调用 webhook/send_email 路径）。
	if e.policy.LethalTrifectaEnabled && in.CallerKey != "" {
		if egressPat, egressHit := e.MatchesExternalEgressPattern(canonPath); egressHit {
			if src, tainted := e.taintTracker.IsTainted(appID, in.CallerKey, now); tainted {
				depth := 0
				agentName := ""
				if in.JWT != nil && in.JWT.Status == jwtverify.StatusVerified {
					depth = len(in.JWT.DelegationChain)
					agentName = verifiedCallerName(in.JWT, in.HeaderAgentID)
				}
				return e.makeViolation(false, nil, EventLethalTrifecta, RuleLethalTrifectaBlocked,
					http.StatusForbidden, CodeLethalTrifecta, agentName, depth,
					fmt.Sprintf("tainted(%s)->egress(%s)", src, egressPat))
			}
		}
	}

	return EvalDecision{}
}

// RecordConfidentialTaint 供外部管线（如 MCP CONFIDENTIAL 工具调用）向 A2A Lethal Trifecta 污点追踪器写入污点。
func (e *Engine) RecordConfidentialTaint(appID, callerKey, source string) {
	if e == nil || e.policy.Mode == ModeOff || !e.policy.LethalTrifectaEnabled {
		return
	}
	if callerKey == "" {
		return
	}
	if appID == "" {
		appID = e.policy.ApplicationID
	}
	e.taintTracker.MarkTainted(appID, callerKey, stripControlChars(source, 128), e.now())
}

// CheckExternalEgress 供外部管线（如 MCP 工具调用命中 external_egress_patterns）检查是否触发 Lethal Trifecta。
func (e *Engine) CheckExternalEgress(appID, callerKey, method, target string, jwtRes *jwtverify.VerificationResult, headerAgentID string) EvalDecision {
	if e == nil || e.policy.Mode == ModeOff || !e.policy.LethalTrifectaEnabled || callerKey == "" {
		return EvalDecision{}
	}
	if appID == "" {
		appID = e.policy.ApplicationID
	}
	egressPat, hit := e.MatchesExternalEgressPattern(target)
	if !hit {
		return EvalDecision{}
	}
	src, tainted := e.taintTracker.IsTainted(appID, callerKey, e.now())
	if !tainted {
		return EvalDecision{}
	}
	depth := 0
	agentName := ""
	if jwtRes != nil && jwtRes.Status == jwtverify.StatusVerified {
		depth = len(jwtRes.DelegationChain)
		agentName = verifiedCallerName(jwtRes, headerAgentID)
	}
	dec := e.makeViolation(false, nil, EventLethalTrifecta, RuleLethalTrifectaBlocked,
		http.StatusForbidden, CodeLethalTrifecta, agentName, depth,
		fmt.Sprintf("tainted(%s)->egress(%s)", src, egressPat))
	if method != "" {
		dec.RPCMethod = method
	}
	return dec
}

func (e *Engine) makeViolation(isRPC bool, rpcReq *RPCRequest, protectEvent, ruleID string, status, rpcCode int, agentName string, depth int, reason string) EvalDecision {
	dec := EvalDecision{
		Matched:         true,
		Block:           e.policy.Mode == ModeProtect,
		IsJSONRPC:       isRPC,
		RuleID:          ruleID,
		HTTPStatus:      status,
		JSONRPCCode:     rpcCode,
		AgentName:       agentName,
		DelegationDepth: depth,
		Reason:          reason,
	}
	if rpcReq != nil {
		dec.RPCMethod = rpcReq.Method
		dec.RPCIDRaw = rpcReq.IDRaw
	}
	if dec.Block {
		dec.EventType = protectEvent
		dec.ActionTaken = ActionBlocked
	} else {
		dec.EventType = EventObserved
		dec.ActionTaken = ActionObserved
	}
	return dec
}

func (e *Engine) matchRPCTokens(req *RPCRequest, matchFn func(string) (string, bool)) (string, bool) {
	if req == nil {
		return "", false
	}
	if pat, hit := matchFn(req.Method); hit {
		return pat, true
	}
	for _, tok := range req.ParamsTokens {
		if pat, hit := matchFn(tok); hit {
			return pat, true
		}
	}
	return "", false
}

func (e *Engine) callerAllowed(jwtRes *jwtverify.VerificationResult, headerAgentID string) bool {
	if jwtRes == nil || jwtRes.Status != jwtverify.StatusVerified {
		return false
	}
	candidates := make([]string, 0, 4)
	if jwtRes.VerifiedPrincipalID != "" {
		candidates = append(candidates, jwtRes.VerifiedPrincipalID)
	}
	if jwtRes.VerifiedAZP != "" {
		candidates = append(candidates, jwtRes.VerifiedAZP)
	}
	if len(jwtRes.DelegationChain) > 0 && jwtRes.DelegationChain[0] != "" {
		candidates = append(candidates, jwtRes.DelegationChain[0])
	}
	// X-A2A-Agent-ID 仅在 JWT 已 VERIFIED 状态下采信。
	if h := stripControlChars(headerAgentID, MaxAgentNameLen); h != "" {
		candidates = append(candidates, h)
	}
	for _, c := range candidates {
		if _, ok := e.allowedAgents[c]; ok {
			return true
		}
	}
	return false
}

func verifiedCallerName(jwtRes *jwtverify.VerificationResult, headerAgentID string) string {
	if jwtRes == nil || jwtRes.Status != jwtverify.StatusVerified {
		return ""
	}
	if len(jwtRes.DelegationChain) > 0 && jwtRes.DelegationChain[0] != "" {
		return jwtRes.DelegationChain[0]
	}
	if jwtRes.VerifiedAZP != "" {
		return jwtRes.VerifiedAZP
	}
	if h := stripControlChars(headerAgentID, MaxAgentNameLen); h != "" {
		return h
	}
	return jwtRes.VerifiedPrincipalID
}

// checkScopeAttenuation 校验 RFC 8693 委派链（depth >= 1）上的作用域衰减：
//  1. 拒绝任意层上的通配符或管理员提权作用域（"*", "admin:*", "root" 等）；
//  2. 当存在嵌套 act.scope 时，按外层（子）→内层（父）序，验证每一级子作用域均为父作用域的子集。
func checkScopeAttenuation(verifiedScopes []string, delegationScopes [][]string) (reason string, violated bool) {
	// 1. 拒绝委派链上的通配符/管理员提权作用域。
	for _, s := range verifiedScopes {
		if isEscalationScope(s) {
			return "delegated_wildcard_or_admin_scope", true
		}
	}
	for _, hop := range delegationScopes {
		for _, s := range hop {
			if isEscalationScope(s) {
				return "delegated_wildcard_or_admin_scope", true
			}
		}
	}

	// 2. 收集非空作用域层级（最外层当前令牌 → 外层 act → 内层父 act）。
	levels := make([][]string, 0, 1+len(delegationScopes))
	if len(verifiedScopes) > 0 {
		levels = append(levels, verifiedScopes)
	}
	for _, hop := range delegationScopes {
		if len(hop) > 0 {
			levels = append(levels, hop)
		}
	}
	// 验证每级子作用域 ⊆ 父作用域（即 levels[i] ⊆ levels[i+1]）。
	for i := 0; i+1 < len(levels); i++ {
		child := levels[i]
		parent := levels[i+1]
		parentSet := make(map[string]struct{}, len(parent))
		for _, s := range parent {
			parentSet[s] = struct{}{}
		}
		for _, s := range child {
			if _, ok := parentSet[s]; !ok {
				return "delegation_scope_not_attenuated", true
			}
		}
	}
	return "", false
}

// isEscalationScope 判断作用域是否为委派链上禁止的通配符或高危管理员提权作用域。
func isEscalationScope(scope string) bool {
	s := strings.ToLower(strings.TrimSpace(scope))
	if s == "" {
		return false
	}
	if strings.Contains(s, "*") {
		return true
	}
	switch s {
	case "admin", "root", "superadmin", "superuser", "all":
		return true
	}
	if strings.HasPrefix(s, "admin:") || strings.HasPrefix(s, "admin.") || strings.HasPrefix(s, "admin/") ||
		strings.HasPrefix(s, "root:") || strings.HasPrefix(s, "root.") || strings.HasPrefix(s, "root/") ||
		strings.HasSuffix(s, ":admin") || strings.HasSuffix(s, ":root") {
		return true
	}
	return false
}
