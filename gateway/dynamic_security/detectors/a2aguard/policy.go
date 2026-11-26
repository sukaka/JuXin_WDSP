// Package a2aguard 实现 Phase 9C-1 A2A（Agent-to-Agent）协议安全网关检测器：
//   - Agent Card 发现与 AgBOM 资产采集（GET /.well-known/agent.json 与 /.well-known/agent-card.json，
//     有界 <=256KiB 未压缩 JSON，剥离凭据与查询串，有界 LRU 去重）；
//   - RFC 8693 委派链深度限制、调用方 Agent 白名单与作用域衰减（Scope Attenuation）强制检查；
//   - 递归调用循环熔断器（有界滑窗 <=8192 键）与 Lethal Trifecta 污点追踪阻断器（有界 <=8192 键、120s TTL）。
//
// 安全纪律：
//   - 仅消费经过密码学验签后的 jwtverify.VerificationResult（Status == StatusVerified），
//     绝不信任未验签 JWT 或无验签上下文的 X-A2A-Agent-ID 头；
//   - 严格 JSON 配置解码（DisallowUnknownFields）+ 全量边界校验，非法配置 fail-closed 拒载；
//   - 零新增第三方依赖，热路径零网络 IO，所有内存状态均有严格容量上限与并发互斥保护。
package a2aguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
)

const (
	// SchemaVersion 本网关支持的 api_a2a_policy 契约版本（不一致 fail-closed 拒载）。
	SchemaVersion = 1

	// 模式枚举（冻结契约）。
	ModeOff     = "OFF"
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"

	// 规则 ID（跨层冻结契约，与 server/web 对齐）。
	RuleCallerAgentDenied         = "a2a.caller_agent_denied"
	RuleDelegationDepthExceeded   = "a2a.delegation_depth_exceeded"
	RuleDelegationScopeEscalation = "a2a.delegation_scope_escalation"
	RuleRecursiveLoopDetected     = "a2a.recursive_loop_detected"
	RuleLethalTrifectaBlocked     = "a2a.lethal_trifecta_blocked"

	// JSON-RPC 2.0 扩展错误码（-32020..-32024，不与 MCP -32010..-32015 或标准码冲突）。
	CodeLoopKilled        = -32020 // 429 Too Many Requests
	CodeLethalTrifecta    = -32021 // 403 Forbidden
	CodeCallerAgentDenied = -32022 // 403 Forbidden
	CodeDelegationDepth   = -32023 // 403 Forbidden
	CodeDelegationScope   = -32024 // 403 Forbidden

	// 事件类型常量（与 jiuzhang_guard/events 对齐）。
	EventAgentCardDiscovered = "A2A_AGENT_CARD_DISCOVERED"
	EventObserved            = "A2A_OBSERVED"
	EventBlocked             = "A2A_BLOCKED"
	EventLoopKilled          = "A2A_LOOP_KILLED"
	EventLethalTrifecta      = "A2A_LETHAL_TRIFECTA"

	// 处置动作枚举。
	ActionObserved   = "OBSERVED"
	ActionBlocked    = "BLOCKED"
	ActionDiscovered = "DISCOVERED"

	// 校验与运行时资源上限（与 server/internal/apia2a & web/src/api/apiA2a.ts 严格对齐）。
	MaxAppIDLen                = 128
	MaxPathPrefixes            = 32
	MaxPathLen                 = 256
	MaxAllowedAgents           = 64
	MaxAgentNameLen            = 128
	MinDelegationDepth         = 1
	MaxDelegationDepth         = 10
	DefaultDelegationDepth     = 3
	MinLoopWindowSeconds       = 5
	MaxLoopWindowSeconds       = 3600
	DefaultLoopWindowSeconds   = 60
	MinMaxCallsPerTaskWindow   = 1
	MaxCallsPerTaskWindow      = 10000
	DefaultMaxCallsPerTask     = 20
	MaxPatterns                = 64
	MaxPatternLen              = 256
	MaxAgentCardBytes          = 256 << 10 // 256 KiB
	MaxJSONRPCBodyBytes        = 256 << 10 // 256 KiB
	MaxAgentSkills             = 32
	MaxAgentAuthSchemes        = 16
	MaxSkillLen                = 128
	MaxAuthSchemeLen           = 64
	DefaultCardDedupTTL        = 60 * time.Second
	DefaultCardDedupMaxEntries = 2048
	DefaultLoopMaxKeys         = 8192
	DefaultTaintMaxKeys        = 8192
	DefaultTaintTTL            = 120 * time.Second
)

// Policy 发布通道下发的 api_a2a_policy 处理器段（严格解码，json tag 为跨层冻结契约）。
type Policy struct {
	SchemaVersion            int      `json:"schema_version"`
	ApplicationID            string   `json:"application_id"`
	Mode                     string   `json:"mode"`
	Version                  int      `json:"version"`
	CardDiscoveryEnabled     bool     `json:"card_discovery_enabled"`
	A2APathPrefixes          []string `json:"a2a_path_prefixes"`
	AllowedCallerAgents      []string `json:"allowed_caller_agents"`
	MaxDelegationDepth       int      `json:"max_delegation_depth"`
	EnforceScopeAttenuation  bool     `json:"enforce_scope_attenuation"`
	LoopWindowSeconds        int      `json:"loop_window_seconds"`
	MaxCallsPerTaskWindow    int      `json:"max_calls_per_task_window"`
	LethalTrifectaEnabled    bool     `json:"lethal_trifecta_enabled"`
	ConfidentialReadPatterns []string `json:"confidential_read_patterns"`
	ExternalEgressPatterns   []string `json:"external_egress_patterns"`
}

// ParseAndValidatePolicy 严格解码（DisallowUnknownFields）并全量校验 api_a2a_policy。
// 任何未知字段、不支持的 schema_version、非法枚举/边界或控制字符注入均拒绝加载（fail-closed）。
func ParseAndValidatePolicy(raw json.RawMessage) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("api_a2a_policy: 配置结构解析失败（拒绝加载）: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("api_a2a_policy: 配置含多余内容（拒绝加载）")
	}
	applyOffDefaults(&p)
	if err := ValidatePolicy(&p); err != nil {
		return nil, fmt.Errorf("api_a2a_policy: 配置校验未通过（拒绝加载）: %w", err)
	}
	return &p, nil
}

// applyOffDefaults 允许极简 OFF 策略省略数值字段，同时保留 OBSERVE/PROTECT 的严格边界拒载。
func applyOffDefaults(p *Policy) {
	if p == nil || p.Mode != ModeOff {
		return
	}
	if p.MaxDelegationDepth == 0 {
		p.MaxDelegationDepth = DefaultDelegationDepth
	}
	if p.LoopWindowSeconds == 0 {
		p.LoopWindowSeconds = DefaultLoopWindowSeconds
	}
	if p.MaxCallsPerTaskWindow == 0 {
		p.MaxCallsPerTaskWindow = DefaultMaxCallsPerTask
	}
}

// ValidatePolicy 校验解析后的 api_a2a_policy。
func ValidatePolicy(p *Policy) error {
	if p == nil {
		return errors.New("policy is nil")
	}
	var errs []error
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if p.SchemaVersion != SchemaVersion {
		add("schema_version: 不支持的版本 %d（本网关支持 %d）", p.SchemaVersion, SchemaVersion)
	}
	if len(p.ApplicationID) > MaxAppIDLen || hasControlChars(p.ApplicationID) {
		add("application_id: 长度超过 %d 或含控制字符", MaxAppIDLen)
	}
	switch p.Mode {
	case ModeOff, ModeObserve, ModeProtect:
	default:
		add("mode: 未知强制语义 %q（仅支持 OFF|OBSERVE|PROTECT）", p.Mode)
	}
	if p.Version < 0 {
		add("version: 不能为负数 %d", p.Version)
	}

	if len(p.A2APathPrefixes) > MaxPathPrefixes {
		add("a2a_path_prefixes: 数量不能超过 %d", MaxPathPrefixes)
	}
	for i, pfx := range p.A2APathPrefixes {
		trimmed := strings.TrimSpace(pfx)
		if trimmed == "" || !strings.HasPrefix(trimmed, "/") || len(trimmed) > MaxPathLen ||
			strings.ContainsAny(trimmed, "?#") || hasControlChars(pfx) {
			add("a2a_path_prefixes[%d]: 必须以 / 开头、长度 <=%d 且不含 ?/# 或控制字符", i, MaxPathLen)
		}
	}

	if len(p.AllowedCallerAgents) > MaxAllowedAgents {
		add("allowed_caller_agents: 数量不能超过 %d", MaxAllowedAgents)
	}
	for i, agent := range p.AllowedCallerAgents {
		trimmed := strings.TrimSpace(agent)
		if trimmed == "" || len(trimmed) > MaxAgentNameLen || hasControlChars(agent) {
			add("allowed_caller_agents[%d]: 不能为空、长度 <=%d 且不含控制字符", i, MaxAgentNameLen)
		}
	}

	if p.MaxDelegationDepth < MinDelegationDepth || p.MaxDelegationDepth > MaxDelegationDepth {
		add("max_delegation_depth: 必须在 %d..%d 之间，实际 %d", MinDelegationDepth, MaxDelegationDepth, p.MaxDelegationDepth)
	}
	if p.LoopWindowSeconds < MinLoopWindowSeconds || p.LoopWindowSeconds > MaxLoopWindowSeconds {
		add("loop_window_seconds: 必须在 %d..%d 之间，实际 %d", MinLoopWindowSeconds, MaxLoopWindowSeconds, p.LoopWindowSeconds)
	}
	if p.MaxCallsPerTaskWindow < MinMaxCallsPerTaskWindow || p.MaxCallsPerTaskWindow > MaxCallsPerTaskWindow {
		add("max_calls_per_task_window: 必须在 %d..%d 之间，实际 %d", MinMaxCallsPerTaskWindow, MaxCallsPerTaskWindow, p.MaxCallsPerTaskWindow)
	}

	validatePatternList("confidential_read_patterns", p.ConfidentialReadPatterns, add)
	validatePatternList("external_egress_patterns", p.ExternalEgressPatterns, add)

	return errors.Join(errs...)
}

func validatePatternList(field string, patterns []string, add func(string, ...any)) {
	if len(patterns) > MaxPatterns {
		add("%s: 数量不能超过 %d", field, MaxPatterns)
	}
	for i, pat := range patterns {
		trimmed := strings.TrimSpace(pat)
		if trimmed == "" || len(trimmed) > MaxPatternLen || hasControlChars(pat) {
			add("%s[%d]: 不能为空、长度 <=%d 且不含控制字符", field, i, MaxPatternLen)
		}
	}
}

// EngineOptions 运行时引擎装配可选项（测试可注入时钟与有界缓存上限）。
type EngineOptions struct {
	Now          func() time.Time
	CardDedupTTL time.Duration
	CardDedupMax int
	LoopMaxKeys  int
	TaintMaxKeys int
	TaintTTL     time.Duration
}

// Engine A2A 协议安全运行时引擎（Provision 后并发安全、热路径零网络 IO）。
type Engine struct {
	policy               *Policy
	pathPrefixes         []string
	allowedAgents        map[string]struct{}
	confidentialPatterns []string // lowercased
	egressPatterns       []string // lowercased
	cardDedup            *cardDedupCache
	loopTracker          *LoopTracker
	taintTracker         *TaintTracker
	now                  func() time.Time
}

// NewEngine 从已校验的 Policy 构建运行时引擎。
func NewEngine(p *Policy, opts EngineOptions) (*Engine, error) {
	if p == nil {
		return nil, errors.New("a2aguard: nil policy")
	}
	cp := clonePolicy(p)
	applyOffDefaults(&cp)
	if err := ValidatePolicy(&cp); err != nil {
		return nil, err
	}

	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	cardTTL := opts.CardDedupTTL
	if cardTTL <= 0 {
		cardTTL = DefaultCardDedupTTL
	}
	cardMax := opts.CardDedupMax
	if cardMax <= 0 {
		cardMax = DefaultCardDedupMaxEntries
	}
	loopMax := opts.LoopMaxKeys
	if loopMax <= 0 {
		loopMax = DefaultLoopMaxKeys
	}
	taintMax := opts.TaintMaxKeys
	if taintMax <= 0 {
		taintMax = DefaultTaintMaxKeys
	}
	taintTTL := opts.TaintTTL
	if taintTTL <= 0 {
		taintTTL = DefaultTaintTTL
	}

	prefixes := make([]string, 0, len(cp.A2APathPrefixes))
	seenPfx := make(map[string]struct{}, len(cp.A2APathPrefixes))
	for _, pfx := range cp.A2APathPrefixes {
		c := normalizer.CanonicalPath(strings.TrimSpace(pfx))
		if len(c) > 1 {
			c = strings.TrimRight(c, "/")
			if c == "" {
				c = "/"
			}
		}
		if _, dup := seenPfx[c]; !dup {
			seenPfx[c] = struct{}{}
			prefixes = append(prefixes, c)
		}
	}

	allowed := make(map[string]struct{}, len(cp.AllowedCallerAgents))
	for _, a := range cp.AllowedCallerAgents {
		if t := strings.TrimSpace(a); t != "" {
			allowed[t] = struct{}{}
		}
	}

	confPats := normalizeLowerPatterns(cp.ConfidentialReadPatterns)
	egressPats := normalizeLowerPatterns(cp.ExternalEgressPatterns)

	return &Engine{
		policy:               &cp,
		pathPrefixes:         prefixes,
		allowedAgents:        allowed,
		confidentialPatterns: confPats,
		egressPatterns:       egressPats,
		cardDedup:            newCardDedupCache(cardTTL, cardMax),
		loopTracker:          NewLoopTracker(loopMax),
		taintTracker:         NewTaintTracker(taintMax, taintTTL),
		now:                  nowFn,
	}, nil
}

// Policy 返回策略只读引用。
func (e *Engine) Policy() *Policy { return e.policy }

// Mode 返回策略模式（OFF|OBSERVE|PROTECT）。
func (e *Engine) Mode() string { return e.policy.Mode }

// MatchA2APath 判断请求路径是否命中任一 a2a_path_prefixes（完整路径段前缀匹配）。
func (e *Engine) MatchA2APath(reqPath string) bool {
	if e == nil || len(e.pathPrefixes) == 0 {
		return false
	}
	cp := normalizer.CanonicalPath(reqPath)
	for _, pfx := range e.pathPrefixes {
		if normalizer.PrefixSegmentMatch(pfx, cp) {
			return true
		}
	}
	return false
}

// ShouldObserveAgentCard 判断请求是否命中 Agent Card 发现路径且发现开关启用。
func (e *Engine) ShouldObserveAgentCard(method, reqPath string) bool {
	if e == nil || e.policy.Mode == ModeOff || !e.policy.CardDiscoveryEnabled {
		return false
	}
	if !strings.EqualFold(method, "GET") {
		return false
	}
	return IsWellKnownAgentCardPath(reqPath)
}

// MatchesConfidentialPattern 判断文本是否命中任一 confidential_read_patterns（大小写不敏感）。
func (e *Engine) MatchesConfidentialPattern(text string) (string, bool) {
	if e == nil || len(e.confidentialPatterns) == 0 || text == "" {
		return "", false
	}
	lower := strings.ToLower(text)
	for _, pat := range e.confidentialPatterns {
		if strings.Contains(lower, pat) {
			return pat, true
		}
	}
	return "", false
}

// MatchesExternalEgressPattern 判断文本是否命中任一 external_egress_patterns（大小写不敏感）。
func (e *Engine) MatchesExternalEgressPattern(text string) (string, bool) {
	if e == nil || len(e.egressPatterns) == 0 || text == "" {
		return "", false
	}
	lower := strings.ToLower(text)
	for _, pat := range e.egressPatterns {
		if strings.Contains(lower, pat) {
			return pat, true
		}
	}
	return "", false
}

// Close 释放引擎资源（无后台 goroutine；幂等）。
func (e *Engine) Close() {}

func clonePolicy(p *Policy) Policy {
	cp := *p
	cp.A2APathPrefixes = append([]string(nil), p.A2APathPrefixes...)
	cp.AllowedCallerAgents = append([]string(nil), p.AllowedCallerAgents...)
	cp.ConfidentialReadPatterns = append([]string(nil), p.ConfidentialReadPatterns...)
	cp.ExternalEgressPatterns = append([]string(nil), p.ExternalEgressPatterns...)
	return cp
}

func normalizeLowerPatterns(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, p := range in {
		l := strings.ToLower(strings.TrimSpace(p))
		if l == "" {
			continue
		}
		if _, dup := seen[l]; dup {
			continue
		}
		seen[l] = struct{}{}
		out = append(out, l)
	}
	return out
}

func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func stripControlChars(s string, maxLen int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if maxLen > 0 && len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}
