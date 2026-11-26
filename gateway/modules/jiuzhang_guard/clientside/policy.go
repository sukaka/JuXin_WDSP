// Package clientside 实现 Phase 9B 客户端供应链安全防护（Magecart 防护 / PCI DSS 4.0 6.4.3 & 11.6.1）：
//   - 严格策略解码与校验（DisallowUnknownFields，fail-closed 拒载）；
//   - CSP 策略头编译与 CR/LF 注入防护；
//   - 有界（<=1MiB）未压缩 2xx text/html 单遍脚本扫描、SRI 篡改检测、可选未授权脚本剥离与去重缓存；
//   - 保留本地端点 /_wdsp/csp/v1/report（限体 <=16KiB、每 IP 限速、多格式解析、URL 脱敏）与 /_wdsp/cs/v1/probe.js（零依赖隐私安全探针）。
package clientside

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
)

const (
	// SchemaVersion 本网关支持的 client_side_policy 契约版本（不一致 fail-closed 拒载）。
	SchemaVersion = 1

	// 模式枚举（冻结契约）。
	ModeOff     = "OFF"
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"

	// CSP 模式枚举（冻结契约）。
	CSPModeOff        = "OFF"
	CSPModeReportOnly = "REPORT_ONLY"
	CSPModeEnforce    = "ENFORCE"

	// 脚本类型枚举（冻结契约）。
	ScriptTypeExternal   = "EXTERNAL"
	ScriptTypeInlineHash = "INLINE_HASH"

	// 脚本状态枚举（冻结契约）。
	ScriptStatusAuthorized = "AUTHORIZED"
	ScriptStatusBlocked    = "BLOCKED"

	// 违规/事件类型枚举（冻结契约）。
	ViolationScriptObserved     = "SCRIPT_OBSERVED"
	ViolationUnauthorizedScript = "UNAUTHORIZED_SCRIPT"
	ViolationScriptTampered     = "SCRIPT_TAMPERED"
	ViolationCSPViolation       = "CSP_VIOLATION"
	ViolationProbeAlert         = "PROBE_ALERT"

	// 处置动作枚举（冻结契约）。
	ActionObserved    = "OBSERVED"
	ActionReported    = "REPORTED"
	ActionStripped    = "STRIPPED"
	ActionCSPEnforced = "CSP_ENFORCED"

	// 保留本地命名空间与固定协议端点（绝不反向代理）。
	CSPReservedNamespace = "/_wdsp/csp/v1/"
	CSPReportPath        = "/_wdsp/csp/v1/report"
	CSReservedNamespace  = "/_wdsp/cs/v1/"
	ProbeScriptPath      = "/_wdsp/cs/v1/probe.js"

	// 校验与运行时资源上限（与 server/web 跨层对齐）。
	MaxSensitivePaths            = 64
	MaxPathLen                   = 512
	MaxOrigins                   = 64
	MaxOriginLen                 = 512
	MaxCustomDirectivesLen       = 2048
	MaxAuthorizedScripts         = 4096
	MaxScriptURLLen              = 2048
	MaxSRILen                    = 256
	MaxAppIDLen                  = 128
	MaxHTMLScanBytes             = 1 << 20 // 1 MiB
	MaxReportBodyBytes           = 16 << 10 // 16 KiB
	MaxReportsPerBatch           = 16
	DefaultDedupTTL              = 60 * time.Second
	DefaultDedupMaxEntries       = 4096
	DefaultReportRateLimitPerMin = 30
	DefaultReportRateLimitMaxIPs = 4096
)

// Policy 发布通道下发的 client_side_policy 处理器段（严格解码，json tag 为跨分片冻结契约）。
type Policy struct {
	SchemaVersion            int                `json:"schema_version"`
	ApplicationID            string             `json:"application_id"`
	Mode                     string             `json:"mode"`
	Version                  int                `json:"version"`
	CSPMode                  string             `json:"csp_mode"`
	SensitivePaths           []string           `json:"sensitive_paths"`
	ProbeEnabled             bool               `json:"probe_enabled"`
	StripUnauthorizedScripts bool               `json:"strip_unauthorized_scripts"`
	AllowedScriptOrigins     []string           `json:"allowed_script_origins"`
	AllowedConnectOrigins    []string           `json:"allowed_connect_origins"`
	AllowedFormOrigins       []string           `json:"allowed_form_origins"`
	CustomCSPDirectives      string             `json:"custom_csp_directives"`
	AuthorizedScripts        []AuthorizedScript `json:"authorized_scripts"`
}

// AuthorizedScript 预授权或显式封禁脚本清单项（冻结契约）。
type AuthorizedScript struct {
	ScriptURL  string `json:"script_url"`
	ScriptType string `json:"script_type"` // EXTERNAL | INLINE_HASH
	SRIHash    string `json:"sri_hash"`
	Status     string `json:"status"` // AUTHORIZED | BLOCKED
}

// ParseAndValidatePolicy 严格解码（DisallowUnknownFields）并全量校验 client_side_policy。
// 任何未知字段、不支持的 schema_version、非法枚举/边界或控制字符注入均拒绝加载（fail-closed）。
func ParseAndValidatePolicy(raw json.RawMessage) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("client_side_policy: 配置结构解析失败（拒绝加载）: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("client_side_policy: 配置含多余内容（拒绝加载）")
	}
	applyPolicyDefaults(&p)
	if err := ValidatePolicy(&p); err != nil {
		return nil, fmt.Errorf("client_side_policy: 配置校验未通过（拒绝加载）: %w", err)
	}
	return &p, nil
}

func applyPolicyDefaults(p *Policy) {
	if p.CSPMode == "" {
		p.CSPMode = CSPModeOff
	}
}

// ValidatePolicy 校验解析后的 client_side_policy。
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
	switch p.CSPMode {
	case CSPModeOff, CSPModeReportOnly, CSPModeEnforce:
	default:
		add("csp_mode: 非法模式 %q（仅支持 OFF|REPORT_ONLY|ENFORCE）", p.CSPMode)
	}

	if len(p.SensitivePaths) > MaxSensitivePaths {
		add("sensitive_paths: 数量不能超过 %d", MaxSensitivePaths)
	}
	for i, sp := range p.SensitivePaths {
		trimmed := strings.TrimSpace(sp)
		if trimmed == "" || !strings.HasPrefix(trimmed, "/") || len(trimmed) > MaxPathLen ||
			strings.ContainsAny(trimmed, "?#") || hasControlChars(sp) {
			add("sensitive_paths[%d]: 必须以 / 开头、长度 <=%d 且不含 ?/# 或控制字符", i, MaxPathLen)
		}
	}

	validateOriginList("allowed_script_origins", p.AllowedScriptOrigins, add)
	validateOriginList("allowed_connect_origins", p.AllowedConnectOrigins, add)
	validateOriginList("allowed_form_origins", p.AllowedFormOrigins, add)

	if len(p.CustomCSPDirectives) > MaxCustomDirectivesLen || hasControlChars(p.CustomCSPDirectives) {
		add("custom_csp_directives: 长度不能超过 %d 且不得包含 CR/LF 或控制字符", MaxCustomDirectivesLen)
	}

	if len(p.AuthorizedScripts) > MaxAuthorizedScripts {
		add("authorized_scripts: 数量不能超过 %d", MaxAuthorizedScripts)
	}
	for i, s := range p.AuthorizedScripts {
		su := strings.TrimSpace(s.ScriptURL)
		if su == "" || len(su) > MaxScriptURLLen || hasControlChars(s.ScriptURL) {
			add("authorized_scripts[%d].script_url: 不能为空、长度 <=%d 且不含控制字符", i, MaxScriptURLLen)
		}
		switch s.ScriptType {
		case ScriptTypeExternal, ScriptTypeInlineHash:
		default:
			add("authorized_scripts[%d].script_type: 仅支持 EXTERNAL|INLINE_HASH，实际 %q", i, s.ScriptType)
		}
		if s.SRIHash != "" {
			if err := ValidateSRIHash(s.SRIHash); err != nil {
				add("authorized_scripts[%d].sri_hash: %v", i, err)
			}
		}
		switch s.Status {
		case ScriptStatusAuthorized, ScriptStatusBlocked:
		default:
			add("authorized_scripts[%d].status: 仅支持 AUTHORIZED|BLOCKED，实际 %q", i, s.Status)
		}
	}

	if len(errs) == 0 && p.Mode != ModeOff && p.CSPMode != CSPModeOff {
		if _, _, err := CompileCSP(p); err != nil {
			add("csp: %v", err)
		}
	}

	return errors.Join(errs...)
}

func validateOriginList(field string, origins []string, add func(string, ...any)) {
	if len(origins) > MaxOrigins {
		add("%s: 数量不能超过 %d", field, MaxOrigins)
	}
	for i, orig := range origins {
		if err := ValidateCSPSourceToken(orig); err != nil {
			add("%s[%d]: %v", field, i, err)
		}
	}
}

// ValidateSRIHash 校验 SRI 摘要（单条或空格分隔多条 sha256-/sha384-/sha512-<base64>）。
func ValidateSRIHash(raw string) error {
	if len(raw) > MaxSRILen || hasControlChars(raw) {
		return fmt.Errorf("长度超过 %d 或含控制字符", MaxSRILen)
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return errors.New("不能为空")
	}
	for _, tok := range fields {
		if !isSingleValidSRI(tok) {
			return fmt.Errorf("非法 SRI 摘要格式 %q（须为 sha256-/sha384-/sha512-<base64>）", tok)
		}
	}
	return nil
}

func isSingleValidSRI(tok string) bool {
	var body string
	switch {
	case strings.HasPrefix(tok, "sha256-"):
		body = strings.TrimPrefix(tok, "sha256-")
	case strings.HasPrefix(tok, "sha384-"):
		body = strings.TrimPrefix(tok, "sha384-")
	case strings.HasPrefix(tok, "sha512-"):
		body = strings.TrimPrefix(tok, "sha512-")
	default:
		return false
	}
	if len(body) < 4 || len(body) > 128 {
		return false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		isB64 := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
		if !isB64 {
			return false
		}
	}
	return true
}

// EngineOptions 运行时引擎装配可选项（测试可注入时钟与有界缓存上限）。
type EngineOptions struct {
	Now                 func() time.Time
	DedupTTL            time.Duration
	DedupMaxEntries     int
	ReportRateLimitRPM  int
	ReportRateMaxIPs    int
}

// Engine 客户端供应链安全运行时引擎（Provision 后并发安全、热路径零网络 IO）。
type Engine struct {
	policy         *Policy
	cspHeaderName  string
	cspHeaderValue string
	sensitivePaths []string
	authExternal   map[string]AuthorizedScript // 规范化 URL（去查询串/凭据）与原始 URL 映射
	authInline     map[string]AuthorizedScript // hash（"sha256-..." 与 "inline:sha256-..."）映射
	allowedOrigins []originMatcher
	dedup          *scriptDedupCache
	reportLimiter  *ipRateLimiter
	now            func() time.Time
}

// NewEngine 从已校验的 Policy 构建运行时引擎。
func NewEngine(p *Policy, opts EngineOptions) (*Engine, error) {
	if p == nil {
		return nil, errors.New("clientside: nil policy")
	}
	cp := clonePolicy(p)
	applyPolicyDefaults(&cp)
	if err := ValidatePolicy(&cp); err != nil {
		return nil, err
	}

	cspName, cspVal, err := CompileCSP(&cp)
	if err != nil {
		return nil, err
	}

	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	dedupTTL := opts.DedupTTL
	if dedupTTL <= 0 {
		dedupTTL = DefaultDedupTTL
	}
	dedupMax := opts.DedupMaxEntries
	if dedupMax <= 0 {
		dedupMax = DefaultDedupMaxEntries
	}
	rlRPM := opts.ReportRateLimitRPM
	if rlRPM <= 0 {
		rlRPM = DefaultReportRateLimitPerMin
	}
	rlMaxIPs := opts.ReportRateMaxIPs
	if rlMaxIPs <= 0 {
		rlMaxIPs = DefaultReportRateLimitMaxIPs
	}

	sens := make([]string, 0, len(cp.SensitivePaths))
	for _, sp := range cp.SensitivePaths {
		sens = append(sens, normalizer.CanonicalPath(strings.TrimSpace(sp)))
	}

	authExt := make(map[string]AuthorizedScript, len(cp.AuthorizedScripts))
	authInl := make(map[string]AuthorizedScript)
	for _, sc := range cp.AuthorizedScripts {
		sc.ScriptURL = strings.TrimSpace(sc.ScriptURL)
		sc.SRIHash = strings.TrimSpace(sc.SRIHash)
		switch sc.ScriptType {
		case ScriptTypeExternal:
			putAuthScript(authExt, sc.ScriptURL, sc)
			if stripped := stripQueryFragmentCreds(sc.ScriptURL); stripped != "" && stripped != sc.ScriptURL {
				putAuthScript(authExt, stripped, sc)
			}
			// 若配置为绝对 URL，同时按规范化小写 scheme+host 建索引。
			if norm := normalizeExternalAuthKey(sc.ScriptURL); norm != "" {
				putAuthScript(authExt, norm, sc)
			}
		case ScriptTypeInlineHash:
			putAuthScript(authInl, sc.ScriptURL, sc)
			if strings.HasPrefix(sc.ScriptURL, "inline:") {
				putAuthScript(authInl, strings.TrimPrefix(sc.ScriptURL, "inline:"), sc)
			} else {
				putAuthScript(authInl, "inline:"+sc.ScriptURL, sc)
			}
			if sc.SRIHash != "" {
				putAuthScript(authInl, sc.SRIHash, sc)
				putAuthScript(authInl, "inline:"+sc.SRIHash, sc)
			}
		}
	}

	matchers := make([]originMatcher, 0, len(cp.AllowedScriptOrigins))
	for _, tok := range cp.AllowedScriptOrigins {
		if m, ok := compileOriginMatcher(tok); ok {
			matchers = append(matchers, m)
		}
	}

	return &Engine{
		policy:         &cp,
		cspHeaderName:  cspName,
		cspHeaderValue: cspVal,
		sensitivePaths: sens,
		authExternal:   authExt,
		authInline:     authInl,
		allowedOrigins: matchers,
		dedup:          newScriptDedupCache(dedupTTL, dedupMax),
		reportLimiter:  newIPRateLimiter(rlRPM, time.Minute, rlMaxIPs),
		now:            nowFn,
	}, nil
}

// putAuthScript 插入授权脚本索引；同键冲突时 BLOCKED 优先于 AUTHORIZED（安全优先）。
func putAuthScript(m map[string]AuthorizedScript, key string, sc AuthorizedScript) {
	if key == "" {
		return
	}
	if prev, exists := m[key]; exists && prev.Status == ScriptStatusBlocked && sc.Status != ScriptStatusBlocked {
		return
	}
	m[key] = sc
}

// Policy 返回策略只读引用。
func (e *Engine) Policy() *Policy { return e.policy }

// Mode 返回策略模式（OFF|OBSERVE|PROTECT）。
func (e *Engine) Mode() string { return e.policy.Mode }

// CSPHeader 返回编译后的 CSP 响应头名与值（未启用时均为空串）。
func (e *Engine) CSPHeader() (name, value string) {
	return e.cspHeaderName, e.cspHeaderValue
}

// MatchSensitivePath 判断规范化请求路径是否命中敏感路径（精确或完整路径段前缀匹配）。
func (e *Engine) MatchSensitivePath(reqPath string) bool {
	if e == nil || len(e.sensitivePaths) == 0 {
		return false
	}
	cp := normalizer.CanonicalPath(reqPath)
	for _, sp := range e.sensitivePaths {
		if normalizer.PrefixSegmentMatch(sp, cp) {
			return true
		}
	}
	return false
}

// ShouldInjectProbe 判断当前请求路径是否应注入防窃取探针脚本。
func (e *Engine) ShouldInjectProbe(reqPath string) bool {
	if e == nil || e.policy.Mode == ModeOff || !e.policy.ProbeEnabled {
		return false
	}
	return e.MatchSensitivePath(reqPath)
}

// Close 释放引擎资源（无后台 goroutine；幂等）。
func (e *Engine) Close() {}

func clonePolicy(p *Policy) Policy {
	cp := *p
	cp.SensitivePaths = append([]string(nil), p.SensitivePaths...)
	cp.AllowedScriptOrigins = append([]string(nil), p.AllowedScriptOrigins...)
	cp.AllowedConnectOrigins = append([]string(nil), p.AllowedConnectOrigins...)
	cp.AllowedFormOrigins = append([]string(nil), p.AllowedFormOrigins...)
	cp.AuthorizedScripts = append([]AuthorizedScript(nil), p.AuthorizedScripts...)
	return cp
}

func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func stripQueryFragmentCreds(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		if idx := strings.IndexAny(raw, "?#"); idx >= 0 {
			return raw[:idx]
		}
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		if idx := strings.IndexAny(raw, "?#"); idx >= 0 {
			return raw[:idx]
		}
		return raw
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	return u.String()
}

func normalizeExternalAuthKey(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || (strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//")) {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = normalizeOriginHost(u.Scheme, u.Host)
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	return u.String()
}

func normalizeOriginHost(scheme, host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	switch scheme {
	case "https", "wss":
		if strings.HasSuffix(h, ":443") {
			return strings.TrimSuffix(h, ":443")
		}
	case "http", "ws":
		if strings.HasSuffix(h, ":80") {
			return strings.TrimSuffix(h, ":80")
		}
	}
	return h
}
