// Package semantic 实现 Phase 9C-2 本地离线 ONNX/SLM 语义防火墙的网关侧纯 Go 客户端、
// 策略校验、熔断器与两级评分决策辅助（通过 Unix Domain Socket 通信，零新增第三方依赖）。
//
// 安全与性能纪律：
//   - socket_path 严格限定在 /var/run/caddy/sidecars/ 或 /run/jiuzhang/ 前缀下，
//     拒绝 ".." 路径穿越、控制字符与 http:// / tcp:// 等网络协议（防 SSRF）；
//   - 严格 JSON 解码（DisallowUnknownFields）+ 全量边界校验，非法配置 fail-closed 拒载；
//   - 热路径严格有界：硬超时（5..200ms）、非阻塞并发信号量（1..256）、熔断器、
//     按 rune 安全截断输入（256..8192）、响应体 <= 16 KiB，绝不透传 Cookie / Authorization；
//   - 证据与日志最小化：DetectorMatch.Evidence 绝不包含原始提示词或请求/响应体文本，
//     仅记录 channel / label / score / model_id / latency_ms / input_runes。
package semantic

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"strings"
)

const (
	// SchemaVersion 本网关支持的 semantic_guard_policy 契约版本（不一致 fail-closed 拒载）。
	SchemaVersion = 1

	// DetectorName 统一管线检测器标识。
	DetectorName = "semantic"

	// 模式词表（跨层冻结契约）。
	ModeOff     = "OFF"
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"

	// 故障处置策略词表（跨层冻结契约）。
	FailOpen   = "FAIL_OPEN"
	FailClosed = "FAIL_CLOSED"

	// 检测通道词表（跨层冻结契约）。
	ChannelLLMPrompt   = "llm_prompt"
	ChannelMCPContent  = "mcp_content"
	ChannelWebGrayzone = "web_grayzone"

	// 规则 ID（跨层冻结契约）。
	RulePromptInjection    = "semantic.prompt_injection"
	RuleJailbreak          = "semantic.jailbreak"
	RuleIndirectInjection  = "semantic.indirect_injection"
	RuleWebPayload         = "semantic.web_payload"
	RuleSidecarUnavailable = "semantic.sidecar_unavailable"

	// 分类器标签词表。
	LabelSafe              = "safe"
	LabelPromptInjection   = "prompt_injection"
	LabelJailbreak         = "jailbreak"
	LabelIndirectInjection = "indirect_injection"
	LabelWebPayload        = "web_payload"

	// 允许的 Unix Socket 路径前缀（与 server / web 严格一致，防路径穿越与 TCP/HTTP SSRF）。
	AllowedSocketPrefixCaddy    = "/var/run/caddy/sidecars/"
	AllowedSocketPrefixJiuzhang = "/run/jiuzhang/"
	DefaultSocketPath           = "/var/run/caddy/sidecars/semantic.sock"

	// 策略字段护栏边界与默认值（与 server/internal/semanticguard 及 web/src/api/semanticGuard.ts 严格对齐）。
	MaxAppIDLen                    = 128
	MaxSocketPathLen               = 256
	MinTimeoutMS                   = 5
	MaxTimeoutMS                   = 200
	DefaultTimeoutMS               = 15
	MinConcurrency                 = 1
	MaxConcurrency                 = 256
	DefaultConcurrency             = 32
	MinInputRunes                  = 256
	MaxInputRunes                  = 8192
	DefaultInputRunes              = 4096
	MinBlockThreshold              = 0.50
	MaxBlockThreshold              = 0.99
	DefaultBlockThreshold          = 0.85
	MinObserveThreshold            = 0.10
	MaxObserveThreshold            = 0.99
	DefaultObserveThreshold        = 0.50
	MinCircuitFailureThreshold     = 1
	MaxCircuitFailureThreshold     = 100
	DefaultCircuitFailureThreshold = 5
	MinCircuitOpenSeconds          = 5
	MaxCircuitOpenSeconds          = 300
	DefaultCircuitOpenSeconds      = 30
)

// Policy 发布通道下发的 semantic_guard_policy 处理器段（严格解码，json tag 为跨层冻结契约）。
type Policy struct {
	SchemaVersion           int     `json:"schema_version"`
	ApplicationID           string  `json:"application_id"`
	Mode                    string  `json:"mode"`
	Version                 int     `json:"version"`
	SocketPath              string  `json:"socket_path"`
	TimeoutMS               int     `json:"timeout_ms"`
	MaxConcurrency          int     `json:"max_concurrency"`
	MaxInputRunes           int     `json:"max_input_runes"`
	BlockThreshold          float64 `json:"block_threshold"`
	ObserveThreshold        float64 `json:"observe_threshold"`
	FailPolicy              string  `json:"fail_policy"`
	InspectLLMPrompts       bool    `json:"inspect_llm_prompts"`
	InspectMCPContent       bool    `json:"inspect_mcp_content"`
	InspectWebGrayzone      bool    `json:"inspect_web_grayzone"`
	CircuitFailureThreshold int     `json:"circuit_failure_threshold"`
	CircuitOpenSeconds      int     `json:"circuit_open_seconds"`

	// testSocketPathOverride 仅供单元测试覆写临时 Unix Socket 目录使用，绝不接受 JSON 解码。
	testSocketPathOverride string `json:"-"`
}

// defaultPolicyGuardrails 返回预填充默认护栏的 Policy（SchemaVersion 与 Mode 留空以强制显式声明）。
func defaultPolicyGuardrails() Policy {
	return Policy{
		SocketPath:              DefaultSocketPath,
		TimeoutMS:               DefaultTimeoutMS,
		MaxConcurrency:          DefaultConcurrency,
		MaxInputRunes:           DefaultInputRunes,
		BlockThreshold:          DefaultBlockThreshold,
		ObserveThreshold:        DefaultObserveThreshold,
		FailPolicy:              FailOpen,
		CircuitFailureThreshold: DefaultCircuitFailureThreshold,
		CircuitOpenSeconds:      DefaultCircuitOpenSeconds,
	}
}

// EffectiveSocketPath 返回运行时实际拨号的 Unix Socket 路径。
// 生产路径恒为通过 ValidateSocketPath 校验的 Policy.SocketPath；
// 仅当测试代码显式调用 SetTestSocketPath 注入临时目录路径时返回覆写路径。
func (p *Policy) EffectiveSocketPath() string {
	if p == nil {
		return ""
	}
	if p.testSocketPathOverride != "" {
		return p.testSocketPathOverride
	}
	return p.SocketPath
}

// SetTestSocketPath 仅供单元测试为本地临时 Unix Socket 目录设置覆写路径（永不从 JSON 接受）。
// 仍强制拒绝非绝对路径、URI 协议方案（http:// / tcp://）与控制字符。
func (p *Policy) SetTestSocketPath(socketPath string) error {
	if p == nil {
		return errors.New("policy is nil")
	}
	if err := validateTestSocketPath(socketPath); err != nil {
		return err
	}
	p.testSocketPathOverride = socketPath
	return nil
}

// Clone 返回 Policy 浅拷贝（包含已验证字段与测试覆写）。
func (p *Policy) Clone() *Policy {
	if p == nil {
		return nil
	}
	cp := *p
	return &cp
}

// ParseAndValidatePolicy 严格解码（DisallowUnknownFields）并全量校验 semantic_guard_policy。
// 任何未知字段、不支持的 schema_version、非法枚举/边界、越权 socket_path 或多余尾缀内容
// 均拒绝加载（fail-closed）。
func ParseAndValidatePolicy(raw json.RawMessage) (*Policy, error) {
	p := defaultPolicyGuardrails()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("semantic_guard_policy: 配置结构解析失败（拒绝加载）: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("semantic_guard_policy: 配置含多余内容（拒绝加载）")
	}
	// 防御：即使结构体被反射构造，也不允许保留任何未显式注入的测试覆写。
	p.testSocketPathOverride = ""
	if err := ValidatePolicy(&p); err != nil {
		return nil, fmt.Errorf("semantic_guard_policy: 配置校验未通过（拒绝加载）: %w", err)
	}
	return &p, nil
}

// ValidatePolicy 校验解析后的 semantic_guard_policy 全量边界与安全约束。
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
		add("mode: 非法取值 %q（仅支持 OFF|OBSERVE|PROTECT）", p.Mode)
	}
	if p.Version < 0 {
		add("version: 不能为负数 (%d)", p.Version)
	}
	if err := ValidateSocketPath(p.SocketPath); err != nil {
		add("socket_path: %v", err)
	}
	if p.TimeoutMS < MinTimeoutMS || p.TimeoutMS > MaxTimeoutMS {
		add("timeout_ms: %d 超出允许范围 [%d, %d]", p.TimeoutMS, MinTimeoutMS, MaxTimeoutMS)
	}
	if p.MaxConcurrency < MinConcurrency || p.MaxConcurrency > MaxConcurrency {
		add("max_concurrency: %d 超出允许范围 [%d, %d]", p.MaxConcurrency, MinConcurrency, MaxConcurrency)
	}
	if p.MaxInputRunes < MinInputRunes || p.MaxInputRunes > MaxInputRunes {
		add("max_input_runes: %d 超出允许范围 [%d, %d]", p.MaxInputRunes, MinInputRunes, MaxInputRunes)
	}
	if !isFiniteFloat(p.BlockThreshold) || p.BlockThreshold < MinBlockThreshold || p.BlockThreshold > MaxBlockThreshold {
		add("block_threshold: %v 超出允许范围 [%.2f, %.2f]", p.BlockThreshold, MinBlockThreshold, MaxBlockThreshold)
	}
	if !isFiniteFloat(p.ObserveThreshold) || p.ObserveThreshold < MinObserveThreshold || p.ObserveThreshold > MaxObserveThreshold {
		add("observe_threshold: %v 超出允许范围 [%.2f, %.2f]", p.ObserveThreshold, MinObserveThreshold, MaxObserveThreshold)
	}
	if isFiniteFloat(p.ObserveThreshold) && isFiniteFloat(p.BlockThreshold) && p.ObserveThreshold > p.BlockThreshold {
		add("observe_threshold (%.4f) 不能大于 block_threshold (%.4f)", p.ObserveThreshold, p.BlockThreshold)
	}
	switch p.FailPolicy {
	case FailOpen, FailClosed:
	default:
		add("fail_policy: 非法取值 %q（仅支持 FAIL_OPEN|FAIL_CLOSED）", p.FailPolicy)
	}
	if p.CircuitFailureThreshold < MinCircuitFailureThreshold || p.CircuitFailureThreshold > MaxCircuitFailureThreshold {
		add("circuit_failure_threshold: %d 超出允许范围 [%d, %d]", p.CircuitFailureThreshold, MinCircuitFailureThreshold, MaxCircuitFailureThreshold)
	}
	if p.CircuitOpenSeconds < MinCircuitOpenSeconds || p.CircuitOpenSeconds > MaxCircuitOpenSeconds {
		add("circuit_open_seconds: %d 超出允许范围 [%d, %d]", p.CircuitOpenSeconds, MinCircuitOpenSeconds, MaxCircuitOpenSeconds)
	}

	return errors.Join(errs...)
}

// ValidateSocketPath 严格校验 Unix Domain Socket 路径：
//   - 必须为绝对路径且以 /var/run/caddy/sidecars/ 或 /run/jiuzhang/ 开头；
//   - 拒绝空值、首尾空白、超长（>256）、控制字符、反斜杠、".." 路径穿越、
//     以及 http:// / https:// / tcp:// / unix:// 等 URI 协议前缀；
//   - 规范化后仍须位于允许目录前缀之下且指向具体 socket 文件而非目录本身。
func ValidateSocketPath(socketPath string) error {
	if socketPath == "" {
		return errors.New("不能为空")
	}
	if len(socketPath) > MaxSocketPathLen {
		return fmt.Errorf("长度 %d 超过上限 %d", len(socketPath), MaxSocketPathLen)
	}
	if strings.TrimSpace(socketPath) != socketPath {
		return errors.New("不能包含首尾空白字符")
	}
	if hasControlChars(socketPath) || strings.ContainsAny(socketPath, " \t\\") {
		return errors.New("不能包含空白、反斜杠或控制字符")
	}
	lower := strings.ToLower(socketPath)
	if strings.Contains(lower, "://") ||
		strings.HasPrefix(lower, "http:") ||
		strings.HasPrefix(lower, "https:") ||
		strings.HasPrefix(lower, "tcp:") ||
		strings.HasPrefix(lower, "unix:") {
		return errors.New("禁止使用 http://、tcp:// 或其他网络/URI 方案，仅允许本地 Unix Socket 路径")
	}
	if strings.Contains(socketPath, "..") {
		return errors.New("禁止包含 '..' 路径穿越段")
	}
	if strings.Contains(socketPath, "//") {
		return errors.New("禁止包含重复斜杠 '//'")
	}
	if !strings.HasPrefix(socketPath, "/") {
		return errors.New("必须为绝对路径")
	}
	if strings.HasSuffix(socketPath, "/") {
		return errors.New("必须指向具体的 socket 文件，不能以 '/' 结尾")
	}
	if !hasAllowedSocketPrefix(socketPath) {
		return fmt.Errorf("必须以 %q 或 %q 开头", AllowedSocketPrefixCaddy, AllowedSocketPrefixJiuzhang)
	}
	cleaned := path.Clean(socketPath)
	if cleaned != socketPath || !hasAllowedSocketPrefix(cleaned) {
		return fmt.Errorf("必须为规范化绝对路径且位于允许目录（%q 或 %q）下", AllowedSocketPrefixCaddy, AllowedSocketPrefixJiuzhang)
	}
	if cleaned == strings.TrimSuffix(AllowedSocketPrefixCaddy, "/") ||
		cleaned == strings.TrimSuffix(AllowedSocketPrefixJiuzhang, "/") {
		return errors.New("必须指定目录内的 socket 文件名")
	}
	return nil
}

func hasAllowedSocketPrefix(p string) bool {
	return strings.HasPrefix(p, AllowedSocketPrefixCaddy) || strings.HasPrefix(p, AllowedSocketPrefixJiuzhang)
}

func validateTestSocketPath(socketPath string) error {
	if socketPath == "" {
		return errors.New("test socket path cannot be empty")
	}
	if len(socketPath) > MaxSocketPathLen {
		return fmt.Errorf("test socket path too long (%d > %d)", len(socketPath), MaxSocketPathLen)
	}
	if hasControlChars(socketPath) {
		return errors.New("test socket path cannot contain control chars")
	}
	lower := strings.ToLower(socketPath)
	if strings.Contains(lower, "://") {
		return errors.New("test socket path cannot be a URI")
	}
	if !strings.HasPrefix(socketPath, "/") || strings.HasSuffix(socketPath, "/") {
		return errors.New("test socket path must be an absolute file path")
	}
	return nil
}

func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func isFiniteFloat(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}
