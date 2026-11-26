// validate.go 本地离线语义防火墙策略与 Unix Socket 路径安全校验（纯函数，无网络 IO）。
package semanticguard

import (
	"fmt"
	"math"
	"path"
	"strings"
)

// FieldError 字段级校验错误。
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError 校验错误集合（handler 映射为 400 details）。
type ValidationError struct {
	Errors []FieldError
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("semantic guard validation failed: %d field(s)", len(e.Errors))
}

func validMode(m string) bool {
	return m == ModeOff || m == ModeObserve || m == ModeProtect
}

func validFailPolicy(fp string) bool {
	return fp == FailPolicyOpen || fp == FailPolicyClosed
}

// NormalizePolicy 归一化语义防火墙策略字段（枚举大写与首尾去空白）。
func NormalizePolicy(p *Policy) {
	p.SchemaVersion = SchemaVersion
	p.Mode = strings.ToUpper(strings.TrimSpace(p.Mode))
	p.FailPolicy = strings.ToUpper(strings.TrimSpace(p.FailPolicy))
	p.SocketPath = strings.TrimSpace(p.SocketPath)
}

// ValidateSocketPath 严格校验本地 Unix Domain Socket 路径：
//   - 长度 <= 256，非空，不含空白、控制字符、反斜杠或 URL scheme（禁止 http://、tcp:// 等 SSRF）；
//   - 必须以 /var/run/caddy/sidecars/ 或 /run/jiuzhang/ 开头，且包含具体文件名（非目录本身）；
//   - 禁止包含 ".."、重复斜杠 "//" 或未归一化段（path.Clean 后须与原串完全一致且仍在白名单前缀下）。
func ValidateSocketPath(socketPath string) string {
	return validateSocketPathWithPrefixes(socketPath, AllowedSocketPrefixCaddy, AllowedSocketPrefixRun)
}

func validateSocketPathWithPrefixes(socketPath string, prefixes ...string) string {
	if socketPath == "" {
		return "Unix Socket 路径不能为空"
	}
	if len(socketPath) > MaxSocketPathLen {
		return fmt.Sprintf("Unix Socket 路径长度不能超过 %d 字符", MaxSocketPathLen)
	}
	if hasControlChars(socketPath) || strings.ContainsAny(socketPath, " \t\\") {
		return "Unix Socket 路径不得包含空白、反斜杠或控制字符"
	}
	lower := strings.ToLower(socketPath)
	if strings.Contains(lower, "://") ||
		strings.HasPrefix(lower, "http:") ||
		strings.HasPrefix(lower, "https:") ||
		strings.HasPrefix(lower, "tcp:") ||
		strings.HasPrefix(lower, "unix:") {
		return "Unix Socket 路径必须为本地绝对路径，禁止网络协议地址"
	}
	if strings.Contains(socketPath, "..") {
		return "Unix Socket 路径不得包含上级目录引用（..）"
	}
	if strings.Contains(socketPath, "//") {
		return "Unix Socket 路径不得包含重复斜杠"
	}
	if strings.HasSuffix(socketPath, "/") {
		return "Unix Socket 路径必须指向具体 Socket 文件，不能以 / 结尾"
	}
	if !hasAnyPrefix(socketPath, prefixes) {
		return fmt.Sprintf("Unix Socket 路径必须位于 %s 或 %s 目录下", AllowedSocketPrefixCaddy, AllowedSocketPrefixRun)
	}
	cleaned := path.Clean(socketPath)
	if cleaned != socketPath || !hasAnyPrefix(cleaned, prefixes) {
		return "Unix Socket 路径必须为规范化绝对路径且不得跳出受控目录"
	}
	return ""
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(s, p) && len(s) > len(p) {
			return true
		}
	}
	return false
}

// ValidatePolicy 校验应用级语义防火墙策略全字段边界。
func ValidatePolicy(p *Policy) []FieldError {
	errs := []FieldError{}
	add := func(field, msg string) {
		errs = append(errs, FieldError{Field: field, Message: msg})
	}

	if !validMode(p.Mode) {
		add("mode", "仅支持 OFF / OBSERVE / PROTECT")
	}
	if msg := ValidateSocketPath(p.SocketPath); msg != "" {
		add("socket_path", msg)
	}
	if p.TimeoutMs < MinTimeoutMs || p.TimeoutMs > MaxTimeoutMs {
		add("timeout_ms", fmt.Sprintf("单次推理超时必须在 %d~%d 毫秒之间", MinTimeoutMs, MaxTimeoutMs))
	}
	if p.MaxConcurrency < MinMaxConcurrency || p.MaxConcurrency > MaxMaxConcurrency {
		add("max_concurrency", fmt.Sprintf("最大并发推理数必须在 %d~%d 之间", MinMaxConcurrency, MaxMaxConcurrency))
	}
	if p.MaxInputRunes < MinMaxInputRunes || p.MaxInputRunes > MaxMaxInputRunes {
		add("max_input_runes", fmt.Sprintf("单次输入截断字符数必须在 %d~%d 之间", MinMaxInputRunes, MaxMaxInputRunes))
	}

	obsValid := !math.IsNaN(p.ObserveThreshold) && !math.IsInf(p.ObserveThreshold, 0) &&
		p.ObserveThreshold >= MinObserveThreshold && p.ObserveThreshold <= MaxObserveThreshold
	if !obsValid {
		add("observe_threshold", fmt.Sprintf("观察阈值必须在 %.2f~%.2f 之间", MinObserveThreshold, MaxObserveThreshold))
	}
	blkValid := !math.IsNaN(p.BlockThreshold) && !math.IsInf(p.BlockThreshold, 0) &&
		p.BlockThreshold >= MinBlockThreshold && p.BlockThreshold <= MaxBlockThreshold
	if !blkValid {
		add("block_threshold", fmt.Sprintf("阻断阈值必须在 %.2f~%.2f 之间", MinBlockThreshold, MaxBlockThreshold))
	}
	if obsValid && blkValid && p.ObserveThreshold > p.BlockThreshold {
		add("observe_threshold", "观察阈值不能大于阻断阈值")
	}

	if !validFailPolicy(p.FailPolicy) {
		add("fail_policy", "仅支持 FAIL_OPEN / FAIL_CLOSED")
	}
	if p.CircuitFailureThreshold < MinCircuitFailureThreshold || p.CircuitFailureThreshold > MaxCircuitFailureThreshold {
		add("circuit_failure_threshold", fmt.Sprintf("熔断连续失败阈值必须在 %d~%d 之间", MinCircuitFailureThreshold, MaxCircuitFailureThreshold))
	}
	if p.CircuitOpenSeconds < MinCircuitOpenSeconds || p.CircuitOpenSeconds > MaxCircuitOpenSeconds {
		add("circuit_open_seconds", fmt.Sprintf("熔断打开时长必须在 %d~%d 秒之间", MinCircuitOpenSeconds, MaxCircuitOpenSeconds))
	}

	return errs
}

func hasControlChars(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

func hasDisallowedTextControlChars(s string) bool {
	for _, c := range s {
		if c == '\n' || c == '\t' {
			continue
		}
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}
