// validate.go Wasm 检测插件配置参数、Base64 二进制与 SHA-256 校验（纯函数，无网络/数据库 IO）。
package wasmplugins

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	namePattern   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

// maxEncodedWasmBase64Len 是 4MiB 二进制的标准 Base64 长度上限加少量空白余量。
const maxEncodedWasmBase64Len = ((MaxWasmBinaryBytes+2)/3)*4 + 1024

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
	return fmt.Sprintf("wasm plugin validation failed: %d field(s)", len(e.Errors))
}

func validMode(m string) bool {
	return m == ModeOff || m == ModeObserve || m == ModeProtect
}

func validFailPolicy(fp string) bool {
	return fp == FailPolicyOpen || fp == FailPolicyClosed
}

// NormalizePathPrefixes 归一化路径前缀列表（去空白、去重保序；保证非 nil 切片）。
func NormalizePathPrefixes(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ComputeSHA256Hex 返回二进制的 64 位小写十六进制 SHA-256 摘要。
func ComputeSHA256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// VerifySHA256ConstantTime 校验 expectedHex 格式合法并与 actualHex 常量时间一致。
func VerifySHA256ConstantTime(expectedHex, actualHex string) string {
	trimmed := strings.TrimSpace(expectedHex)
	if trimmed == "" {
		return ""
	}
	if !sha256Pattern.MatchString(trimmed) {
		return "expected_sha256 必须为 64 位十六进制 SHA-256 摘要"
	}
	expLower := strings.ToLower(trimmed)
	actLower := strings.ToLower(strings.TrimSpace(actualHex))
	if len(expLower) != len(actLower) || subtle.ConstantTimeCompare([]byte(expLower), []byte(actLower)) != 1 {
		return "上传的 Wasm 二进制 SHA-256 摘要与 expected_sha256 不一致"
	}
	return ""
}

// DecodeAndValidateWasmBase64 解码 Base64 Wasm 二进制、执行纯 Go 结构/安全校验并计算 SHA-256。
func DecodeAndValidateWasmBase64(encoded string) ([]byte, string, []FieldError) {
	cleaned := stripBase64Whitespace(encoded)
	if cleaned == "" {
		return nil, "", []FieldError{{Field: "wasm_base64", Message: "必须上传 Wasm 二进制内容（wasm_base64）"}}
	}
	if len(cleaned) > maxEncodedWasmBase64Len {
		return nil, "", []FieldError{{Field: "wasm_base64", Message: "Wasm 二进制大小超过 4MiB 上限"}}
	}
	raw, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, "", []FieldError{{Field: "wasm_base64", Message: "wasm_base64 不是合法的 Base64 编码"}}
	}
	if err := ValidateWasmBinary(raw); err != nil {
		return nil, "", []FieldError{{Field: "wasm_base64", Message: strings.TrimPrefix(err.Error(), ErrInvalidWasm.Error()+": ")}}
	}
	return raw, ComputeSHA256Hex(raw), nil
}

func stripBase64Whitespace(s string) string {
	if !strings.ContainsAny(s, " \t\r\n") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ValidateReason 校验变更/回滚理由（1..500 字符，不含非法控制字符）。
func ValidateReason(reason string) *FieldError {
	r := strings.TrimSpace(reason)
	if r == "" {
		return &FieldError{Field: "reason", Message: "变更理由不能为空"}
	}
	if utf8.RuneCountInString(r) > MaxReasonLen {
		return &FieldError{Field: "reason", Message: fmt.Sprintf("变更理由不能超过 %d 字符", MaxReasonLen)}
	}
	if hasDisallowedTextControlChars(r) {
		return &FieldError{Field: "reason", Message: "变更理由不得包含非法控制字符"}
	}
	return nil
}

// ValidateConfigFields 校验插件通用配置字段（创建与更新共用）。
func ValidateConfigFields(
	name string,
	checkName bool,
	description string,
	abiVersion string,
	mode string,
	priority int,
	timeoutMs int,
	maxMemoryKB int,
	maxBodyBytes int,
	failPolicy string,
	pathPrefixes []string,
) []FieldError {
	errs := []FieldError{}
	add := func(field, msg string) {
		errs = append(errs, FieldError{Field: field, Message: msg})
	}

	if checkName {
		if !namePattern.MatchString(name) {
			add("name", "名称必须以字母或数字开头，长度 1~128，仅支持字母、数字、点、下划线和连字符")
		}
	}
	if utf8.RuneCountInString(description) > MaxDescriptionLen {
		add("description", fmt.Sprintf("描述长度不能超过 %d 字符", MaxDescriptionLen))
	} else if hasDisallowedTextControlChars(description) {
		add("description", "描述不得包含非法控制字符")
	}
	if abiVersion != "" && abiVersion != ABIVersionWDSPV1 {
		add("abi_version", fmt.Sprintf("仅支持 ABI 版本 %s", ABIVersionWDSPV1))
	}
	if !validMode(mode) {
		add("mode", "仅支持 OFF / OBSERVE / PROTECT")
	}
	if priority < MinPriority || priority > MaxPriority {
		add("priority", fmt.Sprintf("优先级必须在 %d~%d 之间", MinPriority, MaxPriority))
	}
	if timeoutMs < MinTimeoutMs || timeoutMs > MaxTimeoutMs {
		add("timeout_ms", fmt.Sprintf("执行超时必须在 %d~%d 毫秒之间", MinTimeoutMs, MaxTimeoutMs))
	}
	if maxMemoryKB < MinMaxMemoryKB || maxMemoryKB > MaxMaxMemoryKB {
		add("max_memory_kb", fmt.Sprintf("内存上限必须在 %d~%d KiB 之间", MinMaxMemoryKB, MaxMaxMemoryKB))
	}
	if maxBodyBytes < MinMaxBodyBytes || maxBodyBytes > MaxMaxBodyBytes {
		add("max_body_bytes", fmt.Sprintf("可读请求体上限必须在 %d~%d 字节之间", MinMaxBodyBytes, MaxMaxBodyBytes))
	}
	if !validFailPolicy(failPolicy) {
		add("fail_policy", "仅支持 FAIL_OPEN / FAIL_CLOSED")
	}

	if len(pathPrefixes) > MaxPathPrefixes {
		add("path_prefixes", fmt.Sprintf("路径前缀最多配置 %d 条", MaxPathPrefixes))
	} else {
		for i, p := range pathPrefixes {
			field := fmt.Sprintf("path_prefixes[%d]", i)
			if p == "" {
				add(field, "路径前缀不能为空")
				continue
			}
			if len(p) > MaxPathPrefixLen {
				add(field, fmt.Sprintf("路径前缀长度不能超过 %d 字符", MaxPathPrefixLen))
				continue
			}
			if !strings.HasPrefix(p, "/") {
				add(field, "路径前缀必须以 / 开头")
				continue
			}
			if strings.ContainsAny(p, "?# \t\r\n\\") || hasControlChars(p) {
				add(field, "路径前缀不得包含 ?、#、空白、反斜杠或控制字符")
				continue
			}
		}
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
