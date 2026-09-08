// Package normalizer 路径与端点标识归一化（方法 + 路径模板，非仅 /api/ 前缀）。
package normalizer

import (
	"regexp"
	"strings"
)

var (
	reUUID    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reHexLong = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	reInt     = regexp.MustCompile(`^\d+$`)
)

// NormalizePath 将动态段替换为模板占位符，保证端点稳定身份。
// 规则：纯数字 → {id}；UUID → {uuid}；长十六进制 → {hex}；其余保持字面量。
func NormalizePath(raw string) string {
	if raw == "" {
		return "/"
	}
	// strip query/fragment if present
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	// collapse multiple slashes
	for strings.Contains(raw, "//") {
		raw = strings.ReplaceAll(raw, "//", "/")
	}
	if raw != "/" {
		raw = strings.TrimSuffix(raw, "/")
	}
	parts := strings.Split(raw, "/")
	for i, p := range parts {
		if p == "" {
			continue
		}
		switch IdentifierShape(p) {
		case "uuid":
			parts[i] = "{uuid}"
		case "numeric":
			parts[i] = "{id}"
		case "hex":
			parts[i] = "{hex}"
		default:
			// keep literal
		}
	}
	out := strings.Join(parts, "/")
	if out == "" {
		return "/"
	}
	return out
}

// IdentifierShape 识别单个值的对象标识形态：纯数字 → numeric；UUID → uuid；
// 长十六进制 → hex；其余返回空串。判定顺序与路径段归一化一致（UUID > 纯数字 > 长 hex）。
// 「只认形态不认语义」：不依据参数名/位置猜测含义，供对象标识来源扩展（Query 参数等）复用。
func IdentifierShape(s string) string {
	switch {
	case reUUID.MatchString(s):
		return "uuid"
	case reInt.MatchString(s):
		return "numeric"
	case reHexLong.MatchString(s):
		return "hex"
	default:
		return ""
	}
}

// EndpointKey 端点唯一键：METHOD + 空格 + 归一化路径。
func EndpointKey(method, rawPath string) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = "GET"
	}
	return m + " " + NormalizePath(rawPath)
}

// EndpointKeyPreserve 端点唯一键（路径全保留，不做动态段归一化）：
// gRPC /package.Service/Method 形态专用（P2-05）——服务/方法名即端点稳定身份，
// 归一化会破坏方法名语义（如全数字方法名被模板化为 {id}）；仍剥离 query/fragment。
func EndpointKeyPreserve(method, rawPath string) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = "GET"
	}
	if i := strings.IndexAny(rawPath, "?#"); i >= 0 {
		rawPath = rawPath[:i]
	}
	return m + " " + rawPath
}

// MergeCompatible 判断两条归一化路径是否可合并为同一端点（模板一致）。
func MergeCompatible(a, b string) bool {
	return NormalizePath(a) == NormalizePath(b)
}
