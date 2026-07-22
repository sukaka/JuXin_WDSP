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
		switch {
		case reUUID.MatchString(p):
			parts[i] = "{uuid}"
		case reInt.MatchString(p):
			parts[i] = "{id}"
		case reHexLong.MatchString(p):
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

// EndpointKey 端点唯一键：METHOD + 空格 + 归一化路径。
func EndpointKey(method, rawPath string) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = "GET"
	}
	return m + " " + NormalizePath(rawPath)
}

// MergeCompatible 判断两条归一化路径是否可合并为同一端点（模板一致）。
func MergeCompatible(a, b string) bool {
	return NormalizePath(a) == NormalizePath(b)
}
