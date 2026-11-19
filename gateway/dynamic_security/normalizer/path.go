// Package normalizer 路径与端点标识归一化（方法 + 路径模板，非仅 /api/ 前缀）。
package normalizer

import (
	"path"
	"regexp"
	"strings"
)

var (
	reUUID    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reHexLong = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	reInt     = regexp.MustCompile(`^\d+$`)
)

// CanonicalPath 将请求或规则路径规范化：剥离 query/fragment、补齐前导 '/'、
// 通过 path.Clean 折叠连续 '//' 并解析 '.' / '..' 点段；若原路径以 '/' 结尾且
// 规范化后非根路径 '/'，则保留单个尾斜杠。
func CanonicalPath(raw string) string {
	if raw == "" {
		return "/"
	}
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	if raw == "" {
		return "/"
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	hadTrailing := strings.HasSuffix(raw, "/")
	cleaned := path.Clean(raw)
	if cleaned == "" || cleaned == "." {
		return "/"
	}
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	if hadTrailing && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

// CanonicalSegments 返回 CanonicalPath 规范化后的非空路径段序列（根路径返回 nil）。
// 供路径模板匹配与位置段提取复用，保证 '//'、'.'、'..' 与模板段 1:1 对齐。
func CanonicalSegments(raw string) []string {
	trimmed := strings.Trim(CanonicalPath(raw), "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// PrefixSegmentMatch 按规范化完整路径段匹配前缀：
// "/api" 匹配 "/api"、"/api/"、"/api/orders"、"/api//orders"、"/x/../api/orders"，
// 不匹配 "/apiv2"；根前缀 "/" 匹配所有以 '/' 开头的路径。
func PrefixSegmentMatch(prefix, reqPath string) bool {
	cp := CanonicalPath(reqPath)
	pref := CanonicalPath(prefix)
	if pref == "/" {
		return strings.HasPrefix(cp, "/")
	}
	pref = strings.TrimSuffix(pref, "/")
	return cp == pref || strings.HasPrefix(cp, pref+"/")
}

// NormalizePath 将动态段替换为模板占位符，保证端点稳定身份。
// 规则：先经 CanonicalPath 折叠 '//' 并解析 '.'/'..'，去非根尾斜杠后：
// 纯数字 → {id}；UUID → {uuid}；长十六进制 → {hex}；其余保持字面量。
func NormalizePath(raw string) string {
	raw = CanonicalPath(raw)
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
