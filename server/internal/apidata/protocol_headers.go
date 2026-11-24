package apidata

import (
	"sort"
	"strings"
)

// standardProtocolHeaders 标准 HTTP / 浏览器传输协议头（小写），与网关
// gateway/dynamic_security/detectors/sensitive_mask.go 保持同口径。
// 这些头不参与字段名级敏感匹配与参数语义推断，避免 Sec-CH-UA-Mobile 等被误判为手机号。
var standardProtocolHeaders = map[string]bool{
	"accept":                    true,
	"accept-charset":            true,
	"accept-encoding":           true,
	"accept-language":           true,
	"accept-ranges":             true,
	"baggage":                   true,
	"cache-control":             true,
	"connection":                true,
	"content-disposition":       true,
	"content-encoding":          true,
	"content-language":          true,
	"content-length":            true,
	"content-range":             true,
	"content-type":              true,
	"date":                      true,
	"dnt":                       true,
	"etag":                      true,
	"expect":                    true,
	"forwarded":                 true,
	"host":                      true,
	"if-match":                  true,
	"if-modified-since":         true,
	"if-none-match":             true,
	"if-range":                  true,
	"if-unmodified-since":       true,
	"keep-alive":                true,
	"last-modified":             true,
	"max-forwards":              true,
	"origin":                    true,
	"pragma":                    true,
	"priority":                  true,
	"purpose":                   true,
	"range":                     true,
	"referer":                   true,
	"save-data":                 true,
	"sec-gpc":                   true,
	"sec-purpose":               true,
	"te":                        true,
	"traceparent":               true,
	"tracestate":                true,
	"trailer":                   true,
	"transfer-encoding":         true,
	"upgrade":                   true,
	"upgrade-insecure-requests": true,
	"user-agent":                true,
	"vary":                      true,
	"via":                       true,
	"x-forwarded-for":           true,
	"x-forwarded-host":          true,
	"x-forwarded-port":          true,
	"x-forwarded-proto":         true,
	"x-real-ip":                 true,
	"x-requested-with":          true,
}

var standardProtocolHeaderNames = func() []string {
	names := make([]string, 0, len(standardProtocolHeaders))
	for k := range standardProtocolHeaders {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}()

// StandardProtocolHeaderNames 返回已排序的标准协议头名称副本（供 SQL ANY($n::text[]) 参数化使用）。
func StandardProtocolHeaderNames() []string {
	out := make([]string, len(standardProtocolHeaderNames))
	copy(out, standardProtocolHeaderNames)
	return out
}

// IsStandardProtocolHeader 判断请求头名是否属标准浏览器/HTTP 传输协议头。
func IsStandardProtocolHeader(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	if strings.HasPrefix(lower, "sec-ch-") ||
		strings.HasPrefix(lower, "sec-fetch-") ||
		strings.HasPrefix(lower, "sec-websocket-") {
		return true
	}
	return standardProtocolHeaders[lower]
}

// IsIgnoredProtocolHeaderFieldHit 判断一条运行时敏感检测明细是否属于历史网关对标准协议头的
// 字段名级误报（如 header.sec-ch-ua-mobile 命中 sensitive.field）。
// 仅过滤 rule_id = sensitive.field 的字段名命中；值级正则命中（sensitive.value 等）绝不过滤。
func IsIgnoredProtocolHeaderFieldHit(location, field, ruleID string) bool {
	if !strings.EqualFold(strings.TrimSpace(location), "header") {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(ruleID), "sensitive.field") {
		return false
	}
	return IsStandardProtocolHeader(field)
}

// IsIgnoredProtocolHeaderPath 按已拼接的 structured_path（如 "header.sec-ch-ua-mobile"）判断
// 是否属于标准协议头的字段名级误报。
func IsIgnoredProtocolHeaderPath(fieldPath, ruleID string) bool {
	trimmed := strings.TrimSpace(fieldPath)
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "header.") {
		return false
	}
	return IsIgnoredProtocolHeaderFieldHit("header", trimmed[len("header."):], ruleID)
}

// IsValueLevelSensitiveRule 判断 sensitive_data 明细是否经过值级正则验证（高置信实值命中）。
func IsValueLevelSensitiveRule(ruleID string) bool {
	switch strings.ToLower(strings.TrimSpace(ruleID)) {
	case "sensitive.value", "sensitive.value_in_query", "sensitive.response_value":
		return true
	default:
		return false
	}
}

// IsIgnoredSensitiveFieldHit 判断一条运行时 sensitive_data 明细是否属于非涉敏噪声：
//  1. sensitive.response_body_unchecked：响应体检测未完成诊断提示（非敏感数据命中）；
//  2. location=path + rule_id=sensitive.field：历史网关对 URL 路径字面段（如 /mobile.zip、
//     /mailer.zip、/remind_password.zip、/reset-password）的字段名误报；
//  3. location=header + rule_id=sensitive.field + 标准协议头（如 sec-ch-ua-mobile）。
//
// 仅过滤上述非数据噪声；路径/请求头上的值级正则命中（sensitive.value 等）绝不过滤。
func IsIgnoredSensitiveFieldHit(location, field, ruleID string) bool {
	rule := strings.ToLower(strings.TrimSpace(ruleID))
	if rule == "sensitive.response_body_unchecked" {
		return true
	}
	if rule == "sensitive.field" && strings.EqualFold(strings.TrimSpace(location), "path") {
		return true
	}
	return IsIgnoredProtocolHeaderFieldHit(location, field, ruleID)
}

// IsIgnoredSensitiveFieldPath 按已拼接的 structured_path（如 "path.mobile.zip" 或
// "header.sec-ch-ua-mobile"）判断是否属于历史敏感字段名噪声或非涉敏诊断明细。
func IsIgnoredSensitiveFieldPath(fieldPath, ruleID string) bool {
	rule := strings.ToLower(strings.TrimSpace(ruleID))
	if rule == "sensitive.response_body_unchecked" {
		return true
	}
	lower := strings.ToLower(strings.TrimSpace(fieldPath))
	if rule == "sensitive.field" && strings.HasPrefix(lower, "path.") {
		return true
	}
	return IsIgnoredProtocolHeaderPath(fieldPath, ruleID)
}
