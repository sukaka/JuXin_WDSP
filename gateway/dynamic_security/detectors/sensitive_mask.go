package detectors

import (
	"strings"
)

const (
	// maxMaskedStars 中间掩码星号上限（防止超长自定义规则命中撑爆事件与库列）。
	maxMaskedStars = 16
	// maxMaskedEmailDomainLen 邮箱脱敏样本中保留域名的最大字符数。
	maxMaskedEmailDomainLen = 48
)

// MaskSensitiveSample 在网关内存中对值级命中的敏感原值按类型做不可逆中间位脱敏，
// 仅输出脱敏样本（供事件与敏感字段台账展示）；原始明文永不落日志或出网关。
// 凭据/口令/令牌类严格不暴露前后缀，统一返回 "******"。
func MaskSensitiveSample(dataType, raw string) string {
	clean := sanitizeSensitiveSampleInput(raw)
	if clean == "" {
		return ""
	}
	dt := strings.ToLower(strings.TrimSpace(dataType))
	if isCredentialDataType(dt) {
		return "******"
	}
	var masked string
	switch dt {
	case "phone", "mobile", "telephone":
		masked = maskKeepEnds(clean, 3, 4, 11)
	case "id_card", "idcard":
		masked = maskKeepEnds(clean, 3, 4, 15)
	case "bank_card", "card_number":
		masked = maskKeepEnds(clean, 4, 4, 12)
	case "email":
		masked = maskEmailSample(clean)
	default:
		masked = maskGenericSample(clean)
	}
	// 防御性兜底：脱敏结果绝不得与原值相同
	if masked == "" || masked == clean {
		return "****"
	}
	return masked
}

func sanitizeSensitiveSampleInput(raw string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, raw)
	return strings.TrimSpace(cleaned)
}

func isCredentialDataType(dt string) bool {
	switch dt {
	case "credential", "password", "passwd", "pwd", "token", "jwt",
		"secret", "api_key", "apikey", "access_key", "private_key":
		return true
	}
	for _, kw := range []string{"credential", "password", "passwd", "secret", "token", "jwt", "private_key", "access_key", "api_key", "apikey"} {
		if strings.Contains(dt, kw) {
			return true
		}
	}
	return false
}

// maskKeepEnds 针对结构化敏感号段（手机号/身份证/银行卡）保留前 keepHead 与后 keepTail 位，
// 中间替换为 *；长度不足 minFullLen 时降级保留更少或整体返回 "****"。
func maskKeepEnds(s string, keepHead, keepTail, minFullLen int) string {
	r := []rune(s)
	n := len(r)
	if n >= minFullLen && n > keepHead+keepTail {
		return formatMaskedRunes(r, keepHead, keepTail)
	}
	if n >= 7 {
		return formatMaskedRunes(r, 2, 2)
	}
	return "****"
}

func maskGenericSample(s string) string {
	r := []rune(s)
	n := len(r)
	switch {
	case n <= 4:
		return "****"
	case n <= 8:
		return formatMaskedRunes(r, 1, 1)
	case n <= 10:
		return formatMaskedRunes(r, 2, 2)
	default:
		return formatMaskedRunes(r, 3, 4)
	}
}

func formatMaskedRunes(r []rune, keepHead, keepTail int) string {
	n := len(r)
	mid := n - keepHead - keepTail
	if mid <= 0 {
		return "****"
	}
	if mid > maxMaskedStars {
		mid = maxMaskedStars
	}
	return string(r[:keepHead]) + strings.Repeat("*", mid) + string(r[n-keepTail:])
}

func maskEmailSample(s string) string {
	at := strings.LastIndex(s, "@")
	if at <= 0 || at >= len(s)-1 {
		return maskGenericSample(s)
	}
	local := []rune(s[:at])
	domain := []rune(s[at+1:])
	if len(domain) > maxMaskedEmailDomainLen {
		domain = append(domain[:maxMaskedEmailDomainLen-3], '.', '.', '.')
	}
	var maskedLocal string
	switch len(local) {
	case 1:
		maskedLocal = "*"
	case 2:
		maskedLocal = string(local[:1]) + "*"
	case 3:
		maskedLocal = string(local[:1]) + "*" + string(local[2:])
	case 4, 5:
		maskedLocal = string(local[:2]) + strings.Repeat("*", len(local)-2)
	default:
		mid := len(local) - 3
		if mid > 12 {
			mid = 12
		}
		maskedLocal = string(local[:2]) + strings.Repeat("*", mid) + string(local[len(local)-1:])
	}
	return maskedLocal + "@" + string(domain)
}

// standardProtocolHeaders 标准 HTTP / 浏览器协议请求头（小写），不参与字段名级敏感匹配，
// 防止 Sec-CH-UA-Mobile 等浏览器内置头被误判为手机号等敏感字段。
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

// isStandardProtocolHeader 判断请求头名是否属标准浏览器/HTTP 传输协议头。
func isStandardProtocolHeader(name string) bool {
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

// defaultSensitiveExcludeFields 内置排除字段名（与迁移 000040 api_sensitive_data_types 种子对齐），
// 命中词根但表达布尔/元信息而非敏感值时跳过，降低字段名级误报。
var defaultSensitiveExcludeFields = map[string]map[string]bool{
	"phone": {
		"phone_verified": true,
		"has_phone":      true,
		"is_phone":       true,
	},
	"email": {
		"email_verified": true,
		"is_email":       true,
	},
	"credential": {
		"password_strength": true,
		"password_hint":     true,
		"token_type":        true,
		"token_expires_in":  true,
		"expires_in":        true,
	},
	"password": {
		"password_strength": true,
		"password_hint":     true,
	},
	"token": {
		"token_type":       true,
		"token_expires_in": true,
		"expires_in":       true,
	},
}

// sensitiveFieldLeaf 取结构化路径的末段字段名（小写；剔除数组后缀 [] 与 XML 属性前缀 @）。
func sensitiveFieldLeaf(fieldPath string) string {
	s := strings.ToLower(strings.TrimSpace(fieldPath))
	if idx := strings.LastIndex(s, "."); idx >= 0 {
		s = s[idx+1:]
	}
	s = strings.TrimPrefix(s, "@")
	s = strings.TrimSuffix(s, "[]")
	return s
}

func matchesExcludeSet(fieldPath string, excludes map[string]bool) bool {
	if len(excludes) == 0 || fieldPath == "" {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(fieldPath))
	if excludes[lower] {
		return true
	}
	leaf := sensitiveFieldLeaf(lower)
	return leaf != "" && excludes[leaf]
}

// IsSensitiveFieldExcluded 判断字段路径是否在该数据类型的排除名单中（内置排除 + 发布下发 exclude_fields）。
func IsSensitiveFieldExcluded(fieldPath, dataType string, valueRules []CompiledSensitiveValueRule) bool {
	dt := strings.ToLower(strings.TrimSpace(dataType))
	if def := defaultSensitiveExcludeFields[dt]; matchesExcludeSet(fieldPath, def) {
		return true
	}
	for _, r := range valueRules {
		rdt := strings.ToLower(strings.TrimSpace(r.dataType))
		if rdt == dt || (dt == "credential" && (rdt == "password" || rdt == "token" || rdt == "jwt")) {
			if matchesExcludeSet(fieldPath, r.excludeFields) {
				return true
			}
		}
	}
	return false
}
