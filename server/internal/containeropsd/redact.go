// redact.go 日志脱敏：保守掩码 password/token/authorization/cookie 等敏感值，
// 口径与 docs/SECURITY_DESIGN.md「日志隐私」一致（宁可多掩，不可漏掩）。
package containeropsd

import (
	"regexp"
	"strings"
)

const mask = "********"

var (
	// headerStyleRe 匹配头部形态 "Key: value"（值可能含空格，保守掩码到行尾）。
	// 仅当键后紧跟 ": "（HTTP 头风格）时按整行值掩码，JSON 形态由 kvRe 处理。
	headerStyleRe = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*[^\s"'][^\r\n]*`)

	// kvRe 匹配键值形态 key=value / key: value / "key":"value"（值取到空白/分隔符或引号闭合）。
	kvRe = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key|secret[-_]?key|session[-_]?id|csrf[-_]?token|xsrf[-_]?token|private[-_]?key|refresh[-_]?token|id[-_]?token|access[-_]?token|client[-_]?secret|authorization|proxy-authorization|cookie|set-cookie)\b(\s*["']?\s*[:=]\s*)("([^"\\]*)"|'([^'\\]*)'|[^\s,;&]+)`)

	// bearerRe 掩码 Authorization 方案令牌（Bearer/Basic 后跟随的凭据）。
	bearerRe = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[a-z0-9\-._~+/=]{4,}`)
)

// stripControls 剥离控制字符（保留 \t），防止日志注入伪造终端/审计行。
func stripControls(s string) string {
	if strings.IndexFunc(s, func(r rune) bool {
		return (r < 0x20 && r != '\t') || r == 0x7f
	}) < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r < 0x20 && r != '\t') || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// redactLine 对单行日志做保守脱敏。
func redactLine(s string) string {
	// 头部形态优先（值到行尾），再处理键值形态，最后兜 Bearer/Basic 令牌
	s = headerStyleRe.ReplaceAllStringFunc(s, func(m string) string {
		idx := strings.Index(m, ":")
		if idx < 0 {
			return mask
		}
		return m[:idx+1] + " " + mask
	})
	s = kvRe.ReplaceAllString(s, "$1$2"+mask)
	s = bearerRe.ReplaceAllString(s, "${1} "+mask)
	return s
}
