// csp.go Content-Security-Policy 编译引擎与来源令牌校验/匹配（防 CR/LF 头注入与分号指令注入）。
package clientside

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const (
	// HeaderCSP 强制执行 CSP 响应头名。
	HeaderCSP = "Content-Security-Policy"
	// HeaderCSPReportOnly 学习上报 CSP 响应头名。
	HeaderCSPReportOnly = "Content-Security-Policy-Report-Only"
)

var validCSPKeywords = map[string]bool{
	"'self'":             true,
	"'none'":             true,
	"'unsafe-inline'":    true,
	"'unsafe-eval'":      true,
	"'strict-dynamic'":   true,
	"'wasm-unsafe-eval'": true,
	"'unsafe-hashes'":    true,
	"'report-sample'":    true,
}

// CompileCSP 从策略配置编译严格 CSP 响应头（名称与值）。
//   - mode == OFF 或 csp_mode == OFF 返回 ("", "", nil)；
//   - csp_mode == REPORT_ONLY 返回 Content-Security-Policy-Report-Only；
//   - csp_mode == ENFORCE（且 mode != OFF）返回 Content-Security-Policy；
//   - probe_enabled == true 时自动确保 script-src 与 connect-src 包含 'self'（且移除冲突的 'none'）；
//   - 拒绝任何 CR/LF 或控制字符，杜绝 HTTP 响应头拆分注入。
func CompileCSP(p *Policy) (headerName, headerValue string, err error) {
	if p == nil || p.Mode == ModeOff || p.CSPMode == CSPModeOff {
		return "", "", nil
	}
	switch p.CSPMode {
	case CSPModeReportOnly:
		headerName = HeaderCSPReportOnly
	case CSPModeEnforce:
		headerName = HeaderCSP
	default:
		return "", "", fmt.Errorf("unsupported csp_mode %q", p.CSPMode)
	}

	scriptSrc, err := compileDirectiveSources(p.AllowedScriptOrigins, p.ProbeEnabled)
	if err != nil {
		return "", "", fmt.Errorf("allowed_script_origins: %w", err)
	}
	connectSrc, err := compileDirectiveSources(p.AllowedConnectOrigins, p.ProbeEnabled)
	if err != nil {
		return "", "", fmt.Errorf("allowed_connect_origins: %w", err)
	}
	formSrc, err := compileDirectiveSources(p.AllowedFormOrigins, false)
	if err != nil {
		return "", "", fmt.Errorf("allowed_form_origins: %w", err)
	}

	directives := []string{
		"script-src " + strings.Join(scriptSrc, " "),
		"connect-src " + strings.Join(connectSrc, " "),
		"form-action " + strings.Join(formSrc, " "),
	}

	custom := strings.TrimSpace(p.CustomCSPDirectives)
	if custom != "" {
		if len(custom) > MaxCustomDirectivesLen || hasControlChars(custom) {
			return "", "", errors.New("custom_csp_directives contains invalid length or control characters")
		}
		custom = strings.Trim(custom, "; ")
		if custom != "" {
			directives = append(directives, custom)
		}
	}

	directives = append(directives, "report-uri "+CSPReportPath)
	headerValue = strings.Join(directives, "; ")
	if hasControlChars(headerValue) {
		return "", "", errors.New("compiled CSP header contains control characters")
	}
	return headerName, headerValue, nil
}

func compileDirectiveSources(raw []string, ensureSelf bool) ([]string, error) {
	seen := make(map[string]bool, len(raw)+1)
	out := make([]string, 0, len(raw)+1)
	for _, tok := range raw {
		tok = strings.TrimSpace(tok)
		if err := ValidateCSPSourceToken(tok); err != nil {
			return nil, err
		}
		if ensureSelf && strings.EqualFold(tok, "'none'") {
			continue
		}
		key := strings.ToLower(tok)
		if !seen[key] {
			seen[key] = true
			out = append(out, tok)
		}
	}
	if len(out) == 0 {
		out = append(out, "'self'")
		seen["'self'"] = true
	}
	if ensureSelf && !seen["'self'"] {
		out = append([]string{"'self'"}, out...)
	}
	return out, nil
}

// ValidateCSPSourceToken 校验单个 CSP 来源令牌（禁止 CR/LF、控制字符、空格、分号、逗号等注入字符）。
func ValidateCSPSourceToken(raw string) error {
	tok := strings.TrimSpace(raw)
	if tok == "" {
		return errors.New("来源令牌不能为空")
	}
	if len(tok) > MaxOriginLen {
		return fmt.Errorf("来源令牌长度超过 %d", MaxOriginLen)
	}
	if hasControlChars(raw) {
		return errors.New("来源令牌不得包含 CR/LF 或控制字符")
	}
	if strings.ContainsAny(tok, " \t;,\"<>\\`") {
		return fmt.Errorf("来源令牌 %q 包含非法分隔符", tok)
	}

	// 单引号关键字或哈希/nonce 源
	if strings.HasPrefix(tok, "'") || strings.HasSuffix(tok, "'") {
		if !strings.HasPrefix(tok, "'") || !strings.HasSuffix(tok, "'") || len(tok) < 3 {
			return fmt.Errorf("非法 CSP 引号关键字 %q", tok)
		}
		lower := strings.ToLower(tok)
		if validCSPKeywords[lower] {
			return nil
		}
		inner := tok[1 : len(tok)-1]
		if isSingleValidSRI(inner) {
			return nil
		}
		if strings.HasPrefix(inner, "nonce-") && len(inner) > len("nonce-")+3 {
			return nil
		}
		return fmt.Errorf("不支持的 CSP 引号令牌 %q", tok)
	}

	if tok == "*" {
		return nil
	}

	// Scheme 源（如 https: / http: / data: / blob: / wss:）
	if strings.HasSuffix(tok, ":") && !strings.Contains(tok, "://") {
		scheme := strings.TrimSuffix(tok, ":")
		if isValidSchemeName(scheme) {
			return nil
		}
		return fmt.Errorf("非法 CSP scheme 源 %q", tok)
	}

	// Host / Origin 源（可选 scheme://，主机或 *.domain，可选 :port / :*，可选 /path）
	check := tok
	if !strings.Contains(check, "://") {
		check = "https://" + check
	}
	// 临时替换通配端口 :* 以便 url.Parse 校验
	check = strings.Replace(check, ":*", ":443", 1)
	// 临时替换子域通配 *. 为 wildcard. 以便 url.Parse 校验
	if idx := strings.Index(check, "://*."); idx >= 0 {
		check = check[:idx+3] + "wildcard." + check[idx+5:]
	}
	u, err := url.Parse(check)
	if err != nil || !isValidSchemeName(u.Scheme) || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("非法 CSP 来源表达式 %q", tok)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("非法 CSP 来源主机 %q", tok)
	}
	if port := u.Port(); port != "" {
		if pn, err := strconv.Atoi(port); err != nil || pn < 1 || pn > 65535 {
			return fmt.Errorf("非法 CSP 来源端口 %q", tok)
		}
	}
	return nil
}

func isValidSchemeName(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		if i == 0 && !isAlpha {
			return false
		}
		if !isAlpha && !isDigit && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// originMatcher 编译后的 CSP script-src 来源匹配器（供 HTML 扫描器校验外链脚本是否属于授权来源）。
type originMatcher struct {
	kind       string // "self" | "none" | "wildcard" | "scheme" | "host"
	scheme     string // 小写（可选）
	host       string // 小写无端口，不含 *.
	subdomain  bool   // *.example.com
	port       string // ""（默认端口）| "*" | 具体端口号
	pathPrefix string // 可选路径约束
}

func compileOriginMatcher(raw string) (originMatcher, bool) {
	tok := strings.TrimSpace(raw)
	lower := strings.ToLower(tok)
	switch {
	case lower == "'self'":
		return originMatcher{kind: "self"}, true
	case lower == "'none'":
		return originMatcher{kind: "none"}, true
	case tok == "*":
		return originMatcher{kind: "wildcard"}, true
	case strings.HasPrefix(tok, "'"):
		// 'unsafe-inline' / hash / nonce 等不用于匹配外链来源
		return originMatcher{}, false
	case strings.HasSuffix(tok, ":") && !strings.Contains(tok, "://"):
		return originMatcher{kind: "scheme", scheme: strings.TrimSuffix(lower, ":")}, true
	}

	hasScheme := strings.Contains(tok, "://")
	parseTarget := tok
	if !hasScheme {
		parseTarget = "https://" + tok
	}
	wildPort := false
	if strings.Contains(parseTarget, ":*") {
		wildPort = true
		parseTarget = strings.Replace(parseTarget, ":*", ":443", 1)
	}
	sub := false
	if idx := strings.Index(parseTarget, "://*."); idx >= 0 {
		sub = true
		parseTarget = parseTarget[:idx+3] + parseTarget[idx+5:]
	}
	u, err := url.Parse(parseTarget)
	if err != nil || u.Hostname() == "" {
		return originMatcher{}, false
	}
	m := originMatcher{
		kind:       "host",
		host:       strings.ToLower(u.Hostname()),
		subdomain:  sub,
		pathPrefix: u.Path,
	}
	if hasScheme {
		m.scheme = strings.ToLower(u.Scheme)
	}
	if wildPort {
		m.port = "*"
	} else {
		m.port = u.Port()
	}
	return m, true
}

func (m originMatcher) matches(scriptURL *url.URL, sameOrigin bool, pageScheme string) bool {
	if scriptURL == nil {
		return false
	}
	scScheme := strings.ToLower(scriptURL.Scheme)
	switch m.kind {
	case "none":
		return false
	case "self":
		return sameOrigin && (scScheme == "http" || scScheme == "https")
	case "wildcard":
		// 按 CSP 规范：* 不匹配 data:/blob:/javascript: 等非网络 scheme
		return scScheme == "http" || scScheme == "https"
	case "scheme":
		return scScheme == m.scheme
	case "host":
		if m.scheme != "" {
			if scScheme != m.scheme {
				return false
			}
		} else {
			// 无显式 scheme 时，允许同级或升级到 https，禁止从 https 降级到 http
			if pageScheme == "https" && scScheme != "https" {
				return false
			}
			if scScheme != "http" && scScheme != "https" {
				return false
			}
		}
		scHost := strings.ToLower(scriptURL.Hostname())
		if m.subdomain {
			// *.example.com 仅匹配子域（如 cdn.example.com），不匹配裸域或 evil-example.com
			if !strings.HasSuffix(scHost, "."+m.host) {
				return false
			}
		} else if scHost != m.host {
			return false
		}
		if m.port != "*" {
			wantPort := m.port
			if wantPort == "" {
				wantPort = defaultPortForScheme(scScheme)
			}
			gotPort := scriptURL.Port()
			if gotPort == "" {
				gotPort = defaultPortForScheme(scScheme)
			}
			if wantPort != gotPort {
				return false
			}
		}
		if m.pathPrefix != "" && m.pathPrefix != "/" {
			if strings.HasSuffix(m.pathPrefix, "/") {
				if !strings.HasPrefix(scriptURL.Path, m.pathPrefix) {
					return false
				}
			} else if scriptURL.Path != m.pathPrefix {
				return false
			}
		}
		return true
	}
	return false
}

func defaultPortForScheme(scheme string) string {
	switch strings.ToLower(scheme) {
	case "https", "wss":
		return "443"
	case "http", "ws":
		return "80"
	default:
		return ""
	}
}

// ExtractOrigin 从 URL 中提取规范化 origin（scheme://host[:port]），不含路径、查询串与凭据。
func ExtractOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "data:") {
		return "data:"
	}
	if strings.HasPrefix(lower, "javascript:") {
		return "javascript:"
	}
	if strings.HasPrefix(lower, "blob:") {
		inner := strings.TrimPrefix(raw, raw[:5])
		if innerOrig := ExtractOrigin(inner); innerOrig != "" {
			return "blob:" + innerOrig
		}
		return "blob:"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := normalizeOriginHost(scheme, u.Host)
	// IPv6 host normalization sanity
	if h, p, err := net.SplitHostPort(host); err == nil {
		if (scheme == "https" && p == "443") || (scheme == "http" && p == "80") {
			if strings.Contains(h, ":") {
				host = "[" + h + "]"
			} else {
				host = h
			}
		}
	}
	return scheme + "://" + host
}
