package middleware

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// RequireAuth 要求已认证会话。
// 若 mustChangePassword 为 true，仅放行修改密码与退出登录等豁免路径。
func RequireAuth(exemptPaths ...string) func(http.Handler) http.Handler {
	exempt := map[string]bool{}
	for _, p := range exemptPaths {
		exempt[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := authz.PrincipalFrom(r.Context())
			if p == nil {
				response.Error(w, r, http.StatusUnauthorized,
					response.CodeUnauthenticated, "未登录或会话已过期")
				return
			}
			if p.MustChangePwd && !exempt[r.Method+" "+r.URL.Path] {
				response.Error(w, r, http.StatusForbidden,
					response.CodePasswordChangeRequired, "首次登录必须先修改密码")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission 要求指定权限（后端强制校验，不依赖前端隐藏）。
func RequirePermission(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := authz.PrincipalFrom(r.Context())
			if p == nil {
				response.Error(w, r, http.StatusUnauthorized,
					response.CodeUnauthenticated, "未登录或会话已过期")
				return
			}
			if !p.HasPermission(perm) {
				response.Error(w, r, http.StatusForbidden,
					response.CodePermissionDenied, "无权执行该操作")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CSRFTokenHeader 是 CSRF Token 请求头。
const CSRFTokenHeader = "X-CSRF-Token"

// CSRFProtect 校验写操作的 CSRF Token 与来源。
// 采用 SameSite Cookie + 自定义头 + Origin 校验三重防护。
// 校验逻辑由 validator 函数提供（与具体会话存储解耦）。
func CSRFProtect(validate func(r *http.Request, token string) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSafeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			// Origin 校验：存在时必须与 Host 同源（且 HTTPS 请求禁止 http:// Origin 降级）
			origin := r.Header.Get("Origin")
			if origin != "" && !sameOriginForRequest(origin, r) {
				response.Error(w, r, http.StatusForbidden,
					response.CodeCSRFInvalid, "请求来源校验失败")
				return
			}
			token := r.Header.Get(CSRFTokenHeader)
			if token == "" || !validate(r, token) {
				response.Error(w, r, http.StatusForbidden,
					response.CodeCSRFInvalid, "CSRF 校验失败，请刷新页面后重试")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// sameOriginForRequest 校验 Origin 与请求同源；当请求经 HTTPS 到达时，禁止 http:// Origin 降级。
func sameOriginForRequest(origin string, r *http.Request) bool {
	if r == nil || !sameOrigin(origin, r.Host) {
		return false
	}
	scheme, _, ok := parseOrigin(origin)
	if !ok {
		return false
	}
	if r.TLS != nil ||
		strings.EqualFold(r.URL.Scheme, "https") ||
		strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		if scheme != "https" {
			return false
		}
	}
	return true
}

// sameOrigin 校验 Origin 与 Host 是否同源。
// 比较前对双方做默认端口归一：https 默认 443、http 默认 80，
// 显式默认端口与省略端口等价；协议默认端口与显式端口必须精确匹配。
func sameOrigin(origin, host string) bool {
	scheme, originHost, ok := parseOrigin(origin)
	if !ok {
		return false
	}
	originName, originPort, ok := splitHostPort(originHost)
	if !ok || originName == "" {
		return false
	}
	defPort := defaultPort(scheme)
	if defPort == "" {
		return false
	}
	if originPort == "" {
		originPort = defPort
	}
	hostName, hostPort, ok := splitHostPort(host)
	if !ok || hostName == "" || !strings.EqualFold(originName, hostName) {
		return false
	}
	if hostPort == "" {
		// Host 未带端口：仅当 Origin 端口与自身 scheme 默认端口一致时视为同源
		// （拒绝 http://host:443、https://host:80 等协议/端口不匹配）
		return originPort == defPort
	}
	return originPort == hostPort
}

// parseOrigin 拆解 Origin 为 scheme 与 host（不含路径）。
// 强制要求显式 http/https scheme（必须含 "://"）；拒绝 userinfo、控制字符或空 host。
func parseOrigin(origin string) (scheme, host string, ok bool) {
	if origin == "" || strings.TrimSpace(origin) != origin {
		return "", "", false
	}
	for i := 0; i < len(origin); i++ {
		if origin[i] < 0x20 || origin[i] == 0x7f {
			return "", "", false
		}
	}
	i := strings.Index(origin, "://")
	if i <= 0 {
		return "", "", false
	}
	scheme = strings.ToLower(origin[:i])
	if scheme != "http" && scheme != "https" {
		return "", "", false
	}
	rest := origin[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	if rest == "" || strings.ContainsAny(rest, "@ \t") {
		return "", "", false
	}
	return scheme, rest, true
}

// splitHostPort 拆分 host[:port]（支持 IPv6 字面量）；非法语法或无效端口返回 ok=false。
func splitHostPort(s string) (host, port string, ok bool) {
	if s == "" || strings.ContainsAny(s, "@ \t\r\n") {
		return "", "", false
	}
	if strings.HasPrefix(s, "[") {
		if h, p, err := net.SplitHostPort(s); err == nil {
			if h == "" || !isValidPort(p) {
				return "", "", false
			}
			return h, p, true
		}
		if strings.HasSuffix(s, "]") && strings.Count(s, "[") == 1 && strings.Count(s, "]") == 1 {
			h := s[1 : len(s)-1]
			if h == "" {
				return "", "", false
			}
			return h, "", true
		}
		return "", "", false
	}
	if strings.Contains(s, ":") {
		h, p, err := net.SplitHostPort(s)
		if err != nil || h == "" || !isValidPort(p) {
			return "", "", false
		}
		return h, p, true
	}
	return s, "", true
}

func isValidPort(p string) bool {
	if p == "" {
		return false
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535
}

// defaultPort 返回 scheme 对应的默认端口。
func defaultPort(scheme string) string {
	switch scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}
