package middleware

import (
	"net"
	"net/http"
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
			// Origin 校验：存在时必须与 Host 同源
			origin := r.Header.Get("Origin")
			if origin != "" && !sameOrigin(origin, r.Host) {
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

// sameOrigin 校验 Origin 与 Host 是否同源。
// 比较前对双方做默认端口归一：https 默认 443、http 默认 80，
// 显式默认端口与省略端口等价；非默认端口必须精确匹配。
func sameOrigin(origin, host string) bool {
	scheme, originHost, ok := parseOrigin(origin)
	if !ok {
		return false
	}
	originName, originPort := splitHostPort(originHost)
	if originName == "" {
		return false
	}
	if originPort == "" {
		originPort = defaultPort(scheme)
	}
	hostName, hostPort := splitHostPort(host)
	if hostName == "" || !strings.EqualFold(originName, hostName) {
		return false
	}
	switch {
	case originPort == "" && hostPort == "":
		return true
	case originPort == "":
		// Origin 未声明端口，无法与显式端口 Host 判定同源
		return false
	case hostPort == "":
		// Host 未带端口，仅当 Origin 使用默认端口时视为同源
		return originPort == "80" || originPort == "443"
	default:
		return originPort == hostPort
	}
}

// parseOrigin 拆解 Origin 为 scheme 与 host（不含路径）。
// scheme 仅接受 http/https；Origin 无 host 或 scheme 非法时视为畸形并拒绝。
func parseOrigin(origin string) (scheme, host string, ok bool) {
	rest := origin
	if i := strings.Index(origin, "://"); i >= 0 {
		scheme = strings.ToLower(origin[:i])
		if scheme != "http" && scheme != "https" {
			return "", "", false
		}
		rest = origin[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "", "", false
	}
	return scheme, rest, true
}

// splitHostPort 拆分 host[:port]；无端口时 port 返回空串。
func splitHostPort(s string) (host, port string) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}
	return s, ""
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
