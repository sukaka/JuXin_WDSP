package middleware

import (
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
func sameOrigin(origin, host string) bool {
	origin = strings.TrimPrefix(origin, "http://")
	origin = strings.TrimPrefix(origin, "https://")
	if i := strings.Index(origin, "/"); i >= 0 {
		origin = origin[:i]
	}
	return strings.EqualFold(origin, host)
}
