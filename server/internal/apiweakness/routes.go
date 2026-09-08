// routes.go API 弱点中心路由注册，统一 /api/v1/api-security 前缀。
// authz 为认证链（会话解析+认证+CSRF），权限点在路由层强制校验。
package apiweakness

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/middleware"
)

// 权限点（种子迁移由集成方统一登记，见任务书五十二章口径）。
const (
	PermRead   = "api_weakness.read"   // 弱点列表/详情
	PermHandle = "api_weakness.handle" // 弱点处置（确认/指派/整改/复测/忽略/归档）
)

// RegisterRoutes 注册弱点中心路由。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/weaknesses",
		authz(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.List))))
	mux.Handle("GET /api/v1/api-security/weaknesses/{id}",
		authz(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.Detail))))
	mux.Handle("POST /api/v1/api-security/weaknesses/{id}/confirm",
		authz(middleware.RequirePermission(PermHandle)(http.HandlerFunc(h.Confirm))))
	mux.Handle("POST /api/v1/api-security/weaknesses/{id}/assign",
		authz(middleware.RequirePermission(PermHandle)(http.HandlerFunc(h.Assign))))
	mux.Handle("POST /api/v1/api-security/weaknesses/{id}/fixed",
		authz(middleware.RequirePermission(PermHandle)(http.HandlerFunc(h.Fixed))))
	mux.Handle("POST /api/v1/api-security/weaknesses/{id}/retest",
		authz(middleware.RequirePermission(PermHandle)(http.HandlerFunc(h.Retest))))
	mux.Handle("POST /api/v1/api-security/weaknesses/{id}/ignore",
		authz(middleware.RequirePermission(PermHandle)(http.HandlerFunc(h.Ignore))))
	mux.Handle("POST /api/v1/api-security/weaknesses/{id}/archive",
		authz(middleware.RequirePermission(PermHandle)(http.HandlerFunc(h.Archive))))
}
