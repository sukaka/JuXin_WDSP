// routes.go 已吊销凭据路由注册（阶段8 §35），统一 /api/v1/api-security 前缀。
// 权限点 api_credential.read / api_credential.manage（种子见迁移 000156）。
package apirevokedcreds

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/middleware"
)

// RegisterRoutes 注册已吊销凭据路由。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/revoked-credentials",
		authz(middleware.RequirePermission(PermCredentialRead)(http.HandlerFunc(h.List))))
	mux.Handle("POST /api/v1/api-security/revoked-credentials",
		authz(middleware.RequirePermission(PermCredentialManage)(http.HandlerFunc(h.Create))))
	mux.Handle("GET /api/v1/api-security/revoked-credentials/{id}",
		authz(middleware.RequirePermission(PermCredentialRead)(http.HandlerFunc(h.Get))))
	mux.Handle("PUT /api/v1/api-security/revoked-credentials/{id}",
		authz(middleware.RequirePermission(PermCredentialManage)(http.HandlerFunc(h.Update))))
	mux.Handle("DELETE /api/v1/api-security/revoked-credentials/{id}",
		authz(middleware.RequirePermission(PermCredentialManage)(http.HandlerFunc(h.Delete))))
}
