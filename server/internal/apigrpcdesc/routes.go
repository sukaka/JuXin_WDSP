// routes.go gRPC 描述符集路由注册（W14-DESC / P2-05 深化），统一 /api/v1/api-security 前缀。
// 权限点复用 api_spec.manage（描述符集与 API 规范同属接口契约资产管理，任务书口径）。
package apigrpcdesc

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/middleware"
)

// RegisterRoutes 注册 gRPC 描述符集路由。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("POST /api/v1/api-security/grpc-descriptors",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.Upload))))
	mux.Handle("GET /api/v1/api-security/grpc-descriptors",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.List))))
	mux.Handle("DELETE /api/v1/api-security/grpc-descriptors/{id}",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.Delete))))
}
