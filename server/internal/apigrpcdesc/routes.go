// routes.go gRPC 描述符集路由注册（W14-DESC / P2-05 深化），统一 /api/v1/api-security 前缀。
// 权限点复用 api_spec.manage（描述符集与 API 规范同属接口契约资产管理，任务书口径）。
package apigrpcdesc

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/middleware"
)

// RegisterRoutes 注册 gRPC 描述符集路由（含 NG-GRPC G1 批次 B1 per-app 绑定
// （设计 §1.3/§1.9：read=api_spec.read / manage=api_spec.manage（写+HIGH 审计）——
// 权限零新增（000019/000046 既有点））。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("POST /api/v1/api-security/grpc-descriptors",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.Upload))))
	mux.Handle("GET /api/v1/api-security/grpc-descriptors",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.List))))
	mux.Handle("DELETE /api/v1/api-security/grpc-descriptors/{id}",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.Delete))))
	// NG-GRPC G1 批次 B1：per-app 绑定 CRUD + 未登记服务清单
	mux.Handle("GET /api/v1/api-security/grpc-bindings",
		authz(middleware.RequirePermission("api_spec.read")(http.HandlerFunc(h.ListBindings))))
	mux.Handle("POST /api/v1/api-security/grpc-bindings",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.CreateBinding))))
	mux.Handle("PUT /api/v1/api-security/grpc-bindings/{id}",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.UpdateBinding))))
	mux.Handle("DELETE /api/v1/api-security/grpc-bindings/{id}",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.DeleteBinding))))
	mux.Handle("GET /api/v1/api-security/grpc-bindings/undocumented-services",
		authz(middleware.RequirePermission("api_spec.read")(http.HandlerFunc(h.ListUndocumentedServices))))
}
