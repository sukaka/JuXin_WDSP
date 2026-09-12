// routes.go 流程基线路由注册（阶段8 §44），统一 /api/v1/api-security 前缀。
// 权限点 api_flow.read / api_flow.manage（种子见迁移 000155）。
package apiflows

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/middleware"
)

// RegisterRoutes 注册流程基线路由。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/flow-baselines",
		authz(middleware.RequirePermission(PermFlowRead)(http.HandlerFunc(h.List))))
	mux.Handle("POST /api/v1/api-security/flow-baselines",
		authz(middleware.RequirePermission(PermFlowManage)(http.HandlerFunc(h.Create))))
	mux.Handle("GET /api/v1/api-security/flow-baselines/{id}",
		authz(middleware.RequirePermission(PermFlowRead)(http.HandlerFunc(h.Get))))
	mux.Handle("PUT /api/v1/api-security/flow-baselines/{id}",
		authz(middleware.RequirePermission(PermFlowManage)(http.HandlerFunc(h.Update))))
	mux.Handle("DELETE /api/v1/api-security/flow-baselines/{id}",
		authz(middleware.RequirePermission(PermFlowManage)(http.HandlerFunc(h.Delete))))
}
