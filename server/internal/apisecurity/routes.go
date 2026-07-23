// routes.go 阶段8（WDSP）51.4–51.6 路由注册，统一 /api/v1/api-security 前缀。
// authz 为认证链（会话解析+认证+CSRF），权限点在路由层按任务书五十二章强制校验。
package apisecurity

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/middleware"
)

// RegisterRoutes 注册 API 安全（分类图谱/规范导入/风险运行时）路由。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	// 51.4 用途分类
	mux.Handle("GET /api/v1/api-security/classifications",
		authz(middleware.RequirePermission("api_classification.read")(http.HandlerFunc(h.ListClassifications))))
	mux.Handle("POST /api/v1/api-security/classifications",
		authz(middleware.RequirePermission("api_classification.manage")(http.HandlerFunc(h.CreateClassification))))
	mux.Handle("PUT /api/v1/api-security/endpoints/{id}/classification",
		authz(middleware.RequirePermission("api_classification.manage")(http.HandlerFunc(h.PutEndpointClassification))))
	// 51.4 调用图谱 / 拓扑
	mux.Handle("GET /api/v1/api-security/graph",
		authz(middleware.RequirePermission("api_graph.read")(http.HandlerFunc(h.Graph))))
	mux.Handle("GET /api/v1/api-security/topology",
		authz(middleware.RequirePermission("api_graph.read")(http.HandlerFunc(h.Topology))))
	// 51.5 规范导入
	mux.Handle("POST /api/v1/api-security/specs/import",
		authz(middleware.RequirePermission("api_spec.import")(http.HandlerFunc(h.ImportSpec))))
	mux.Handle("GET /api/v1/api-security/specs",
		authz(middleware.RequirePermission("api_spec.read")(http.HandlerFunc(h.ListSpecs))))
	mux.Handle("GET /api/v1/api-security/specs/{id}/diff",
		authz(middleware.RequirePermission("api_spec.read")(http.HandlerFunc(h.GetSpecDiff))))
	// 51.6 风险与运行时
	mux.Handle("GET /api/v1/api-security/findings",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.ListFindings))))
	mux.Handle("GET /api/v1/api-security/violations",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.ListViolations))))
	mux.Handle("GET /api/v1/api-security/posture",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.Posture))))
	mux.Handle("GET /api/v1/api-security/runtime/statistics",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.RuntimeStatistics))))
	mux.Handle("GET /api/v1/api-security/runtime/events",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.ListRuntimeEvents))))
}
