// routes.go MCP 工具目录路由注册（NG-MCP G1 批次 B1，统一 /api/v1/api-security
// 前缀；权限复用 api_spec.read/manage（目录与 gRPC 描述符同属接口契约资产域，
// 零新增权限点——apigrpcdesc routes.go 同域先例）。
package apimcp

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/middleware"
)

// RegisterRoutes 注册 MCP 目录与绑定路由。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	// 目录 CRUD + 审核（写操作 manage+HIGH 审计）
	mux.Handle("POST /api/v1/api-security/mcp/tool-catalogs",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.CreateCatalog))))
	mux.Handle("GET /api/v1/api-security/mcp/tool-catalogs",
		authz(middleware.RequirePermission("api_spec.read")(http.HandlerFunc(h.ListCatalogs))))
	mux.Handle("GET /api/v1/api-security/mcp/tool-catalogs/{id}",
		authz(middleware.RequirePermission("api_spec.read")(http.HandlerFunc(h.GetCatalog))))
	mux.Handle("PUT /api/v1/api-security/mcp/tool-catalogs/{id}",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.UpdateCatalog))))
	mux.Handle("DELETE /api/v1/api-security/mcp/tool-catalogs/{id}",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.DeleteCatalog))))
	mux.Handle("POST /api/v1/api-security/mcp/tool-catalogs/{id}/tools/{toolId}/review",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.ReviewTool))))
	mux.Handle("POST /api/v1/api-security/mcp/tools/{id}/pin",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.PinTool))))
	// 绑定 CRUD
	mux.Handle("GET /api/v1/api-security/mcp/bindings",
		authz(middleware.RequirePermission("api_spec.read")(http.HandlerFunc(h.ListBindings))))
	mux.Handle("POST /api/v1/api-security/mcp/bindings",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.CreateBinding))))
	mux.Handle("PUT /api/v1/api-security/mcp/bindings/{id}",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.UpdateBinding))))
	mux.Handle("DELETE /api/v1/api-security/mcp/bindings/{id}",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.DeleteBinding))))
}
