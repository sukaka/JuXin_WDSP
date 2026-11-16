package apigroups

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/middleware"
)

func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/endpoint-groups",
		authz(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.List))))
	mux.Handle("POST /api/v1/api-security/endpoint-groups",
		authz(middleware.RequirePermission(PermManage)(http.HandlerFunc(h.Create))))
	mux.Handle("GET /api/v1/api-security/endpoint-groups/{id}",
		authz(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.Get))))
	mux.Handle("PUT /api/v1/api-security/endpoint-groups/{id}",
		authz(middleware.RequirePermission(PermManage)(http.HandlerFunc(h.Update))))
	mux.Handle("DELETE /api/v1/api-security/endpoint-groups/{id}",
		authz(middleware.RequirePermission(PermManage)(http.HandlerFunc(h.Delete))))
	mux.Handle("GET /api/v1/api-security/endpoint-groups/{id}/endpoints",
		authz(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.ListEndpoints))))
	mux.Handle("POST /api/v1/api-security/endpoint-groups/{id}/endpoints",
		authz(middleware.RequirePermission(PermManage)(http.HandlerFunc(h.AddEndpoint))))
	mux.Handle("DELETE /api/v1/api-security/endpoint-groups/{id}/endpoints/{endpoint_id}",
		authz(middleware.RequirePermission(PermManage)(http.HandlerFunc(h.RemoveEndpoint))))
}
