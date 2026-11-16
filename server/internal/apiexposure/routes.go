// routes.go 暴露面判定路由注册（统一 /api/v1/api-security 前缀；
// 权限点零新增：读复用 api_asset.read，即时重评复用 api_asset.edit）。
package apiexposure

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/middleware"
)

// RegisterRoutes 注册暴露面判定路由。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/endpoints/{id}/exposure",
		authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.GetExposure))))
	mux.Handle("POST /api/v1/api-security/endpoints/{id}/exposure/reassess",
		authz(middleware.RequirePermission("api_asset.edit")(http.HandlerFunc(h.Reassess))))
}
