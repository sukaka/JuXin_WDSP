// routes.go 机器身份登记路由注册（NG-ID g1 批次 B1，统一 /api/v1/api-security 前缀；
// 权限复用 jwt_trust.read/manage——机器身份与 JWT 信任链同属可信密钥管理域
// （app.go:1045-1047 实证已注册），零新增权限点）。
package apimachineid

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/middleware"
)

// RegisterRoutes 注册机器身份与绑定路由。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	// 身份 CRUD（写操作 manage+HIGH 审计）
	mux.Handle("POST /api/v1/api-security/machine-identities",
		authz(middleware.RequirePermission("jwt_trust.manage")(http.HandlerFunc(h.CreateIdentity))))
	mux.Handle("GET /api/v1/api-security/machine-identities",
		authz(middleware.RequirePermission("jwt_trust.read")(http.HandlerFunc(h.ListIdentities))))
	mux.Handle("GET /api/v1/api-security/machine-identities/{id}",
		authz(middleware.RequirePermission("jwt_trust.read")(http.HandlerFunc(h.GetIdentity))))
	mux.Handle("PUT /api/v1/api-security/machine-identities/{id}",
		authz(middleware.RequirePermission("jwt_trust.manage")(http.HandlerFunc(h.UpdateIdentity))))
	mux.Handle("DELETE /api/v1/api-security/machine-identities/{id}",
		authz(middleware.RequirePermission("jwt_trust.manage")(http.HandlerFunc(h.DeleteIdentity))))
	// 公钥导入/轮换/撤销（§1.3 静态离线导入纪律；§1.6 状态机）
	mux.Handle("POST /api/v1/api-security/machine-identities/{id}/keys",
		authz(middleware.RequirePermission("jwt_trust.manage")(http.HandlerFunc(h.ImportKey))))
	mux.Handle("POST /api/v1/api-security/machine-identities/{id}/keys/{keyId}/rotate",
		authz(middleware.RequirePermission("jwt_trust.manage")(http.HandlerFunc(h.RotateKey))))
	mux.Handle("POST /api/v1/api-security/machine-identities/{id}/keys/{keyId}/revoke",
		authz(middleware.RequirePermission("jwt_trust.manage")(http.HandlerFunc(h.RevokeKey))))
	// 绑定 CRUD
	mux.Handle("GET /api/v1/api-security/machine-identity-bindings",
		authz(middleware.RequirePermission("jwt_trust.read")(http.HandlerFunc(h.ListBindings))))
	mux.Handle("POST /api/v1/api-security/machine-identity-bindings",
		authz(middleware.RequirePermission("jwt_trust.manage")(http.HandlerFunc(h.CreateBinding))))
	mux.Handle("PUT /api/v1/api-security/machine-identity-bindings/{id}",
		authz(middleware.RequirePermission("jwt_trust.manage")(http.HandlerFunc(h.UpdateBinding))))
	mux.Handle("DELETE /api/v1/api-security/machine-identity-bindings/{id}",
		authz(middleware.RequirePermission("jwt_trust.manage")(http.HandlerFunc(h.DeleteBinding))))
}
