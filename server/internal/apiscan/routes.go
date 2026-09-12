// routes.go API 主动扫描路由注册，统一 /api/v1/api-security/scans 前缀。
// authz 为认证链（会话解析+认证+CSRF），权限点在路由层强制校验。
package apiscan

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/middleware"
)

// 权限点（种子迁移由集成方统一登记——任务书分配 000055；双权限点纪律：
// 建目标/任务管理 api_scan.manage 与授权签发/撤销 api_scan.execute 分离）。
const (
	PermRead    = "api_scan.read"    // 目标/授权/任务/发现查询
	PermExecute = "api_scan.execute" // 授权签发与撤销、紧急停止（联动撤销授权）、复测执行
	PermManage  = "api_scan.manage"  // 目标维护、任务发起/启停、发现处置
)

// RegisterRoutes 注册主动扫描路由。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	// 目标
	mux.Handle("GET /api/v1/api-security/scans/targets",
		authz(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.ListTargets))))
	mux.Handle("POST /api/v1/api-security/scans/targets",
		authz(middleware.RequirePermission(PermManage)(http.HandlerFunc(h.CreateTarget))))
	mux.Handle("GET /api/v1/api-security/scans/targets/{id}",
		authz(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.GetTarget))))
	mux.Handle("PUT /api/v1/api-security/scans/targets/{id}",
		authz(middleware.RequirePermission(PermManage)(http.HandlerFunc(h.UpdateTarget))))
	// 授权
	mux.Handle("POST /api/v1/api-security/scans/targets/{id}/authorize",
		authz(middleware.RequirePermission(PermExecute)(http.HandlerFunc(h.Authorize))))
	mux.Handle("GET /api/v1/api-security/scans/targets/{id}/authorizations",
		authz(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.ListAuthorizations))))
	mux.Handle("POST /api/v1/api-security/scans/authorizations/{id}/revoke",
		authz(middleware.RequirePermission(PermExecute)(http.HandlerFunc(h.RevokeAuthorization))))
	// 任务
	mux.Handle("GET /api/v1/api-security/scans/jobs",
		authz(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.ListJobs))))
	mux.Handle("POST /api/v1/api-security/scans/jobs",
		authz(middleware.RequirePermission(PermManage)(http.HandlerFunc(h.CreateJob))))
	mux.Handle("GET /api/v1/api-security/scans/jobs/{id}",
		authz(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.GetJob))))
	mux.Handle("POST /api/v1/api-security/scans/jobs/{id}/start",
		authz(middleware.RequirePermission(PermManage)(http.HandlerFunc(h.StartJob))))
	mux.Handle("POST /api/v1/api-security/scans/jobs/{id}/stop",
		authz(middleware.RequirePermission(PermManage)(http.HandlerFunc(h.StopJob))))
	// 紧急停止副作用含撤销授权（revoke 超集），须挂 execute 权限点，不得倒挂在 manage 上
	mux.Handle("POST /api/v1/api-security/scans/jobs/{id}/emergency-stop",
		authz(middleware.RequirePermission(PermExecute)(http.HandlerFunc(h.EmergencyStop))))
	// 发现
	mux.Handle("GET /api/v1/api-security/scans/findings",
		authz(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.ListFindings))))
	mux.Handle("POST /api/v1/api-security/scans/findings/{id}/confirm",
		authz(middleware.RequirePermission(PermManage)(http.HandlerFunc(h.ConfirmFinding))))
	mux.Handle("POST /api/v1/api-security/scans/findings/{id}/false-positive",
		authz(middleware.RequirePermission(PermManage)(http.HandlerFunc(h.FalsePositiveFinding))))
	mux.Handle("POST /api/v1/api-security/scans/findings/{id}/retest",
		authz(middleware.RequirePermission(PermExecute)(http.HandlerFunc(h.RetestFinding))))
}
