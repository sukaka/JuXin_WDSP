// routes.go AI 定时运营任务路由注册，统一 /api/v1/api-security/ai-ops 前缀。
// authz 为认证链（会话解析+认证+CSRF），权限点在路由层强制校验。
package apiops

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/middleware"
)

// 权限点（种子迁移 000063；三权口径仿 000019：SECURITY_ADMIN 全量、AUDIT_ADMIN 只读）。
const (
	PermRead    = "api_ai.read"    // 计划/执行记录查询
	PermExecute = "api_ai.execute" // 计划创建/修改/删除/启停/立即执行
)

// RegisterRoutes 注册 AI 定时运营任务路由。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	// 任务类型词表
	mux.Handle("GET /api/v1/api-security/ai-ops/task-types",
		authz(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.ListTaskTypes))))
	// 计划
	mux.Handle("GET /api/v1/api-security/ai-ops/schedules",
		authz(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.ListSchedules))))
	mux.Handle("POST /api/v1/api-security/ai-ops/schedules",
		authz(middleware.RequirePermission(PermExecute)(http.HandlerFunc(h.CreateSchedule))))
	mux.Handle("GET /api/v1/api-security/ai-ops/schedules/{id}",
		authz(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.GetSchedule))))
	mux.Handle("PUT /api/v1/api-security/ai-ops/schedules/{id}",
		authz(middleware.RequirePermission(PermExecute)(http.HandlerFunc(h.UpdateSchedule))))
	mux.Handle("DELETE /api/v1/api-security/ai-ops/schedules/{id}",
		authz(middleware.RequirePermission(PermExecute)(http.HandlerFunc(h.DeleteSchedule))))
	// 启停
	mux.Handle("POST /api/v1/api-security/ai-ops/schedules/{id}/enable",
		authz(middleware.RequirePermission(PermExecute)(http.HandlerFunc(h.EnableSchedule))))
	mux.Handle("POST /api/v1/api-security/ai-ops/schedules/{id}/disable",
		authz(middleware.RequirePermission(PermExecute)(http.HandlerFunc(h.DisableSchedule))))
	// 立即执行
	mux.Handle("POST /api/v1/api-security/ai-ops/schedules/{id}/run",
		authz(middleware.RequirePermission(PermExecute)(http.HandlerFunc(h.RunSchedule))))
	// 执行记录
	mux.Handle("GET /api/v1/api-security/ai-ops/schedules/{id}/runs",
		authz(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.ListRuns))))
	mux.Handle("GET /api/v1/api-security/ai-ops/runs/{id}",
		authz(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.GetRun))))
}
