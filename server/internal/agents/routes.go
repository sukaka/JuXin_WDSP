// routes.go 路由注册：管理端走 authChain + RequirePermission（契约 §4 权限点），
// 机器端不挂 authz 链（无会话/CSRF 面，自有 Bearer credential 认证——契约 §3）。
package agents

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/middleware"
)

// 权限点（契约 §4；种子见迁移 000109_traffic_agent_perms）。
const (
	PermAgentsView   = "traffic.agents.view"
	PermAgentsManage = "traffic.agents.manage"
)

// RegisterAdminRoutes 注册管理端路由（读 traffic.agents.view，写 traffic.agents.manage）。
func RegisterAdminRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	view := func(fn http.HandlerFunc) http.Handler {
		return authz(middleware.RequirePermission(PermAgentsView)(fn))
	}
	manage := func(fn http.HandlerFunc) http.Handler {
		return authz(middleware.RequirePermission(PermAgentsManage)(fn))
	}

	// 注册令牌
	mux.Handle("POST /api/v1/traffic/agents/enrollment-tokens", manage(h.CreateToken))
	mux.Handle("GET /api/v1/traffic/agents/enrollment-tokens", view(h.ListTokens))
	mux.Handle("POST /api/v1/traffic/agents/enrollment-tokens/{id}/revoke", manage(h.RevokeToken))

	// 跨平台安装包清单、WDSP 接入地址自动探测与离线下载（须先于 {agent_id} 语义声明）
	mux.Handle("GET /api/v1/traffic/agents/packages", view(h.ListPackages))
	mux.Handle("GET /api/v1/traffic/agents/packages/{os}/{arch}/{format}", view(h.DownloadPackage))
	mux.Handle("GET /api/v1/traffic/agents/install-endpoint", view(h.GetInstallEndpoint))
	mux.Handle("PUT /api/v1/traffic/agents/install-endpoint", manage(h.UpdateInstallEndpoint))

	// Agent 查询（summary 须先于 {agent_id} 注册，Go 1.22 ServeMux 按特异性匹配，
	// 固定段 summary 天然优先于通配 {agent_id}，顺序仅为可读性）
	mux.Handle("GET /api/v1/traffic/agents/summary", view(h.Summary))
	mux.Handle("GET /api/v1/traffic/agents", view(h.ListAgents))
	mux.Handle("GET /api/v1/traffic/agents/{agent_id}", view(h.GetAgent))
	mux.Handle("GET /api/v1/traffic/agents/{agent_id}/events", view(h.ListEvents))
	// HTTP 事件（Phase 3 契约 §6：分页 ts 倒序；单条全量）
	mux.Handle("GET /api/v1/traffic/agents/{agent_id}/http-events", view(h.ListHTTPEvents))
	mux.Handle("GET /api/v1/traffic/agents/{agent_id}/http-events/{id}", view(h.GetHTTPEvent))
	// HTTP 资产来源关系（v2 契约 §5：关联状态可查询——配额拒绝/未绑定/失败不只 Warn）
	mux.Handle("GET /api/v1/traffic/agents/{agent_id}/http-asset-sources", view(h.ListHTTPAssetSources))
	// 定向采集规则（Phase 4 契约 §2.3：创建/删除联动 config_version+1）
	mux.Handle("GET /api/v1/traffic/agents/{agent_id}/overrides", view(h.ListOverrides))
	mux.Handle("POST /api/v1/traffic/agents/{agent_id}/overrides", manage(h.CreateOverride))
	mux.Handle("DELETE /api/v1/traffic/agents/{agent_id}/overrides/{override_id}", manage(h.DeleteOverride))

	// Agent 禁用/启用/删除
	mux.Handle("POST /api/v1/traffic/agents/{agent_id}/disable", manage(h.DisableAgent))
	mux.Handle("POST /api/v1/traffic/agents/{agent_id}/enable", manage(h.EnableAgent))
	mux.Handle("DELETE /api/v1/traffic/agents/{agent_id}", manage(h.DeleteAgent))

	// 策略绑定
	mux.Handle("POST /api/v1/traffic/agents/{agent_id}/policy", manage(h.BindPolicy))
	mux.Handle("DELETE /api/v1/traffic/agents/{agent_id}/policy", manage(h.UnbindPolicy))

	// 策略 CRUD
	mux.Handle("GET /api/v1/traffic/policies", view(h.ListPolicies))
	mux.Handle("POST /api/v1/traffic/policies", manage(h.CreatePolicy))
	mux.Handle("GET /api/v1/traffic/policies/{id}", view(h.GetPolicy))
	mux.Handle("PUT /api/v1/traffic/policies/{id}", manage(h.UpdatePolicy))
	mux.Handle("DELETE /api/v1/traffic/policies/{id}", manage(h.DeletePolicy))

	// 策略版本化与回滚（Phase 2，设计 §68.13/§68.14）
	mux.Handle("GET /api/v1/traffic/policies/{id}/versions", view(h.ListPolicyVersions))
	mux.Handle("POST /api/v1/traffic/policies/{id}/rollback", manage(h.RollbackPolicy))
}

// RegisterMachineRoutes 注册机器端路由（无 authz——Bearer credential / 证书 PoP / ACTIVE 注册令牌认证，无 CSRF 面）。
func RegisterMachineRoutes(mux *http.ServeMux, mh *MachineHandler) {
	mux.Handle("GET /api/v1/agents/bootstrap/manifest", http.HandlerFunc(mh.BootstrapManifest))
	mux.Handle("GET /api/v1/agents/bootstrap/script/{os}", http.HandlerFunc(mh.BootstrapScript))
	mux.Handle("GET /api/v1/agents/bootstrap/packages/{os}/{arch}/{format}", http.HandlerFunc(mh.BootstrapPackage))
	mux.Handle("POST /api/v1/agents/enroll", http.HandlerFunc(mh.Enroll))
	mux.Handle("POST /api/v1/agents/{agent_id}/heartbeat", http.HandlerFunc(mh.Heartbeat))
	mux.Handle("POST /api/v1/agents/{agent_id}/metrics", http.HandlerFunc(mh.Metrics))
	mux.Handle("GET /api/v1/agents/{agent_id}/config", http.HandlerFunc(mh.GetConfig))
	mux.Handle("POST /api/v1/agents/{agent_id}/config/ack", http.HandlerFunc(mh.ConfigAck))
	mux.Handle("POST /api/v1/agents/{agent_id}/flows", http.HandlerFunc(mh.Flows))
	mux.Handle("POST /api/v1/agents/{agent_id}/http", http.HandlerFunc(mh.HTTPEvents))
	mux.Handle("POST /api/v1/agents/{agent_id}/api-observations", http.HandlerFunc(mh.APIObservations))
	mux.Handle("POST /api/v1/agents/{agent_id}/packets", http.HandlerFunc(mh.Packets))
	mux.Handle("POST /api/v1/agents/{agent_id}/rotate-cert", http.HandlerFunc(mh.RotateCert))
}
