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
	// 51.5 规范导入（W3-C：版本状态机 / URL 导入 / 跨版本 CHANGED diff）
	mux.Handle("POST /api/v1/api-security/specs/import",
		authz(middleware.RequirePermission("api_spec.import")(http.HandlerFunc(h.ImportSpec))))
	mux.Handle("POST /api/v1/api-security/specs/import-url",
		authz(middleware.RequirePermission("api_spec.import")(http.HandlerFunc(h.ImportSpecURL))))
	mux.Handle("GET /api/v1/api-security/specs",
		authz(middleware.RequirePermission("api_spec.read")(http.HandlerFunc(h.ListSpecs))))
	mux.Handle("GET /api/v1/api-security/specs/{id}/diff",
		authz(middleware.RequirePermission("api_spec.read")(http.HandlerFunc(h.GetSpecDiff))))
	mux.Handle("GET /api/v1/api-security/specs/{id}/version-diff",
		authz(middleware.RequirePermission("api_spec.read")(http.HandlerFunc(h.GetSpecVersionDiff))))
	mux.Handle("POST /api/v1/api-security/specs/{id}/activate",
		authz(middleware.RequirePermission("api_spec.manage")(http.HandlerFunc(h.ActivateSpec))))
	// 51.6 风险与运行时
	mux.Handle("GET /api/v1/api-security/findings",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.ListFindings))))
	// 风险中心（P0-13 Risk 侧：降噪聚合/详情/处置状态机；Risk=运行时异常，
	// 与 apiweakness 包的长期弱点互不混用）
	mux.Handle("GET /api/v1/api-security/findings/summary",
		authz(middleware.RequirePermission("api_risk.read")(http.HandlerFunc(h.RiskSummary))))
	mux.Handle("GET /api/v1/api-security/findings/{id}",
		authz(middleware.RequirePermission("api_risk.read")(http.HandlerFunc(h.RiskFindingDetail))))
	mux.Handle("POST /api/v1/api-security/findings/{id}/confirm",
		authz(middleware.RequirePermission("api_risk.handle")(http.HandlerFunc(h.RiskConfirm))))
	mux.Handle("POST /api/v1/api-security/findings/{id}/start",
		authz(middleware.RequirePermission("api_risk.handle")(http.HandlerFunc(h.RiskStart))))
	mux.Handle("POST /api/v1/api-security/findings/{id}/resolve",
		authz(middleware.RequirePermission("api_risk.handle")(http.HandlerFunc(h.RiskResolve))))
	mux.Handle("POST /api/v1/api-security/findings/{id}/false-positive",
		authz(middleware.RequirePermission("api_risk.handle")(http.HandlerFunc(h.RiskFalsePositive))))
	mux.Handle("POST /api/v1/api-security/findings/{id}/ignore",
		authz(middleware.RequirePermission("api_risk.handle")(http.HandlerFunc(h.RiskIgnore))))
	mux.Handle("POST /api/v1/api-security/findings/{id}/archive",
		authz(middleware.RequirePermission("api_risk.handle")(http.HandlerFunc(h.RiskArchive))))
	mux.Handle("GET /api/v1/api-security/violations",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.ListViolations))))
	mux.Handle("GET /api/v1/api-security/posture",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.Posture))))
	// W9-P101 态势补齐：顶部核心指标总览 + 按天趋势（复用 api_runtime.read）
	mux.Handle("GET /api/v1/api-security/posture/overview",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.PostureOverview))))
	mux.Handle("GET /api/v1/api-security/posture/trends",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.PostureTrends))))
	// W10-SEC 态势访问维度（任务书 §6.4/§6.5 残余）：访问来源 + 访问目标排名（复用 api_runtime.read）
	mux.Handle("GET /api/v1/api-security/posture/sources",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.PostureSources))))
	mux.Handle("GET /api/v1/api-security/posture/targets",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.PostureTargets))))
	mux.Handle("GET /api/v1/api-security/runtime/statistics",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.RuntimeStatistics))))
	mux.Handle("GET /api/v1/api-security/runtime/events",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.ListRuntimeEvents))))
	// API 准入防护（P1，docs/API_ADMISSION_CONTROL_DESIGN.md §5.2/§5.3）：
	// 覆盖率报告（切 PROTECT 前影响面评估）与准入拦截列表；权限同 api 资产页
	mux.Handle("GET /api/v1/api-security/admission/coverage",
		authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.AdmissionCoverage))))
	mux.Handle("GET /api/v1/api-security/admission/denied",
		authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.AdmissionDenied))))
	// 行为基线画像（WDSP 访问微模型：api_behavior_profiles 离线聚合结果只读）
	mux.Handle("GET /api/v1/api-security/behavior-profiles",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.ListBehaviorProfiles))))
	// 对象模型（WDSP 访问微模型·对象维度：api_object_models 清扫产出只读）
	mux.Handle("GET /api/v1/api-security/object-models",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.ListObjectModels))))
	// 对象模型发布状态管理（NG-AZ-02 D5/D7 管理写入路径；权限 api_authorization.manage + 审计）
	mux.Handle("PATCH /api/v1/api-security/object-models/{id}",
		authz(middleware.RequirePermission(permAuthorizationManage)(http.HandlerFunc(h.PatchObjectModel))))
	// 身份画像（身份微模型：api_identity_profiles 离线聚合 + 质量分）
	mux.Handle("GET /api/v1/api-security/identity-profiles",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.ListIdentityProfiles))))
	// 身份画像详情（画像 + 五级风险评估 + 近期事件；GB/T 31509 修订稿矩阵法，只产信号不阻断）
	mux.Handle("GET /api/v1/api-security/identity-profiles/detail",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.IdentityProfileDetail))))
	mux.Handle("GET /api/v1/api-security/sensitive-fields",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.ListSensitiveFields))))
	// 敏感字段识别结果批量删除（权限与敏感数据类型/脱敏规则同一管理点 api_data.manage）
	mux.Handle("POST /api/v1/api-security/sensitive-fields/batch-delete",
		authz(middleware.RequirePermission("api_data.manage")(http.HandlerFunc(h.DeleteSensitiveFields))))
	// 模型成熟度状态机总览（三微模型框架 §四第 10 项，真实表计数推导，只读）
	mux.Handle("GET /api/v1/api-security/model-maturity",
		authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(h.ModelMaturity))))
	// 防护策略（模式 db>env>default；发布触发配置下发网关）
	mux.Handle("GET /api/v1/api-security/policy",
		authz(middleware.RequirePermission("api_policy.read")(http.HandlerFunc(h.GetPolicy))))
	mux.Handle("PUT /api/v1/api-security/policy",
		authz(middleware.RequirePermission("api_policy.edit")(http.HandlerFunc(h.PutPolicy))))
	mux.Handle("POST /api/v1/api-security/policy/publish",
		authz(middleware.RequirePermission("api_policy.publish")(http.HandlerFunc(h.PublishPolicy))))
}
