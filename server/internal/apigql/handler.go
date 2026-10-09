// handler.go GraphQL 成本预算策略管理 API（NG-GQL-03）：
//
//	GET    /api/v1/api-security/apps/{id}/graphql-policy   读策略（api_policy.read）
//	PUT    /api/v1/api-security/apps/{id}/graphql-policy   写策略（api_policy.edit + 审计）
//	DELETE /api/v1/api-security/apps/{id}/graphql-policy   删除=关闭（api_policy.edit + 审计）
//
// 纪律：无行 GET 返回 enabled=false 默认视图（「无段=关闭」，非 404）；
// 写入校验（非负数值/上限/32hex digest/键名 ≤128），非法 400；
// 写操作触发整站发布链由调用方决定（策略变更经发布生效，与 api_admission 同口径——
// 本端点只读写库与审计，不隐式发布）。
package apigql

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 权限点（沿用 api-security policy 读写权限，任务书口径无新权限点）。
const (
	permPolicyRead = "api_policy.read"
	permPolicyEdit = "api_policy.edit"
)

// auditRecorder 操作审计记录接口（由 *audits.Service 实现；单测注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// 写入上限（防 OOM 配置与失控预算；与网关侧归一上限同口径）。
const (
	maxDocBytesCap    = 64 << 20 // 与网关 apiGraphQLPolicyJSON.toPolicy 归一上限一致
	maxBudgetCap      = 1 << 40
	maxTrustedDigests = 1024
	maxWeightPathLen  = 128
	maxWeightEntries  = 4096
)

// Handler GraphQL 策略管理面处理器。
type Handler struct {
	store  Store
	audits auditRecorder
}

// NewHandler 创建处理器。
func NewHandler(store Store, auditsSvc auditRecorder) *Handler {
	return &Handler{store: store, audits: auditsSvc}
}

// RegisterRoutes 注册路由（/api/v1/api-security 命名空间）。
func RegisterRoutes(mux *http.ServeMux, authzFn func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/apps/{id}/graphql-policy",
		authzFn(middleware.RequirePermission(permPolicyRead)(http.HandlerFunc(h.Get))))
	mux.Handle("PUT /api/v1/api-security/apps/{id}/graphql-policy",
		authzFn(middleware.RequirePermission(permPolicyEdit)(http.HandlerFunc(h.Put))))
	mux.Handle("DELETE /api/v1/api-security/apps/{id}/graphql-policy",
		authzFn(middleware.RequirePermission(permPolicyEdit)(http.HandlerFunc(h.Delete))))
}

// Get GET /api/v1/api-security/apps/{id}/graphql-policy
// 读单应用策略（无行返回 enabled=false 默认视图；id 非法 400）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	appID, ok := parseAppID(w, r)
	if !ok {
		return
	}
	view, err := h.store.GetPolicy(r.Context(), appID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, view)
}

// Put PUT /api/v1/api-security/apps/{id}/graphql-policy
// 写入策略（upsert；应用不存在 404；非法输入 400；审计 after=策略摘要）。
func (h *Handler) Put(w http.ResponseWriter, r *http.Request) {
	appID, ok := parseAppID(w, r)
	if !ok {
		return
	}
	var req Policy
	if err := decodeStrict(w, r, &req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误: "+err.Error())
		return
	}
	if msg := validatePolicy(req); msg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return
	}
	var actorID uuid.UUID
	p := authz.PrincipalFrom(r.Context())
	if p != nil {
		actorID = p.UserID
	}
	view, err := h.store.UpsertPolicy(r.Context(), appID, req, actorID)
	if err != nil {
		if errors.Is(err, ErrAppNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在或已删除")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", appID.String(), "PUT graphql-policy: "+policySummary(view.Policy), "SUCCESS")
	response.JSON(w, r, http.StatusOK, view)
}

// Delete DELETE /api/v1/api-security/apps/{id}/graphql-policy
// 删除策略行（→ 关闭；审计 after=disabled）。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	appID, ok := parseAppID(w, r)
	if !ok {
		return
	}
	p := authz.PrincipalFrom(r.Context())
	var actorID uuid.UUID
	if p != nil {
		actorID = p.UserID
	}
	if err := h.store.DeletePolicy(r.Context(), appID, actorID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", appID.String(), "DELETE graphql-policy（→ 关闭）", "SUCCESS")
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

// parseAppID 路径应用 ID（非法 400）。
func parseAppID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用 id（需 UUID）")
		return uuid.Nil, false
	}
	return id, true
}

// decodeStrict 严格 JSON 解码（拒绝未知字段与多余内容；上限 1MiB 远低于字段校验）。
func decodeStrict(w http.ResponseWriter, r *http.Request, v *Policy) error {
	return decodeJSONStrict(r, v, 1<<20)
}

// validatePolicy 写入校验：非负数值/上限/digest 形态/键名长度。返回首个违规描述（空=合法）。
func validatePolicy(p Policy) string {
	if p.Limits.MaxDocBytes < 0 || p.Limits.MaxDocBytes > maxDocBytesCap {
		return "limits.max_doc_bytes 须在 0..64MiB"
	}
	for name, v := range map[string]int{
		"limits.max_depth": p.Limits.MaxDepth, "limits.max_nodes": p.Limits.MaxNodes,
		"limits.max_aliases": p.Limits.MaxAliases, "limits.max_fragment_exp": p.Limits.MaxFragmentExp,
	} {
		if v < 0 {
			return name + " 不得为负"
		}
	}
	if len(p.Weights.Fields) > maxWeightEntries {
		return "weights.fields 超过上限 4096"
	}
	for path, fw := range p.Weights.Fields {
		if len(path) > maxWeightPathLen {
			return "weights.fields 键超过 128 字符: " + path
		}
		if fw.Weight < 0 || fw.ListBound < 0 || fw.Weight > maxBudgetCap || fw.ListBound > maxBudgetCap {
			return "weights.fields." + path + " 数值非法"
		}
	}
	for name, v := range map[string]int64{
		"weights.default_field_weight": p.Weights.DefaultFieldWeight,
		"weights.default_list_bound":   p.Weights.DefaultListBound,
		"weights.introspection_weight": p.Weights.IntrospectionWeight,
		"budget.per_request_budget":    p.Budget.PerRequest,
		"budget.window_seconds":        p.Budget.WindowSeconds,
		"budget.window_budget":         p.Budget.WindowBudget,
		"budget.anonymous_budget":      p.Budget.AnonymousBudget,
	} {
		if v < 0 || v > maxBudgetCap {
			return name + " 须在 0..2^40"
		}
	}
	if len(p.TrustedDocDigests) > maxTrustedDigests {
		return "trusted_doc_digests 超过上限 1024"
	}
	for _, d := range p.TrustedDocDigests {
		if len(d) != 32 {
			return "trusted_doc_digests 须为 32 位 hex（gqlast.DigestDocument 口径）: " + d
		}
		for _, c := range d {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return "trusted_doc_digests 须为小写 hex: " + d
			}
		}
	}
	return ""
}

// policySummary 审计摘要（enabled + 关键预算键；不含完整 config）。
func policySummary(p Policy) string {
	enabled := "disabled"
	if p.Enabled {
		enabled = "enabled"
	}
	return enabled + " per_request_budget=" + itoa64(p.Budget.PerRequest) +
		" window_budget=" + itoa64(p.Budget.WindowBudget) +
		" trusted_docs=" + itoa(len(p.TrustedDocDigests))
}

// recordAudit 写操作审计（与 apirevokedcreds 同一纪律：审计未注入/无主体跳过）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, after, result string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "api_security",
		Action:       action,
		ObjectType:   "api_graphql_policy",
		ObjectID:     objID,
		AfterSummary: after,
		Result:       result,
		RiskLevel:    "MEDIUM",
		RequestID:    response.RequestIDFrom(r),
	})
}
