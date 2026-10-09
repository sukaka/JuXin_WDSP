// handler.go MCP 工具目录与绑定管理端点（NG-MCP G1 批次 B1，设计 §1.14）：
//
//	POST   /api/v1/api-security/mcp/tool-catalogs
//	GET    /api/v1/api-security/mcp/tool-catalogs
//	GET    /api/v1/api-security/mcp/tool-catalogs/{id}
//	PUT    /api/v1/api-security/mcp/tool-catalogs/{id}
//	DELETE /api/v1/api-security/mcp/tool-catalogs/{id}
//	POST   /api/v1/api-security/mcp/tool-catalogs/{id}/tools/{toolId}/review
//	GET    /api/v1/api-security/mcp/bindings
//	POST   /api/v1/api-security/mcp/bindings
//	PUT    /api/v1/api-security/mcp/bindings/{id}
//	DELETE /api/v1/api-security/mcp/bindings/{id}
//
// 权限：read=api_spec.read / manage=api_spec.manage（零新增权限点）；
// 写操作 HIGH 审计（目录与绑定变更影响工具调用检查面——与对象模型 PATCH 同纪律）。
package apimcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// auditRecorder 操作审计记录接口（*audits.Service 实现；单测注入 spy——apigrpcdesc 同形态）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// PublishFunc 触发现有网关配置发布链（口径同 apiflows.PublishFunc；nil = 发布通道暂不可用）。
type PublishFunc func(ctx context.Context, uid uuid.UUID, requestID string)

// Handler MCP 目录管理面处理器。
type Handler struct {
	repo    Repository
	audits  auditRecorder
	publish PublishFunc
}

// NewHandler 创建（audit 为 nil 时跳过审计不影响主流程）。
func NewHandler(repo Repository, audit *audits.Service) *Handler {
	h := &Handler{repo: repo}
	if audit != nil {
		h.audits = audit
	}
	return h
}

// SetPublishFunc 注入现有配置发布链（设计 §1.14：绑定变更提交后异步触发整站发布
// 热生效；发布失败仅记日志，绑定已落库，后续发布可重试带上最新状态——apiflows 同一口径）。
func (h *Handler) SetPublishFunc(fn PublishFunc) { h.publish = fn }

// triggerPublish 绑定变更提交后触发发布链；发布通道不可用时 Warn 延迟同步。
func (h *Handler) triggerPublish(r *http.Request, p *authz.Principal) {
	if h.publish == nil {
		slog.Warn("mcp catalog binding changed but publish channel unavailable, gateway sync deferred")
		return
	}
	uid := uuid.Nil
	if p != nil {
		uid = p.UserID
	}
	h.publish(context.Background(), uid, response.RequestIDFrom(r))
}

// ---------- 目录 ----------

// CreateCatalog POST /mcp/tool-catalogs（显式导入；新工具/变更行落 PENDING_REVIEW）。
func (h *Handler) CreateCatalog(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req CatalogInput
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if msg := ValidateCatalogInput(req); msg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return
	}
	createdBy := ""
	if p != nil {
		createdBy = p.Username
	}
	c, tools, err := h.repo.CreateCatalog(r.Context(), req, createdBy)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", "mcp_tool_catalog", c.ID.String(), c.Name,
		"", catalogSummary(c, len(tools)), audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]any{"catalog": c, "tools": tools})
}

// ListCatalogs GET /mcp/tool-catalogs（含 catalog_hash 与审核统计）。
func (h *Handler) ListCatalogs(w http.ResponseWriter, r *http.Request) {
	list, err := h.repo.ListCatalogs(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": list, "total": len(list)})
}

// GetCatalog GET /mcp/tool-catalogs/{id}（详情含工具行）。
func (h *Handler) GetCatalog(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	c, tools, err := h.repo.GetCatalog(r.Context(), id)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"catalog": c, "tools": tools})
}

// UpdateCatalog PUT /mcp/tool-catalogs/{id}（整体再导入；乐观锁；变更行重置待审核）。
func (h *Handler) UpdateCatalog(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req CatalogInput
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if msg := ValidateCatalogInput(req); msg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return
	}
	if req.Version < 1 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "version 必须 ≥1（乐观锁与目录 version 比对）")
		return
	}
	c, tools, err := h.repo.UpdateCatalog(r.Context(), id, req)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", "mcp_tool_catalog", c.ID.String(), c.Name,
		"", catalogSummary(c, len(tools)), audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]any{"catalog": c, "tools": tools})
}

// DeleteCatalog DELETE /mcp/tool-catalogs/{id}（绑定引用 409 先决校验）。
func (h *Handler) DeleteCatalog(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := h.repo.DeleteCatalog(r.Context(), id); err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", "mcp_tool_catalog", id.String(), "", "", "",
		audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

// ReviewTool POST /mcp/tool-catalogs/{id}/tools/{toolId}/review（审核+定级）。
func (h *Handler) ReviewTool(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	catalogID, ok := parseID(w, r)
	if !ok {
		return
	}
	toolID, err := uuid.Parse(r.PathValue("toolId"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 toolId")
		return
	}
	var req ReviewInput
	if err := response.DecodeJSON(w, r, &req, 65536); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	action := strings.ToUpper(strings.TrimSpace(req.Action))
	if action != ReviewApproved && action != ReviewRejected {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, ErrReviewActionVocab.Error())
		return
	}
	if msg := validateReviewLevels(req); msg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return
	}
	reviewedBy := ""
	if p != nil {
		reviewedBy = p.Username
	}
	t, err := h.repo.ReviewTool(r.Context(), catalogID, toolID, req, reviewedBy)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "review", "mcp_catalog_tool", toolID.String(), t.ToolName,
		"", reviewSummary(t), audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, t)
}

// validateReviewLevels 审核定级词表（risk/data_classification 给出即校）。
func validateReviewLevels(in ReviewInput) string {
	if v := strings.ToUpper(strings.TrimSpace(in.RiskLevel)); v != "" {
		switch v {
		case RiskLow, RiskMedium, RiskHigh:
		default:
			return "risk_level 词表外（LOW|MEDIUM|HIGH）"
		}
	}
	if v := strings.ToUpper(strings.TrimSpace(in.DataClassification)); v != "" {
		switch v {
		case ClassPublic, ClassInternal, ClassConfidential, ClassUnknown:
		default:
			return "data_classification 词表外（PUBLIC|INTERNAL|CONFIDENTIAL|UNKNOWN）"
		}
	}
	if in.MaxCallsPerMinute != nil && *in.MaxCallsPerMinute < 0 {
		return "max_calls_per_minute 必须 ≥0"
	}
	return ""
}

// ---------- 绑定 ----------

// ListBindings GET /mcp/bindings（application_id 可选过滤）。
func (h *Handler) ListBindings(w http.ResponseWriter, r *http.Request) {
	var applicationID uuid.UUID
	if v := strings.TrimSpace(r.URL.Query().Get("application_id")); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的站点ID")
			return
		}
		applicationID = id
	}
	list, err := h.repo.ListBindings(r.Context(), applicationID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": list, "total": len(list)})
}

// CreateBinding POST /mcp/bindings（同（应用,endpoint_path）409）。
func (h *Handler) CreateBinding(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req BindingInput
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if msg := ValidateBindingInput(req); msg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return
	}
	createdBy := ""
	if p != nil {
		createdBy = p.Username
	}
	b, err := h.repo.CreateBinding(r.Context(), req, createdBy)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", "mcp_catalog_binding", b.ID.String(), b.EndpointPath,
		"", bindingSummary(b), audits.ResultSuccess, audits.RiskHigh)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, b)
}

// UpdateBinding PUT /mcp/bindings/{id}（改 mode/目录；乐观锁）。
func (h *Handler) UpdateBinding(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req BindingInput
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if _, err := uuid.Parse(strings.TrimSpace(req.CatalogID)); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "catalog_id 非法（UUID）")
		return
	}
	switch strings.ToUpper(strings.TrimSpace(req.Mode)) {
	case "", ModeObserve, ModeProtect:
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "mode 非法（OBSERVE|PROTECT）")
		return
	}
	if req.Version < 1 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "version 必须 ≥1（乐观锁与绑定行 version 比对）")
		return
	}
	b, err := h.repo.UpdateBinding(r.Context(), id, req)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", "mcp_catalog_binding", b.ID.String(), b.EndpointPath,
		"", bindingSummary(b), audits.ResultSuccess, audits.RiskHigh)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, b)
}

// DeleteBinding DELETE /mcp/bindings/{id}（解绑）。
func (h *Handler) DeleteBinding(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := h.repo.DeleteBinding(r.Context(), id); err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", "mcp_catalog_binding", id.String(), "", "", "",
		audits.ResultSuccess, audits.RiskHigh)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

// ---------- 内部 ----------

func parseID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的资源ID")
		return uuid.Nil, false
	}
	return id, true
}

// writeStoreError 存储/校验错误→HTTP 精确映射（400 校验 / 404 不存在 / 409 冲突语义）。
func writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, ve.Msg)
	case errors.Is(err, ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "目录不存在")
	case errors.Is(err, ErrBindingNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "绑定不存在")
	case errors.Is(err, ErrDuplicateName):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "同名目录已存在")
	case errors.Is(err, ErrBindingDuplicate):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "同（应用,endpoint_path）绑定已存在（恰一条）")
	case errors.Is(err, ErrCatalogNotFound):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "引用的目录不存在")
	case errors.Is(err, ErrAppNotFound):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "引用的应用不存在")
	case errors.Is(err, ErrVersionConflict):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, ErrVersionConflict.Error())
	case errors.Is(err, ErrCatalogInUse):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, ErrCatalogInUse.Error())
	default:
		response.InternalError(w, r, err)
	}
}

// recordAudit 写操作审计（apigrpcdesc 同形态）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objType, objID, objName, before, after, result, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_security",
		Action:        action,
		ObjectType:    objType,
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        result,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

// catalogSummary 目录审计摘要（JSON 形态——既有审计脱敏器对非 JSON 摘要整段遮蔽，
// 键均非敏感键全值保留可读）。
func catalogSummary(c *Catalog, toolCount int) string {
	return fmt.Sprintf(`{"name":%q,"service_identity":%q,"status":%q,"catalog_hash":%q,"version":%d,"tools":%d}`,
		c.Name, c.ServiceIdentity, c.Status, c.CatalogHash, c.Version, toolCount)
}

// reviewSummary 审核审计摘要（JSON 形态）。
func reviewSummary(t *Tool) string {
	return fmt.Sprintf(`{"tool_name":%q,"review_status":%q,"risk_level":%q,"data_classification":%q,"tool_hash":%q,"reviewed_by":%q}`,
		t.ToolName, t.ReviewStatus, t.RiskLevel, t.DataClassification, t.ToolHash, t.ReviewedBy)
}

// bindingSummary 绑定审计摘要（JSON 形态）。
func bindingSummary(b *Binding) string {
	return fmt.Sprintf(`{"application_id":%q,"endpoint_path":%q,"catalog_id":%q,"catalog_name":%q,"mode":%q,"version":%d}`,
		b.ApplicationID.String(), b.EndpointPath, b.CatalogID.String(), b.CatalogName, b.Mode, b.Version)
}
