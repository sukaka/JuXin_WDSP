package apimodels

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 模型版本与参数 API（任务书 51.2 / 51.3）。
type Handler struct {
	store  *Store
	audits *audits.Service
}

// NewHandler 创建处理器（构造注入审计服务，语义同 customrules）。
func NewHandler(store *Store, audit *audits.Service) *Handler {
	return &Handler{store: store, audits: audit}
}

// RegisterRoutes 注册任务书 51.2（模型生命周期）与 51.3（参数）路由。
// authz 为认证链（会话解析+认证+CSRF），权限点在路由层按任务书五十二章强制校验。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	rp := middleware.RequirePermission

	// ---- 51.2 模型生命周期 ----
	mux.Handle("GET /api/v1/api-security/endpoints/{id}/models", authz(rp("api_model.read")(http.HandlerFunc(h.ListModels))))
	mux.Handle("POST /api/v1/api-security/endpoints/{id}/models", authz(rp("api_model.edit")(http.HandlerFunc(h.CreateModel))))
	mux.Handle("GET /api/v1/api-security/models/{id}", authz(rp("api_model.read")(http.HandlerFunc(h.GetModel))))
	mux.Handle("GET /api/v1/api-security/models/{id}/diff/{other_id}", authz(rp("api_model.read")(http.HandlerFunc(h.DiffModel))))
	mux.Handle("POST /api/v1/api-security/models/{id}/submit-review", authz(rp("api_model.review")(http.HandlerFunc(h.SubmitReview))))
	mux.Handle("POST /api/v1/api-security/models/{id}/confirm", authz(rp("api_model.confirm")(http.HandlerFunc(h.Confirm))))
	mux.Handle("POST /api/v1/api-security/models/{id}/reject", authz(rp("api_model.review")(http.HandlerFunc(h.Reject))))
	mux.Handle("POST /api/v1/api-security/models/{id}/activate", authz(rp("api_model.activate")(http.HandlerFunc(h.Activate))))
	mux.Handle("POST /api/v1/api-security/models/{id}/archive", authz(rp("api_model.archive")(http.HandlerFunc(h.Archive))))

	// ---- 51.3 参数 ----
	mux.Handle("GET /api/v1/api-security/models/{id}/parameters", authz(rp("api_parameter.read")(http.HandlerFunc(h.ListParameters))))
	mux.Handle("GET /api/v1/api-security/parameters/{id}", authz(rp("api_parameter.read")(http.HandlerFunc(h.GetParameter))))
	mux.Handle("PATCH /api/v1/api-security/parameters/{id}", authz(rp("api_parameter.edit")(http.HandlerFunc(h.UpdateParameter))))
	mux.Handle("POST /api/v1/api-security/parameters/{id}/confirm", authz(rp("api_parameter.edit")(http.HandlerFunc(h.ConfirmParameter))))
}

// ---------- 51.2 模型生命周期 ----------

// ListModels GET /api/v1/api-security/endpoints/{id}/models
func (h *Handler) ListModels(w http.ResponseWriter, r *http.Request) {
	endpointID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的端点ID")
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListByEndpoint(r.Context(), endpointID, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// CreateModel POST /api/v1/api-security/endpoints/{id}/models
// body: {"schema": {"字段": "类型", ...}, "change_summary": "可选变更说明"}
func (h *Handler) CreateModel(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	endpointID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的端点ID")
		return
	}
	var req struct {
		Schema        map[string]string `json:"schema"`
		ChangeSummary string            `json:"change_summary"`
	}
	if err := response.DecodeJSON(w, r, &req, 65536); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if len(req.Schema) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "schema 不能为空")
		return
	}
	endpointKey, err := h.store.EndpointKey(r.Context(), endpointID)
	if errors.Is(err, ErrEndpointNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	v, err := h.store.CreateCandidate(r.Context(), endpointID, endpointKey, req.ChangeSummary, req.Schema, operatorID(p))
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", "api_model", v.ID.String(), endpointKey,
		"", "创建候选模型, 字段数="+strconv.Itoa(len(v.Schema)), audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{"version": v, "message": "候选模型已创建"})
}

// GetModel GET /api/v1/api-security/models/{id}
func (h *Handler) GetModel(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模型版本ID")
		return
	}
	v, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "模型版本不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, v)
}

// DiffModel GET /api/v1/api-security/models/{id}/diff/{other_id}
func (h *Handler) DiffModel(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模型版本ID")
		return
	}
	otherID, err := uuid.Parse(r.PathValue("other_id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的对比版本ID")
		return
	}
	d, err := h.store.Diff(r.Context(), id, otherID)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "模型版本不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, d)
}

// SubmitReview POST /api/v1/api-security/models/{id}/submit-review
func (h *Handler) SubmitReview(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, comment, ok := h.mutationInput(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "模型版本不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	v, err := h.store.SubmitReview(r.Context(), id, operatorID(p), comment)
	if writeStateError(w, r, err) {
		return
	}
	h.recordAudit(r, p, "submit_review", "api_model", id.String(), before.EndpointKey,
		"status="+before.Status, "status="+v.Status, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{"version": v, "message": "已提交评审"})
}

// Confirm POST /api/v1/api-security/models/{id}/confirm
func (h *Handler) Confirm(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模型版本ID")
		return
	}
	before, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "模型版本不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	v, err := h.store.Confirm(r.Context(), id, operatorID(p))
	if writeStateError(w, r, err) {
		return
	}
	h.recordAudit(r, p, "confirm", "api_model", id.String(), before.EndpointKey,
		"status="+before.Status, "status=FORMAL, version_number="+strconv.Itoa(v.VersionNumber), audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"version": v, "message": "模型已确认为正式版本"})
}

// Reject POST /api/v1/api-security/models/{id}/reject
func (h *Handler) Reject(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, comment, ok := h.mutationInput(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "模型版本不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	v, err := h.store.Reject(r.Context(), id, operatorID(p), comment)
	if writeStateError(w, r, err) {
		return
	}
	h.recordAudit(r, p, "reject", "api_model", id.String(), before.EndpointKey,
		"status="+before.Status, "status="+v.Status, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{"version": v, "message": "模型已拒绝"})
}

// Activate POST /api/v1/api-security/models/{id}/activate
func (h *Handler) Activate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模型版本ID")
		return
	}
	before, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "模型版本不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	v, err := h.store.Activate(r.Context(), id)
	if writeStateError(w, r, err) {
		return
	}
	h.recordAudit(r, p, "activate", "api_model", id.String(), before.EndpointKey,
		"status="+before.Status, "激活为端点当前模型, version_number="+strconv.Itoa(v.VersionNumber), audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]any{"version": v, "message": "模型已激活"})
}

// Archive POST /api/v1/api-security/models/{id}/archive
func (h *Handler) Archive(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模型版本ID")
		return
	}
	before, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "模型版本不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	v, err := h.store.Archive(r.Context(), id)
	if writeStateError(w, r, err) {
		return
	}
	h.recordAudit(r, p, "archive", "api_model", id.String(), before.EndpointKey,
		"status="+before.Status, "status="+v.Status, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"version": v, "message": "模型已归档"})
}

// ---------- 51.3 参数 ----------

// ListParameters GET /api/v1/api-security/models/{id}/parameters
func (h *Handler) ListParameters(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模型版本ID")
		return
	}
	list, err := h.store.ListParametersByVersion(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": list})
}

// GetParameter GET /api/v1/api-security/parameters/{id}
func (h *Handler) GetParameter(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的参数ID")
		return
	}
	p, err := h.store.GetParameterByID(r.Context(), id)
	if errors.Is(err, ErrParameterNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "参数不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, p)
}

// UpdateParameter PATCH /api/v1/api-security/parameters/{id}
func (h *Handler) UpdateParameter(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的参数ID")
		return
	}
	var req struct {
		Required             bool           `json:"required"`
		Nullable             bool           `json:"nullable"`
		EmptyAllowed         bool           `json:"empty_allowed"`
		ConfirmedConstraints map[string]any `json:"confirmed_constraints"`
		SensitivityLevel     string         `json:"sensitivity_level"`
	}
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	before, err := h.store.GetParameterByID(r.Context(), id)
	if errors.Is(err, ErrParameterNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "参数不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	updated, err := h.store.UpdateParameterConfirmed(r.Context(), id, ParameterConfirmInput{
		Required:             req.Required,
		Nullable:             req.Nullable,
		EmptyAllowed:         req.EmptyAllowed,
		ConfirmedConstraints: req.ConfirmedConstraints,
		SensitivityLevel:     req.SensitivityLevel,
	})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", "api_parameter", id.String(), before.ParameterName,
		"required="+strconv.FormatBool(before.Required)+", sensitivity="+before.SensitivityLevel,
		"required="+strconv.FormatBool(updated.Required)+", sensitivity="+updated.SensitivityLevel, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{"parameter": updated, "message": "参数约束已更新"})
}

// ConfirmParameter POST /api/v1/api-security/parameters/{id}/confirm
func (h *Handler) ConfirmParameter(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的参数ID")
		return
	}
	before, err := h.store.GetParameterByID(r.Context(), id)
	if errors.Is(err, ErrParameterNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "参数不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	confirmed, err := h.store.ConfirmParameter(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "confirm", "api_parameter", id.String(), before.ParameterName,
		"", "采纳推荐约束为确认约束", audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{"parameter": confirmed, "message": "参数约束已确认"})
}

// ---------- 内部辅助 ----------

// mutationInput 解析路径 id 与可选 {"comment": "..."} 请求体（空体视为无评论）。
func (h *Handler) mutationInput(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模型版本ID")
		return uuid.Nil, "", false
	}
	if r.ContentLength == 0 {
		return id, "", true
	}
	var req struct {
		Comment string `json:"comment"`
	}
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return uuid.Nil, "", false
	}
	return id, req.Comment, true
}

// writeStateError 状态机冲突统一返回 409；非状态错误走 500。返回 true 表示已响应。
func writeStateError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "模型版本不存在")
	case errors.Is(err, ErrNotCandidate):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "仅候选或评审中的版本可确认为正式模型")
	case errors.Is(err, ErrInvalidTransition):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "当前状态不允许该操作")
	case errors.Is(err, ErrFormalImmutable):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "正式模型不可修改")
	default:
		response.InternalError(w, r, err)
	}
	return true
}

// operatorID 取操作者 ID（主体缺失时为零值，落库为 NULL）。
func operatorID(p *authz.Principal) uuid.UUID {
	if p == nil {
		return uuid.Nil
	}
	return p.UserID
}

// recordAudit 写操作审计（含操作者、动作、对象、前后摘要、风险等级）；
// 审计服务未接线或主体缺失时跳过，不影响主流程。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objType, objID, objName, before, after, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	_ = h.audits.Record(r.Context(), audits.RecordInput{
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
		Result:        audits.ResultSuccess,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
