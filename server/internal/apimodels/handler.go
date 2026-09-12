package apimodels

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

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
	// runtime 运行时策略存取（P0-03/21；*Store 实现，包内单测可注入 fake）。
	runtime RuntimePolicyStore
	// runtimePublish 回滚后重触发整站发布（app 装配时接线 publisher.PublishSync；nil 时回滚接口返回 503）
	runtimePublish RuntimePolicyPublishFunc
	// respSchemas 响应 Schema 学习结果只读存取（P0-06；*Store 实现，包内单测可注入 fake）
	respSchemas ResponseSchemaReader
	// batchConfirm 参数批量采纳存取（*Store 实现，包内单测可注入 fake；语义同 runtime/respSchemas）
	batchConfirm ParameterBatchConfirmer
}

// NewHandler 创建处理器（构造注入审计服务，语义同 customrules）。
func NewHandler(store *Store, audit *audits.Service) *Handler {
	h := &Handler{store: store, audits: audit}
	if store != nil {
		h.runtime = store
		h.respSchemas = store
		h.batchConfirm = store
	}
	return h
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
	mux.Handle("POST /api/v1/api-security/models/{id}/parameters/confirm-batch", authz(rp("api_parameter.edit")(http.HandlerFunc(h.ConfirmParametersBatch))))
	mux.Handle("GET /api/v1/api-security/models/{id}/parameter-relations", authz(rp("api_parameter.read")(http.HandlerFunc(h.ListParameterRelations))))
	// 参数条件关系确认闭环（W11-REL）：手工新建（候选）→ confirm 生效 / reject 撤回
	mux.Handle("POST /api/v1/api-security/models/{id}/parameter-relations", authz(rp("api_parameter.edit")(http.HandlerFunc(h.CreateParameterRelation))))
	mux.Handle("POST /api/v1/api-security/parameter-relations/{id}/confirm", authz(rp("api_parameter.edit")(http.HandlerFunc(h.ConfirmParameterRelation))))
	mux.Handle("POST /api/v1/api-security/parameter-relations/{id}/reject", authz(rp("api_parameter.edit")(http.HandlerFunc(h.RejectParameterRelation))))

	// ---- 运行时策略版本（P0-03/21：编译产物列表/溯源/回滚）----
	mux.Handle("GET /api/v1/api-security/runtime-policies", authz(rp("api_model.read")(http.HandlerFunc(h.ListRuntimePolicies))))
	mux.Handle("GET /api/v1/api-security/models/{id}/runtime", authz(rp("api_model.read")(http.HandlerFunc(h.GetModelRuntimePolicies))))
	mux.Handle("POST /api/v1/api-security/runtime-policies/{id}/rollback", authz(rp("api_model.activate")(http.HandlerFunc(h.RollbackRuntimePolicy))))

	// ---- 响应 Schema 学习结果（P0-06：只读，按端点查、按状态码分组）----
	mux.Handle("GET /api/v1/api-security/endpoints/{id}/response-schemas", authz(rp("api_model.read")(http.HandlerFunc(h.ListResponseSchemas))))
}

// ---------- 51.2 模型生命周期 ----------

// ListModels GET /api/v1/api-security/endpoints/{id}/models
func (h *Handler) ListModels(w http.ResponseWriter, r *http.Request) {
	endpointID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的接口ID")
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
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的接口ID")
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
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
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
		"status="+before.Status, "激活为接口当前模型, version_number="+strconv.Itoa(v.VersionNumber), audits.RiskHigh)
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
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListParametersByVersionPage(r.Context(), id, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"items": list, "total": total, "page": page, "page_size": pageSize,
	})
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
	// confirmed_constraints 用指针区分「省略（保留）」与「显式 {}（清空）」；
	// semantic_type 用指针区分「省略（保留）」与「显式空串（清空）」
	var req struct {
		Required             bool            `json:"required"`
		Nullable             bool            `json:"nullable"`
		EmptyAllowed         bool            `json:"empty_allowed"`
		ConfirmedConstraints *map[string]any `json:"confirmed_constraints"`
		SensitivityLevel     string          `json:"sensitivity_level"`
		SemanticType         *string         `json:"semantic_type"`
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
	in := ParameterConfirmInput{
		Required:         req.Required,
		Nullable:         req.Nullable,
		EmptyAllowed:     req.EmptyAllowed,
		SensitivityLevel: req.SensitivityLevel,
		SemanticType:     req.SemanticType,
	}
	if req.ConfirmedConstraints != nil {
		in.UpdateConstraints = true
		in.ConfirmedConstraints = *req.ConfirmedConstraints
	}
	updated, err := h.store.UpdateParameterConfirmed(r.Context(), id, in)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", "api_parameter", id.String(), before.ParameterName,
		"required="+strconv.FormatBool(before.Required)+", sensitivity="+before.SensitivityLevel+", semantic_type="+before.SemanticType,
		"required="+strconv.FormatBool(updated.Required)+", sensitivity="+updated.SensitivityLevel+", semantic_type="+updated.SemanticType, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{"parameter": updated, "message": "参数约束已更新"})
}

// ParameterBatchConfirmer 参数批量采纳存取（*Store 实现；包内单测注入 fake，
// 仿 runtime/respSchemas 的构造+Setter 注入惯例）。
type ParameterBatchConfirmer interface {
	// ConfirmParametersBatch 批量采纳推荐约束；ids 为空则采纳版本内全部有 recommended 的参数
	ConfirmParametersBatch(ctx context.Context, versionID uuid.UUID, ids []uuid.UUID) (confirmed, skipped int, err error)
}

// SetParameterBatchConfirmer 覆盖参数批量采纳存取（测试注入 fake；生产无需调用）。
func (h *Handler) SetParameterBatchConfirmer(c ParameterBatchConfirmer) { h.batchConfirm = c }

// ConfirmParametersBatch POST /api/v1/api-security/models/{id}/parameters/confirm-batch
// body 可选 {"ids":["uuid",...]}；省略 ids（或空 body）则采纳本版本全部有 recommended 的参数。
// 非空 body 必须是合法 JSON：解析失败明确 400——不得静默吞错按全量采纳处理
// （否则非法 body 会触发全量分支且审计误记成功）。
func (h *Handler) ConfirmParametersBatch(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	versionID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模型版本ID")
		return
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if r.ContentLength > 0 {
		if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
			return
		}
	}
	var ids []uuid.UUID
	for _, s := range req.IDs {
		id, err := uuid.Parse(s)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的参数ID")
			return
		}
		ids = append(ids, id)
	}
	confirmed, skipped, err := h.batchConfirm.ConfirmParametersBatch(r.Context(), versionID, ids)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "confirm_batch", "api_parameter", versionID.String(), "batch",
		"", "批量采纳推荐约束 confirmed="+strconv.Itoa(confirmed)+" skipped="+strconv.Itoa(skipped), audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"confirmed": confirmed, "skipped": skipped,
		"message": "批量确认完成",
	})
}

// ListParameterRelations GET /api/v1/api-security/models/{id}/parameter-relations
func (h *Handler) ListParameterRelations(w http.ResponseWriter, r *http.Request) {
	versionID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模型版本ID")
		return
	}
	list, err := h.store.ListParameterRelations(r.Context(), versionID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if list == nil {
		list = []map[string]any{}
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": list})
}

// CreateParameterRelation POST /api/v1/api-security/models/{id}/parameter-relations
// body: {"source_parameter_id":"uuid","target_parameter_id":"uuid","relation_type":"REQUIRES|MUTEX|EQUALS|NOT_EQUALS|GREATER_THAN|LESS_THAN|TIME_BEFORE|TIME_AFTER"}
// 新建为候选（confirmed=false），确认走 confirm 接口（只有 confirmed 关系进入强制检测）。
func (h *Handler) CreateParameterRelation(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	versionID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模型版本ID")
		return
	}
	var req struct {
		SourceParameterID string `json:"source_parameter_id"`
		TargetParameterID string `json:"target_parameter_id"`
		RelationType      string `json:"relation_type"`
	}
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	srcID, err := uuid.Parse(req.SourceParameterID)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的源参数ID")
		return
	}
	tgtID, err := uuid.Parse(req.TargetParameterID)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的目标参数ID")
		return
	}
	rel, err := h.store.CreateParameterRelation(r.Context(), versionID, srcID, tgtID,
		strings.ToUpper(strings.TrimSpace(req.RelationType)))
	if writeRelationError(w, r, err) {
		return
	}
	h.recordAudit(r, p, "create", "api_parameter_relation", rel.ID.String(), rel.RelationType,
		"", "新建参数关系候选（confirmed=false）", audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{"relation": rel, "message": "参数关系已创建（候选，确认后生效）"})
}

// ConfirmParameterRelation POST /api/v1/api-security/parameter-relations/{id}/confirm
func (h *Handler) ConfirmParameterRelation(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的关系ID")
		return
	}
	rel, err := h.store.ConfirmParameterRelation(r.Context(), id, operatorID(p))
	if writeRelationError(w, r, err) {
		return
	}
	h.recordAudit(r, p, "confirm", "api_parameter_relation", rel.ID.String(), rel.RelationType,
		"confirmed=false", "confirmed=true（随发布下发网关强制检测）", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"relation": rel, "message": "参数关系已确认"})
}

// RejectParameterRelation POST /api/v1/api-security/parameter-relations/{id}/reject
// 撤回确认：confirmed → 候选（行保留不删除，避免 CO_OCCURS 候选被自动刷新重新生成）。
func (h *Handler) RejectParameterRelation(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的关系ID")
		return
	}
	rel, err := h.store.RejectParameterRelation(r.Context(), id)
	if writeRelationError(w, r, err) {
		return
	}
	h.recordAudit(r, p, "reject", "api_parameter_relation", rel.ID.String(), rel.RelationType,
		"confirmed=true", "confirmed=false（撤回确认，不再下发）", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"relation": rel, "message": "参数关系已撤回确认"})
}

// writeRelationError 参数关系错误统一映射：404/400/409；非领域错误走 500。返回 true 表示已响应。
func writeRelationError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, ErrRelationNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "参数关系不存在")
	case errors.Is(err, ErrRelationInvalidType):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "手工新建仅支持 REQUIRES / MUTEX 关系")
	case errors.Is(err, ErrRelationParamMismatch):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "关系两端参数必须为该版本内不同的请求侧参数")
	case errors.Is(err, ErrRelationDuplicate):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "同参数对同类型关系已存在")
	case errors.Is(err, ErrRelationAlreadyConfirmed):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "关系已确认，请勿重复操作")
	case errors.Is(err, ErrRelationNotConfirmed):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "关系未确认，无需撤回")
	default:
		response.InternalError(w, r, err)
	}
	return true
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
	if errors.Is(err, ErrEmptyRecommended) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "推荐约束为空，无法采纳；请先编辑确认约束")
		return
	}
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
