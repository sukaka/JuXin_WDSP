// Package apiassets API 端点资产管理（阶段8/WDSP 任务书 51.1 端点组 + 学习启停）。
package apiassets

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler API 端点管理。
type Handler struct {
	store  Repository
	audits *audits.Service
}

// NewHandler 创建处理器（构造注入审计服务，语义同 customrules）。
func NewHandler(store Repository, audit *audits.Service) *Handler {
	return &Handler{store: store, audits: audit}
}

// RegisterRoutes 注册任务书 51.1 / 51.2 端点组（统一 /api/v1/api-security 前缀，
// 权限点与任务书五十二章一致）。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/endpoints", authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.List))))
	mux.Handle("POST /api/v1/api-security/endpoints/confirm", authz(middleware.RequirePermission("api_asset.confirm")(http.HandlerFunc(h.ConfirmBatch))))
	mux.Handle("GET /api/v1/api-security/endpoints/{id}", authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.Get))))
	mux.Handle("PATCH /api/v1/api-security/endpoints/{id}", authz(middleware.RequirePermission("api_asset.edit")(http.HandlerFunc(h.Update))))
	mux.Handle("POST /api/v1/api-security/endpoints/{id}/merge", authz(middleware.RequirePermission("api_asset.merge")(http.HandlerFunc(h.Merge))))
	mux.Handle("POST /api/v1/api-security/endpoints/{id}/split", authz(middleware.RequirePermission("api_asset.split")(http.HandlerFunc(h.Split))))
	mux.Handle("POST /api/v1/api-security/endpoints/{id}/ignore", authz(middleware.RequirePermission("api_asset.ignore")(http.HandlerFunc(h.Ignore))))
	mux.Handle("POST /api/v1/api-security/endpoints/{id}/classify", authz(middleware.RequirePermission("api_asset.edit")(http.HandlerFunc(h.Classify))))
	mux.Handle("POST /api/v1/api-security/endpoints/{id}/learning/start", authz(middleware.RequirePermission("api_learning.start")(http.HandlerFunc(h.LearningStart))))
	mux.Handle("POST /api/v1/api-security/endpoints/{id}/learning/stop", authz(middleware.RequirePermission("api_learning.stop")(http.HandlerFunc(h.LearningStop))))
	mux.Handle("GET /api/v1/api-security/endpoints/{id}/learning/status", authz(middleware.RequirePermission("api_learning.read")(http.HandlerFunc(h.LearningStatus))))
	mux.Handle("GET /api/v1/api-security/endpoints/{id}/learning/samples", authz(middleware.RequirePermission("api_learning.read")(http.HandlerFunc(h.LearningSamples))))
	mux.Handle("GET /api/v1/api-security/endpoints/{id}/lifecycle-events", authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.LifecycleEvents))))
}

// List GET /api/v1/api-security/endpoints
// 过滤：asset_status / learning_status / keyword / application_id。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := ListFilter{
		AssetStatus:    strings.ToUpper(strings.TrimSpace(q.Get("asset_status"))),
		LearningStatus: strings.ToUpper(strings.TrimSpace(q.Get("learning_status"))),
		Keyword:        strings.TrimSpace(q.Get("keyword")),
		Page:           queryInt(r, "page", 1),
		PageSize:       queryInt(r, "page_size", 20),
	}
	if v := strings.TrimSpace(q.Get("application_id")); v != "" {
		appID, err := uuid.Parse(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的application_id")
			return
		}
		f.ApplicationID = &appID
	}
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// ConfirmBatch POST /api/v1/api-security/endpoints/confirm  {ids:[...]}
// 批量确认 asset_status=CONFIRMED。
func (h *Handler) ConfirmBatch(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req struct {
		IDs []uuid.UUID `json:"ids"`
	}
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if len(req.IDs) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "ids 不能为空")
		return
	}
	if len(req.IDs) > 100 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "单次最多确认 100 个端点")
		return
	}
	type failedItem struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	}
	confirmed := []string{}
	failed := []failedItem{}
	for _, id := range req.IDs {
		_, err := h.store.Confirm(r.Context(), id)
		if errors.Is(err, ErrNotFound) {
			failed = append(failed, failedItem{ID: id.String(), Reason: "端点不存在"})
			continue
		}
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		confirmed = append(confirmed, id.String())
	}
	objID := ""
	if len(req.IDs) > 0 {
		objID = req.IDs[0].String()
	}
	h.recordAudit(r, p, "confirm", objID, fmt.Sprintf("批量确认 %d 个端点", len(req.IDs)),
		summaryJSON(map[string]any{"ids": req.IDs}),
		summaryJSON(map[string]any{"confirmed": len(confirmed), "failed": len(failed)}), audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"confirmed":     len(confirmed),
		"confirmed_ids": confirmed,
		"failed":        failed,
	})
}

// Get GET /api/v1/api-security/endpoints/{id}（含 api_assets 扩展字段）
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	e, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	asset, err := h.store.GetAsset(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	e.Asset = asset
	response.JSON(w, r, http.StatusOK, map[string]any{"endpoint": e})
}

// Update PATCH /api/v1/api-security/endpoints/{id}
// 编辑 api_assets：purpose/exposure/owner/tags（全量替换）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Purpose  string   `json:"purpose"`
		Exposure string   `json:"exposure"`
		Owner    string   `json:"owner"`
		Tags     []string `json:"tags"`
	}
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	req.Purpose = strings.TrimSpace(req.Purpose)
	req.Owner = strings.TrimSpace(req.Owner)
	req.Exposure = strings.ToUpper(strings.TrimSpace(req.Exposure))
	if req.Purpose == "" && req.Exposure == "" && req.Owner == "" && req.Tags == nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体不能为空")
		return
	}
	switch req.Exposure {
	case "", "INTERNAL", "PARTNER", "PUBLIC":
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的暴露面取值（INTERNAL/PARTNER/PUBLIC）")
		return
	}
	if len(req.Purpose) > 128 || len(req.Owner) > 128 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "purpose/owner 长度不能超过 128")
		return
	}
	if len(req.Tags) > 32 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "标签数量不能超过 32")
		return
	}
	for _, t := range req.Tags {
		if len(strings.TrimSpace(t)) == 0 || len(t) > 64 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "标签不能为空且长度不能超过 64")
			return
		}
	}
	e, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	before, err := h.store.GetAsset(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	asset, err := h.store.UpsertAsset(r.Context(), id, req.Purpose, req.Exposure, req.Owner, req.Tags)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "edit", id.String(), truncateName(e.EndpointKey),
		assetSummary(before), assetSummary(asset), audits.RiskMedium)
	e.Asset = asset
	response.JSON(w, r, http.StatusOK, map[string]any{"endpoint": e, "message": "资产信息已更新"})
}

// Merge POST /api/v1/api-security/endpoints/{id}/merge  {other_id}
func (h *Handler) Merge(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	var req struct {
		OtherID uuid.UUID `json:"other_id"`
	}
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.OtherID == uuid.Nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "other_id 不能为空")
		return
	}
	if req.OtherID == id {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "不能将端点合并到自身")
		return
	}
	other, err := h.store.GetByID(r.Context(), req.OtherID)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "待合并端点不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	before, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	merged, err := h.store.Merge(r.Context(), id, req.OtherID, actorOf(p))
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "merge", id.String(), truncateName(merged.EndpointKey),
		summaryJSON(map[string]any{"endpoint_key": before.EndpointKey, "hit_count": before.HitCount,
			"other_id": req.OtherID.String(), "other_key": other.EndpointKey}),
		summaryJSON(map[string]any{"endpoint_key": merged.EndpointKey, "hit_count": merged.HitCount}),
		audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]any{"endpoint": merged, "message": "端点已合并"})
}

// Split POST /api/v1/api-security/endpoints/{id}/split  {paths:[...]}
func (h *Handler) Split(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Paths []string `json:"paths"`
	}
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if len(req.Paths) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "拆分路径不能为空")
		return
	}
	if len(req.Paths) > 50 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "单次最多拆分 50 个路径")
		return
	}
	normed := make([]string, 0, len(req.Paths))
	for _, raw := range req.Paths {
		if strings.TrimSpace(raw) == "" {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "拆分路径不能为空")
			return
		}
		normed = append(normed, normalizer.NormalizePath(raw))
	}
	src, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	created, err := h.store.Split(r.Context(), id, normed, actorOf(p))
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	if errors.Is(err, ErrEndpointConflict) {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
		return
	}
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "split", id.String(), truncateName(src.EndpointKey),
		summaryJSON(map[string]any{"endpoint_key": src.EndpointKey}),
		summaryJSON(map[string]any{"paths": normed, "created": len(created)}), audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"endpoints": created, "message": "端点已拆分"})
}

// Ignore POST /api/v1/api-security/endpoints/{id}/ignore（asset_status=IGNORED）
func (h *Handler) Ignore(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	e, err := h.store.SetAssetStatus(r.Context(), id, "IGNORED", actorOf(p))
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "ignore", id.String(), truncateName(e.EndpointKey),
		summaryJSON(map[string]any{"asset_status": before.AssetStatus}),
		summaryJSON(map[string]any{"asset_status": e.AssetStatus}), audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"endpoint": e, "message": "端点已忽略"})
}

// Classify POST /api/v1/api-security/endpoints/{id}/classify
// 按路径/方法启发式自动分类，写 api_classification_dimensions（source=AUTO）。
func (h *Handler) Classify(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	e, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	dims, err := h.store.AutoClassify(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	if errors.Is(err, ErrClassificationLocked) {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "分类已锁定，请先解锁后再执行自动分类")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "classify", id.String(), truncateName(e.EndpointKey), "",
		summaryJSON(map[string]any{"dimensions": dims}), audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{"dimensions": dims, "message": "自动分类完成"})
}

// LearningStart POST /api/v1/api-security/endpoints/{id}/learning/start
func (h *Handler) LearningStart(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	var createdBy *uuid.UUID
	if p != nil {
		uid := p.UserID
		createdBy = &uid
	}
	job, err := h.store.StartLearning(r.Context(), id, createdBy)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	if errors.Is(err, ErrLearningRunning) {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "该端点已有运行中的学习任务")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "learning_start", id.String(), id.String(), "",
		summaryJSON(map[string]any{"job_id": job.ID.String(), "status": job.Status}), audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{"job": job, "message": "学习任务已启动"})
}

// LearningStop POST /api/v1/api-security/endpoints/{id}/learning/stop
func (h *Handler) LearningStop(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	job, err := h.store.StopLearning(r.Context(), id, actorOf(p))
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	if errors.Is(err, ErrLearningNotRunning) {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "当前没有运行中的学习任务")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "learning_stop", id.String(), id.String(), "",
		summaryJSON(map[string]any{"job_id": job.ID.String(), "status": job.Status}), audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{"job": job, "message": "学习任务已停止"})
}

// LearningStatus GET /api/v1/api-security/endpoints/{id}/learning/status
func (h *Handler) LearningStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	e, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	job, stats, err := h.store.LearningStatus(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"endpoint_id":     id,
		"learning_status": e.LearningStatus,
		"job":             job,
		"samples":         stats,
	})
}

// LifecycleEvents GET /api/v1/api-security/endpoints/{id}/lifecycle-events
// api_lifecycle_events 按 created_at DESC 分页。
func (h *Handler) LifecycleEvents(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	if _, err := h.store.GetByID(r.Context(), id); errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	} else if err != nil {
		response.InternalError(w, r, err)
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListLifecycleEvents(r.Context(), id, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// LearningSamples GET /api/v1/api-security/endpoints/{id}/learning/samples
// api_learning_samples 过滤 accepted（true/false，可空）+ 分页。
func (h *Handler) LearningSamples(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	if _, err := h.store.GetByID(r.Context(), id); errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	} else if err != nil {
		response.InternalError(w, r, err)
		return
	}
	var accepted *bool
	if v := strings.TrimSpace(r.URL.Query().Get("accepted")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 accepted 取值（true/false）")
			return
		}
		accepted = &b
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListLearningSamples(r.Context(), id, accepted, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// recordAudit 写操作审计（语义同 customrules：操作者/动作/对象/前后摘要/风险等级）。
// 审计服务未注入（旧接线）或无操作者上下文时跳过，不影响主流程。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, before, after, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	_ = h.audits.Record(r.Context(), audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_assets",
		Action:        action,
		ObjectType:    "api_endpoint",
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        audits.ResultSuccess,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

func parsePathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的端点ID")
		return uuid.Nil, false
	}
	return id, true
}

func actorOf(p *authz.Principal) string {
	if p == nil || p.Username == "" {
		return "system"
	}
	return p.Username
}

// summaryJSON 生成审计摘要（合法 JSON 对象，交给审计层脱敏）。
func summaryJSON(v map[string]any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// assetSummary 资产扩展摘要；无记录时返回空。
func assetSummary(a *Asset) string {
	if a == nil {
		return ""
	}
	return summaryJSON(map[string]any{
		"purpose": a.Purpose, "exposure": a.Exposure,
		"owner": a.Owner, "tags": a.Tags,
	})
}

// truncateName 审计 object_name 列上限 255。
func truncateName(s string) string {
	if len(s) > 255 {
		return s[:255]
	}
	return s
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
