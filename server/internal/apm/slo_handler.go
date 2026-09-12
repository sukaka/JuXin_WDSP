// slo_handler.go APM SLO 目标管理接口（设计 §16.2：PUT slos 为中风险审计——
// 本实现 create/update/delete 三个写接口统一按 RiskMedium 落审计；纯查询不写审计）。
// 权限点：读 apm.overview.read（迁移 000088）、写 apm.settings.manage（迁移 000089），
// 路由层由 middleware.RequirePermission 强制。评估口径见 slo_types.go 包注释。
package apm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// SLORepository SLO 存取与评估抽象（handler 单测以 fake 注入；生产为 *SLOStore）。
type SLORepository interface {
	CreateSLO(ctx context.Context, slo *SLO) error
	GetSLO(ctx context.Context, id uuid.UUID) (*SLO, error)
	UpdateSLO(ctx context.Context, slo *SLO) error
	DeleteSLO(ctx context.Context, id uuid.UUID) error
	EvaluateSLO(ctx context.Context, def *SLO, now time.Time) (*SLOListItem, error)
	EvaluateAllSLOs(ctx context.Context, now time.Time) ([]SLOListItem, error)
	SLOTrend(ctx context.Context, def *SLO, now time.Time) ([]SLOTrendPoint, error)
}

// SLOHandler SLO 管理接口处理器。
type SLOHandler struct {
	store  SLORepository
	audits auditRecorder // nil 时写操作不记审计（仅测试便利；生产装配必须注入）
	now    func() time.Time
}

// NewSLOHandler 创建 SLO 处理器。
func NewSLOHandler(store SLORepository) *SLOHandler {
	return &SLOHandler{store: store, now: time.Now}
}

// SetAudits 注入操作审计记录器（生产由 app 装配 *audits.Service）。
func (h *SLOHandler) SetAudits(a auditRecorder) *SLOHandler { h.audits = a; return h }

// RegisterSLORoutes 注册 /api/v1/apm/slos 路由（权限点与迁移 000088/000089 种子一致；
// 与 RegisterAgentAdminRoutes 同先例——独立注册函数，由 app 装配层调用）。
func RegisterSLORoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *SLOHandler) {
	mux.Handle("GET /api/v1/apm/slos", authz(middleware.RequirePermission("apm.overview.read")(http.HandlerFunc(h.ListSLOs))))
	mux.Handle("POST /api/v1/apm/slos", authz(middleware.RequirePermission(PermSettingsManage)(http.HandlerFunc(h.CreateSLO))))
	mux.Handle("GET /api/v1/apm/slos/{id}", authz(middleware.RequirePermission("apm.overview.read")(http.HandlerFunc(h.GetSLO))))
	mux.Handle("PUT /api/v1/apm/slos/{id}", authz(middleware.RequirePermission(PermSettingsManage)(http.HandlerFunc(h.UpdateSLO))))
	mux.Handle("DELETE /api/v1/apm/slos/{id}", authz(middleware.RequirePermission(PermSettingsManage)(http.HandlerFunc(h.DeleteSLO))))
}

// sloUpsertRequest 创建/全量更新入参。
type sloUpsertRequest struct {
	Name       string  `json:"name"`
	Service    string  `json:"service"`
	MetricType string  `json:"metric_type"`
	Target     float64 `json:"target"`
	Window     string  `json:"window"`
}

// sloListResponse GET /api/v1/apm/slos 响应数据（不分页，合同固定 {list,total}）。
type sloListResponse struct {
	List  []SLOListItem `json:"list"`
	Total int64         `json:"total"`
}

// parseSLOID 解析路径 id（非法 400）。
func parseSLOID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		badRequest(w, r, "无效的 id")
		return uuid.Nil, false
	}
	return id, true
}

// decodeSLOUpsert 解码并校验写接口入参（失败已写 400 响应）。
func decodeSLOUpsert(w http.ResponseWriter, r *http.Request) (*sloUpsertRequest, bool) {
	var req sloUpsertRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		badRequest(w, r, "请求格式错误")
		return nil, false
	}
	req.Name, req.Service = normalizeSLOStrings(req.Name, req.Service)
	if err := validateSLOInput(req.Name, req.Service, req.MetricType, req.Target, req.Window); err != nil {
		badRequest(w, r, err.Error())
		return nil, false
	}
	return &req, true
}

// sloWriteConflict 唯一冲突统一 409 文案。
func sloWriteConflict(w http.ResponseWriter, r *http.Request) {
	response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
		"该服务已存在相同指标与窗口的 SLO 定义")
}

// sloNotFound 统一 404 文案。
func sloNotFound(w http.ResponseWriter, r *http.Request) {
	response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "SLO 不存在")
}

// ListSLOs GET /api/v1/apm/slos（权限 apm.overview.read；不分页；逐项实时评估）。
func (h *SLOHandler) ListSLOs(w http.ResponseWriter, r *http.Request) {
	items, err := h.store.EvaluateAllSLOs(r.Context(), h.now())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, sloListResponse{List: items, Total: int64(len(items))})
}

// CreateSLO POST /api/v1/apm/slos（权限 apm.settings.manage；创建即评估一次；中风险审计）。
func (h *SLOHandler) CreateSLO(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	req, ok := decodeSLOUpsert(w, r)
	if !ok {
		return
	}
	slo := &SLO{
		Name:       req.Name,
		Service:    req.Service,
		MetricType: req.MetricType,
		Target:     req.Target,
		Window:     req.Window,
	}
	if p != nil {
		uid := p.UserID
		slo.CreatedBy = &uid
	}
	if err := h.store.CreateSLO(r.Context(), slo); err != nil {
		if errors.Is(err, ErrSLOConflict) {
			sloWriteConflict(w, r)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	// 创建即评估一次（评估失败为真实存储/聚合故障，如实 500；定义已持久化，可经 GET 复查）
	item, err := h.store.EvaluateSLO(r.Context(), slo, h.now())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", slo.ID.String(), slo.Service+"/"+slo.Name, "", sloSummary(slo))
	response.JSON(w, r, http.StatusOK, item)
}

// GetSLO GET /api/v1/apm/slos/{id}（权限 apm.overview.read；详情 + 窗口达标率趋势）。
func (h *SLOHandler) GetSLO(w http.ResponseWriter, r *http.Request) {
	id, ok := parseSLOID(w, r)
	if !ok {
		return
	}
	def, err := h.store.GetSLO(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrSLONotFound) {
			sloNotFound(w, r)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	now := h.now()
	item, err := h.store.EvaluateSLO(r.Context(), def, now)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	trend, err := h.store.SLOTrend(r.Context(), def, now)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, SLODetail{SLOListItem: *item, Trend: trend})
}

// UpdateSLO PUT /api/v1/apm/slos/{id}（权限 apm.settings.manage；全量更新；中风险审计）。
func (h *SLOHandler) UpdateSLO(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseSLOID(w, r)
	if !ok {
		return
	}
	req, ok := decodeSLOUpsert(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetSLO(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrSLONotFound) {
			sloNotFound(w, r)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	slo := &SLO{
		ID:         id,
		Name:       req.Name,
		Service:    req.Service,
		MetricType: req.MetricType,
		Target:     req.Target,
		Window:     req.Window,
	}
	if err := h.store.UpdateSLO(r.Context(), slo); err != nil {
		if errors.Is(err, ErrSLONotFound) {
			sloNotFound(w, r)
			return
		}
		if errors.Is(err, ErrSLOConflict) {
			sloWriteConflict(w, r)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	item, err := h.store.EvaluateSLO(r.Context(), slo, h.now())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", slo.ID.String(), slo.Service+"/"+slo.Name, sloSummary(before), sloSummary(slo))
	response.JSON(w, r, http.StatusOK, item)
}

// DeleteSLO DELETE /api/v1/apm/slos/{id}（权限 apm.settings.manage；中风险审计）。
func (h *SLOHandler) DeleteSLO(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseSLOID(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetSLO(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrSLONotFound) {
			sloNotFound(w, r)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.DeleteSLO(r.Context(), id); err != nil {
		if errors.Is(err, ErrSLONotFound) {
			sloNotFound(w, r)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", before.ID.String(), before.Service+"/"+before.Name, sloSummary(before), "deleted=true")
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "SLO 已删除"})
}

// sloSummary 审计摘要（定义字段全量，无敏感面）。
func sloSummary(s *SLO) string {
	if s == nil {
		return ""
	}
	b, _ := json.Marshal(map[string]interface{}{
		"name": s.Name, "service": s.Service, "metric_type": s.MetricType,
		"target": s.Target, "window": s.Window,
	})
	return string(b)
}

// recordAudit 记录操作审计（口径与 AgentAdminHandler.recordAudit 一致：审计未接线时
// 安全跳过——仅测试场景；审计写失败不阻断已完成的变更）。
func (h *SLOHandler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, before, after string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "apm",
		Action:        action,
		ObjectType:    "apm_slo",
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        audits.ResultSuccess,
		RiskLevel:     audits.RiskMedium,
		RequestID:     response.RequestIDFrom(r),
	})
}
