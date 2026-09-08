package appconfigs

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 应用头合规配置与路径转发管理。
type Handler struct {
	store  Repository
	audits *audits.Service
}

// NewHandler 创建处理器（构造注入审计服务，语义同 customrules）。
func NewHandler(store Repository, audit *audits.Service) *Handler {
	return &Handler{store: store, audits: audit}
}

// RegisterRoutes 注册接口组（/api/v1/applications/{id} 子资源，
// 读用 applications.read，写用 applications.update）。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/applications/{id}/header-config", authz(middleware.RequirePermission("applications.read")(http.HandlerFunc(h.GetHeaderConfig))))
	mux.Handle("PUT /api/v1/applications/{id}/header-config", authz(middleware.RequirePermission("applications.update")(http.HandlerFunc(h.PutHeaderConfig))))
	mux.Handle("GET /api/v1/applications/{id}/path-routes", authz(middleware.RequirePermission("applications.read")(http.HandlerFunc(h.ListPathRoutes))))
	mux.Handle("POST /api/v1/applications/{id}/path-routes", authz(middleware.RequirePermission("applications.update")(http.HandlerFunc(h.CreatePathRoute))))
	mux.Handle("PATCH /api/v1/applications/{id}/path-routes/{rid}", authz(middleware.RequirePermission("applications.update")(http.HandlerFunc(h.UpdatePathRoute))))
	mux.Handle("DELETE /api/v1/applications/{id}/path-routes/{rid}", authz(middleware.RequirePermission("applications.update")(http.HandlerFunc(h.DeletePathRoute))))
}

// GetHeaderConfig GET /api/v1/applications/{id}/header-config
// 返回存储配置；无配置时返回默认对象 + configured:false + version:0。
func (h *Handler) GetHeaderConfig(w http.ResponseWriter, r *http.Request) {
	appID, ok := parseAppID(w, r)
	if !ok {
		return
	}
	rec, err := h.store.GetHeaderConfigRecord(r.Context(), appID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if rec == nil {
		response.JSON(w, r, http.StatusOK, map[string]any{
			"config":     DefaultHeaderConfig(),
			"configured": false,
			"version":    0,
		})
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"config":     rec.Config,
		"configured": true,
		"version":    rec.Version,
		"updated_at": rec.UpdatedAt,
	})
}

// headerConfigRequest PUT 请求体：完整配置 + version（0 表示首次创建）。
type headerConfigRequest struct {
	gatewayconfig.AppHeaderConfig
	Version int `json:"version"`
}

// PutHeaderConfig PUT /api/v1/applications/{id}/header-config
// 全量 upsert + version 乐观锁；校验失败 400，版本冲突 409，应用不存在 404。
func (h *Handler) PutHeaderConfig(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	appID, ok := parseAppID(w, r)
	if !ok {
		return
	}
	var req headerConfigRequest
	if err := response.DecodeJSON(w, r, &req, 65536); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	var updatedBy uuid.UUID
	if p != nil {
		updatedBy = p.UserID
	}
	newVersion, err := h.store.UpsertHeaderConfig(r.Context(), appID, &req.AppHeaderConfig, updatedBy, req.Version)
	if errors.Is(err, ErrInvalid) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if errors.Is(err, ErrAppNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
		return
	}
	if errors.Is(err, ErrVersionConflict) {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "配置已被其他人修改，请刷新后重试")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", appID.String(), "header-config", "",
		summaryJSON(map[string]any{"config": req.AppHeaderConfig, "version": newVersion}), audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"config":     req.AppHeaderConfig,
		"configured": true,
		"version":    newVersion,
		"message":    "头合规配置已保存",
	})
}

// ListPathRoutes GET /api/v1/applications/{id}/path-routes（分页）
func (h *Handler) ListPathRoutes(w http.ResponseWriter, r *http.Request) {
	appID, ok := parseAppID(w, r)
	if !ok {
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListPathRoutes(r.Context(), appID, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// pathRouteRequest POST/PATCH 请求体。Priority 为 nil 时取默认值 100（同迁移默认值）。
type pathRouteRequest struct {
	PathPrefix     string `json:"path_prefix"`
	UpstreamScheme string `json:"upstream_scheme"`
	UpstreamHost   string `json:"upstream_host"`
	UpstreamPort   int    `json:"upstream_port"`
	StripPrefix    bool   `json:"strip_prefix"`
	Priority       *int   `json:"priority"`
	Status         string `json:"status"`
	Description    string `json:"description"`
	Version        int    `json:"version"`
}

// toRoute 转换请求体为 PathRoute（应用缺省值：scheme=http、status=ENABLED、priority=100）。
func (req *pathRouteRequest) toRoute(appID, routeID uuid.UUID) *PathRoute {
	scheme := strings.ToLower(strings.TrimSpace(req.UpstreamScheme))
	if scheme == "" {
		scheme = "http"
	}
	status := strings.ToUpper(strings.TrimSpace(req.Status))
	if status == "" {
		status = "ENABLED"
	}
	priority := 100
	if req.Priority != nil {
		priority = *req.Priority
	}
	return &PathRoute{
		ID:             routeID,
		ApplicationID:  appID,
		PathPrefix:     strings.TrimSpace(req.PathPrefix),
		UpstreamScheme: scheme,
		UpstreamHost:   strings.TrimSpace(req.UpstreamHost),
		UpstreamPort:   req.UpstreamPort,
		StripPrefix:    req.StripPrefix,
		Priority:       priority,
		Status:         status,
		Description:    strings.TrimSpace(req.Description),
		Version:        req.Version,
	}
}

// CreatePathRoute POST /api/v1/applications/{id}/path-routes
func (h *Handler) CreatePathRoute(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	appID, ok := parseAppID(w, r)
	if !ok {
		return
	}
	var req pathRouteRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	route := req.toRoute(appID, uuid.Nil)
	if p != nil {
		uid := p.UserID
		route.CreatedBy = &uid
	}
	if err := h.store.CreatePathRoute(r.Context(), route); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", route.ID.String(), route.PathPrefix, "",
		summaryJSON(map[string]any{"route": route}), audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"route": route, "message": "路径转发已创建"})
}

// UpdatePathRoute PATCH /api/v1/applications/{id}/path-routes/{rid}
// 全量替换 + version 乐观锁。
func (h *Handler) UpdatePathRoute(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	appID, routeID, ok := parseRouteIDs(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetPathRoute(r.Context(), appID, routeID)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "路径转发不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	var req pathRouteRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	route := req.toRoute(appID, routeID)
	if err := h.store.UpdatePathRoute(r.Context(), route); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", routeID.String(), route.PathPrefix,
		summaryJSON(map[string]any{"route": before}),
		summaryJSON(map[string]any{"route": route}), audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"route": route, "message": "路径转发已更新"})
}

// DeletePathRoute DELETE /api/v1/applications/{id}/path-routes/{rid}
func (h *Handler) DeletePathRoute(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	appID, routeID, ok := parseRouteIDs(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetPathRoute(r.Context(), appID, routeID)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "路径转发不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.DeletePathRoute(r.Context(), appID, routeID); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", routeID.String(), before.PathPrefix,
		summaryJSON(map[string]any{"route": before}), "", audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "路径转发已删除"})
}

// writeStoreError 统一映射仓储错误：校验 400、应用不存在 404、
// 记录不存在 404、版本/唯一冲突 409，其余 500。
func (h *Handler) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrInvalid):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
	case errors.Is(err, ErrAppNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
	case errors.Is(err, ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "路径转发不存在")
	case errors.Is(err, ErrVersionConflict):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "配置已被其他人修改，请刷新后重试")
	case errors.Is(err, ErrRouteConflict):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "相同路径前缀与源站的转发规则已存在")
	default:
		response.InternalError(w, r, err)
	}
}

// recordAudit 写操作审计（语义同 customrules：操作者/动作/对象/前后摘要/风险等级）。
// 审计服务未注入或无操作者上下文时跳过，不影响主流程。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, before, after, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "app_configs",
		Action:        action,
		ObjectType:    "app_config",
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        audits.ResultSuccess,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

func parseAppID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return uuid.Nil, false
	}
	return id, true
}

func parseRouteIDs(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	appID, ok := parseAppID(w, r)
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}
	routeID, err := uuid.Parse(r.PathValue("rid"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的路径转发ID")
		return uuid.Nil, uuid.Nil, false
	}
	return appID, routeID, true
}

// summaryJSON 生成审计摘要（合法 JSON 对象，交给审计层脱敏）。
func summaryJSON(v map[string]any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
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
