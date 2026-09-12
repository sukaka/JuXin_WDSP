// handler.go 站点发现管理接口（列表 + 确认/忽略/恢复处置）。
package sitediscovery

import (
	"encoding/json"
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

// Handler 站点发现处理器。
type Handler struct {
	store  Repository
	audits *audits.Service
}

// NewHandler 创建处理器（构造注入审计服务，语义同 apiassets/customrules）。
func NewHandler(store Repository, audit *audits.Service) *Handler {
	return &Handler{store: store, audits: audit}
}

// RegisterRoutes 注册站点发现接口（权限点 site_discovery.read / site_discovery.manage，
// 种子见迁移 000077）。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/site-discoveries", authz(middleware.RequirePermission("site_discovery.read")(http.HandlerFunc(h.List))))
	mux.Handle("POST /api/v1/site-discoveries/{id}/confirm", authz(middleware.RequirePermission("site_discovery.manage")(http.HandlerFunc(h.Confirm))))
	mux.Handle("POST /api/v1/site-discoveries/{id}/ignore", authz(middleware.RequirePermission("site_discovery.manage")(http.HandlerFunc(h.Ignore))))
	mux.Handle("POST /api/v1/site-discoveries/{id}/restore", authz(middleware.RequirePermission("site_discovery.manage")(http.HandlerFunc(h.Restore))))
}

// List GET /api/v1/site-discoveries?status=&protocol=&source_mode=&keyword=&page=&page_size=
// 过滤值非法（不在词表内）返回 400；分页参数非法回落默认（与邻居模块同口径）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := ListFilter{
		Status:     strings.ToUpper(strings.TrimSpace(q.Get("status"))),
		Protocol:   strings.ToUpper(strings.TrimSpace(q.Get("protocol"))),
		SourceMode: strings.ToUpper(strings.TrimSpace(q.Get("source_mode"))),
		Keyword:    strings.TrimSpace(q.Get("keyword")),
		Page:       queryInt(r, "page", 1),
		PageSize:   queryInt(r, "page_size", 20),
	}
	if f.Status != "" && !validStatus(f.Status) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"无效的 status 取值（NEW/CONFIRMED/IGNORED）")
		return
	}
	if f.Protocol != "" && f.Protocol != ProtocolHTTP && f.Protocol != ProtocolHTTPS {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"无效的 protocol 取值（HTTP/HTTPS）")
		return
	}
	switch f.SourceMode {
	case "", SourceModeMirror, SourceModeRouted, SourceModeTransparent:
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"无效的 source_mode 取值（MIRROR/ROUTED/TRANSPARENT）")
		return
	}
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Confirm POST /api/v1/site-discoveries/{id}/confirm（NEW→CONFIRMED）。
func (h *Handler) Confirm(w http.ResponseWriter, r *http.Request) {
	h.transition(w, r, "confirm", func(id uuid.UUID, operator string) (*Discovery, error) {
		return h.store.Confirm(r.Context(), id, operator)
	}, audits.RiskLow)
}

// Ignore POST /api/v1/site-discoveries/{id}/ignore（NEW/CONFIRMED→IGNORED）。
func (h *Handler) Ignore(w http.ResponseWriter, r *http.Request) {
	h.transition(w, r, "ignore", func(id uuid.UUID, operator string) (*Discovery, error) {
		return h.store.Ignore(r.Context(), id, operator)
	}, audits.RiskMedium)
}

// Restore POST /api/v1/site-discoveries/{id}/restore（CONFIRMED/IGNORED→NEW）。
func (h *Handler) Restore(w http.ResponseWriter, r *http.Request) {
	h.transition(w, r, "restore", func(id uuid.UUID, operator string) (*Discovery, error) {
		return h.store.Restore(r.Context(), id, operator)
	}, audits.RiskMedium)
}

// transition 处置流转公共路径：参数解析 → 流转 → 审计 → 返回更新后条目。
func (h *Handler) transition(w http.ResponseWriter, r *http.Request, action string,
	fn func(id uuid.UUID, operator string) (*Discovery, error), risk string) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的发现ID")
		return
	}
	before, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "发现条目不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	d, err := fn(id, actorOf(p))
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "发现条目不存在")
		return
	}
	if errors.Is(err, ErrInvalidTransition) {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
			"当前状态不允许该操作（status="+before.Status+"）")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, action, d, before.Status, risk)
	response.JSON(w, r, http.StatusOK, d)
}

// recordAudit 写操作审计（语义同 apiassets：操作者/动作/对象/前后摘要/风险等级）。
// 审计服务未注入或无操作者上下文时跳过，不影响主流程。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action string, d *Discovery, fromStatus, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "site_discovery",
		Action:        action,
		ObjectType:    "site_asset_discovery",
		ObjectID:      d.ID.String(),
		ObjectName:    truncateName(discoveryName(d)),
		BeforeSummary: summaryJSON(map[string]any{"status": fromStatus}),
		AfterSummary:  summaryJSON(map[string]any{"status": d.Status}),
		Result:        audits.ResultSuccess,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

// discoveryName 审计对象名：domain:port（无域名时 ip:port）。
func discoveryName(d *Discovery) string {
	host := d.Domain
	if host == "" {
		host = d.IP
	}
	return host + ":" + strconv.Itoa(d.Port)
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
