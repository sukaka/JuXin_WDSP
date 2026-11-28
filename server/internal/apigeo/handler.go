// handler.go 数据出境看板 HTTP 处理器：GET /api/v1/api-security/cross-border
// 单端点返回聚合看板 + 明细分页。只读接口，权限点 api_data.read（种子迁移 000041）。
package apigeo

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/jiuzhang-waf/server/internal/apidata"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 明细分页页大小上限（防过宽拉取）。
const eventPageSizeMax = 100

// Handler 数据出境看板处理器。
type Handler struct {
	store    Repository
	lookup   CountryLookup  // nil = GeoIP 数据源未加载（看板如实标注 geo_enabled=false）
	settings SettingsReader // home_regions 来源（nil 时用默认值）
}

// NewHandler 创建处理器。
func NewHandler(store Repository, lookup CountryLookup, settings SettingsReader) *Handler {
	return &Handler{store: store, lookup: lookup, settings: settings}
}

// RegisterRoutes 注册路由（统一 /api/v1/api-security 前缀；权限点 api_data.read）。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/cross-border",
		authz(middleware.RequirePermission(apidata.PermDataRead)(http.HandlerFunc(h.CrossBorder))))
}

// crossBorderResponse 看板 + 明细组合响应。
type crossBorderResponse struct {
	GeoEnabled  bool              `json:"geo_enabled"`  // GeoIP 数据源是否可用（false 时看板可能为历史数据）
	HomeRegions []string          `json:"home_regions"` // 当前本土地区判定基准
	Dashboard   *DashboardData    `json:"dashboard"`
	Events      response.PageData `json:"events"` // 明细分页（与看板同窗口）
}

// CrossBorder GET /api/v1/api-security/cross-border
// 查询参数：days（窗口，默认 7 上限 30）作用于看板与明细；
// country/direction/risk_level/endpoint_key 仅过滤明细；page/page_size 明细分页。
func (h *Handler) CrossBorder(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	country := strings.ToUpper(strings.TrimSpace(q.Get("country")))
	if country != "" && (len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z') {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 country 取值（两位 ISO 3166-1 alpha-2 国家码）")
		return
	}
	direction := strings.ToUpper(strings.TrimSpace(q.Get("direction")))
	if direction != "" && !validDirection(direction) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 direction 取值（OUT/IN）")
		return
	}
	riskLevel := strings.ToUpper(strings.TrimSpace(q.Get("risk_level")))
	if riskLevel != "" && !validRiskLevel(riskLevel) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 risk_level 取值（LOW/MEDIUM/HIGH）")
		return
	}
	endpointKey := strings.TrimSpace(q.Get("endpoint_key"))
	if len(endpointKey) > 560 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "endpoint_key 长度不能超过 560")
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	if pageSize > eventPageSizeMax {
		pageSize = eventPageSizeMax
	}
	days := clampDays(queryInt(r, "days", DashboardDefaultDays))

	dashboard, err := h.store.Dashboard(r.Context(), days)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	events, total, err := h.store.ListEvents(r.Context(), EventFilter{
		Days:        days,
		Country:     country,
		Direction:   direction,
		RiskLevel:   riskLevel,
		EndpointKey: endpointKey,
		Page:        page,
		PageSize:    pageSize,
	})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}

	rawHome := DefaultHomeRegions
	if h.settings != nil {
		rawHome = h.settings.GetString(r.Context(), SettingsGroup, SettingsKeyHomeRegions, DefaultHomeRegions)
	}
	response.JSON(w, r, http.StatusOK, crossBorderResponse{
		GeoEnabled:  IsLookupEnabled(h.lookup),
		HomeRegions: ParseHomeRegions(rawHome),
		Dashboard:   dashboard,
		Events: response.PageData{
			Items:    events,
			Page:     page,
			PageSize: pageSize,
			Total:    total,
		},
	})
}

// queryInt 查询参数整型（正数，非法回退默认值）。
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
