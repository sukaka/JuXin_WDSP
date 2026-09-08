// handler.go LLM API 观测 HTTP 处理器：
//
//	GET /api/v1/api-security/llm/observations  明细分页（过滤 model/endpoint_key/时间窗/findings_only）
//	GET /api/v1/api-security/llm/stats         统计（模型分布/token 用量趋势/涉敏命中计数）
//
// 只读接口，权限点 api_runtime.read（与 apisecurity 运行时只读接口同一权限域）。
package apillm

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 明细分页页大小上限（防过宽拉取）。
const observationPageSizeMax = 100

// PermRuntimeRead 权限点（apisecurity 运行时只读接口同一字面量；常量未导出，此处镜像）。
const PermRuntimeRead = "api_runtime.read"

// Handler LLM 观测处理器。
type Handler struct {
	store Repository
}

// NewHandler 创建处理器。
func NewHandler(store Repository) *Handler {
	return &Handler{store: store}
}

// RegisterRoutes 注册路由（统一 /api/v1/api-security 前缀；权限点 api_runtime.read）。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/llm/observations",
		authz(middleware.RequirePermission(PermRuntimeRead)(http.HandlerFunc(h.ListObservations))))
	mux.Handle("GET /api/v1/api-security/llm/stats",
		authz(middleware.RequirePermission(PermRuntimeRead)(http.HandlerFunc(h.Stats))))
}

// ListObservations GET /api/v1/api-security/llm/observations
// 查询参数：model/endpoint_key 精确过滤，findings_only=true 仅命中观测；
// days（窗口，默认 7 上限 30，按 occurred_at 口径）；page/page_size 分页。
func (h *Handler) ListObservations(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseObservationFilter(w, r)
	if !ok {
		return
	}
	items, total, err := h.store.ListObservations(r.Context(), filter)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, response.PageData{
		Items:    items,
		Page:     filter.Page,
		PageSize: filter.PageSize,
		Total:    total,
	})
}

// Stats GET /api/v1/api-security/llm/stats
// 查询参数：days（窗口，默认 7 上限 30）。
func (h *Handler) Stats(w http.ResponseWriter, r *http.Request) {
	days := clampDays(queryInt(r, "days", ListDefaultDays))
	stats, err := h.store.Stats(r.Context(), days)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, stats)
}

// parseObservationFilter 解析并校验列表查询参数（超长键 400，与白名单纪律一致）。
func parseObservationFilter(w http.ResponseWriter, r *http.Request) (ObservationFilter, bool) {
	q := r.URL.Query()
	model := strings.TrimSpace(q.Get("model"))
	if len(model) > 128 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "model 长度不能超过 128")
		return ObservationFilter{}, false
	}
	endpointKey := strings.TrimSpace(q.Get("endpoint_key"))
	if len(endpointKey) > 560 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "endpoint_key 长度不能超过 560")
		return ObservationFilter{}, false
	}
	findingsOnly := false
	if v := strings.TrimSpace(q.Get("findings_only")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 findings_only 取值（true/false）")
			return ObservationFilter{}, false
		}
		findingsOnly = b
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	if pageSize > observationPageSizeMax {
		pageSize = observationPageSizeMax
	}
	return ObservationFilter{
		Days:         clampDays(queryInt(r, "days", ListDefaultDays)),
		Model:        model,
		EndpointKey:  endpointKey,
		FindingsOnly: findingsOnly,
		Page:         page,
		PageSize:     pageSize,
	}, true
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
