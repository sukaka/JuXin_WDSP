// handler.go 统计分析 HTTP 接口（只读）。
package analytics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 统计分析处理器。
type Handler struct {
	store *Store
}

// NewHandler 创建统计分析处理器。
func NewHandler(aggStore *aggregations.Store, db *pgxpool.Pool) *Handler {
	return &Handler{store: NewStore(db, aggStore)}
}

// parsedQuery 解析后的公共查询参数。
type parsedQuery struct {
	r       Range
	appID   *uuid.UUID
	appCode string
}

// parseQuery 解析并校验 start_time/end_time/application_id。
func (h *Handler) parseQuery(w http.ResponseWriter, r *http.Request) (*parsedQuery, bool) {
	rng, err := ParseRange(r.URL.Query(), time.Now())
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return nil, false
	}
	pq := &parsedQuery{r: rng}
	if v := r.URL.Query().Get("application_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
			return nil, false
		}
		code, err := h.store.ResolveAppCode(r.Context(), id)
		if err != nil {
			if err == ErrApplicationNotFound {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			} else {
				response.InternalError(w, r, err)
			}
			return nil, false
		}
		pq.appID = &id
		pq.appCode = code
	}
	return pq, true
}

func queryLimit(r *http.Request, def int) int {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// RequestTrend GET /api/v1/analytics/request-trend
// 响应除趋势序列外附带请求方法分布、Content-Type 主类型分布、客户端 IP 来源分布与
// 可信代理来源分布（access_logs 实时聚合）。
func (h *Handler) RequestTrend(w http.ResponseWriter, r *http.Request) {
	pq, ok := h.parseQuery(w, r)
	if !ok {
		return
	}
	data, err := h.store.RequestTrend(r.Context(), pq.r, pq.appCode)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if data.MethodDistribution, err = h.store.MethodDistribution(r.Context(), pq.r, pq.appID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	if data.ContentTypeDistribution, err = h.store.ContentTypeDistribution(r.Context(), pq.r, pq.appID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	if data.ClientIPSourceDistribution, err = h.store.ClientIPSourceDistribution(r.Context(), pq.r, pq.appID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	if data.TrustedProxyDistribution, err = h.store.TrustedProxyDistribution(r.Context(), pq.r, pq.appID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, data)
}

// SecurityEventTrend GET /api/v1/analytics/security-event-trend
func (h *Handler) SecurityEventTrend(w http.ResponseWriter, r *http.Request) {
	pq, ok := h.parseQuery(w, r)
	if !ok {
		return
	}
	data, err := h.store.SecurityEventTrend(r.Context(), pq.r, pq.appCode)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, data)
}

// RiskLevels GET /api/v1/analytics/risk-levels
func (h *Handler) RiskLevels(w http.ResponseWriter, r *http.Request) {
	pq, ok := h.parseQuery(w, r)
	if !ok {
		return
	}
	data, err := h.store.RiskLevels(r.Context(), pq.r, pq.appCode)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": data})
}

// AttackTypes GET /api/v1/analytics/attack-types
func (h *Handler) AttackTypes(w http.ResponseWriter, r *http.Request) {
	pq, ok := h.parseQuery(w, r)
	if !ok {
		return
	}
	data, err := h.store.AttackTypes(r.Context(), pq.r, pq.appCode)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": data})
}

// TopSourceIPs GET /api/v1/analytics/top-source-ips
func (h *Handler) TopSourceIPs(w http.ResponseWriter, r *http.Request) {
	pq, ok := h.parseQuery(w, r)
	if !ok {
		return
	}
	data, err := h.store.TopSourceIPs(r.Context(), pq.r, pq.appID, queryLimit(r, 10))
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": data})
}

// TopApplications GET /api/v1/analytics/top-applications
func (h *Handler) TopApplications(w http.ResponseWriter, r *http.Request) {
	pq, ok := h.parseQuery(w, r)
	if !ok {
		return
	}
	data, err := h.store.TopApplications(r.Context(), pq.r, queryLimit(r, 10))
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": data})
}

// TopRules GET /api/v1/analytics/top-rules
func (h *Handler) TopRules(w http.ResponseWriter, r *http.Request) {
	pq, ok := h.parseQuery(w, r)
	if !ok {
		return
	}
	data, err := h.store.TopRules(r.Context(), pq.r, pq.appID, queryLimit(r, 10))
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": data})
}

// TopURIs GET /api/v1/analytics/top-uris
func (h *Handler) TopURIs(w http.ResponseWriter, r *http.Request) {
	pq, ok := h.parseQuery(w, r)
	if !ok {
		return
	}
	data, err := h.store.TopURIs(r.Context(), pq.r, pq.appID, queryLimit(r, 10))
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": data})
}

// CCOverview GET /api/v1/analytics/cc-overview
func (h *Handler) CCOverview(w http.ResponseWriter, r *http.Request) {
	pq, ok := h.parseQuery(w, r)
	if !ok {
		return
	}
	data, err := h.store.CCOverview(r.Context(), pq.r, pq.appID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, data)
}

// AccessControlOverview GET /api/v1/analytics/access-control-overview
func (h *Handler) AccessControlOverview(w http.ResponseWriter, r *http.Request) {
	pq, ok := h.parseQuery(w, r)
	if !ok {
		return
	}
	data, err := h.store.AccessControlOverview(r.Context(), pq.r, pq.appID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, data)
}

// DispositionOverview GET /api/v1/analytics/disposition-overview
func (h *Handler) DispositionOverview(w http.ResponseWriter, r *http.Request) {
	pq, ok := h.parseQuery(w, r)
	if !ok {
		return
	}
	data, err := h.store.DispositionOverview(r.Context(), pq.r, pq.appID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, data)
}
