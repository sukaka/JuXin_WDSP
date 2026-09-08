// handler.go APM 查询接口（全部 GET；强制时间窗上限 31 天与分页上限 100）。
// 权限点在路由层由 middleware.RequirePermission 强制（种子见迁移 000088，ADR D12）；
// 纯查询接口不写操作审计。
package apm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 查询窗口与分页约束（合同固定：缺省最近 1 小时，窗口上限 31 天；page 默认 1，
// page_size 默认 20、上限 100，超限夹紧而非报错，与 accesslogs 等既有列表口径一致）。
const (
	defaultWindow   = time.Hour
	maxWindow       = 31 * 24 * time.Hour
	defaultPage     = 1
	defaultPageSize = 20
	maxPageSize     = 100
	// traceSearchWindowMax trace-search 窗口上限（CH 原始表扫描必须限窗，§21.3）
	traceSearchWindowMax = 24 * time.Hour
	// requestIDMaxLen / serviceNameMaxLen 过滤参数长度上限（参数化查询无注入面，
	// 上限仅防异常放大；service_name 与迁移 000089 VARCHAR(128) 同口径）
	requestIDMaxLen   = 128
	serviceNameMaxLen = 128
	// dbSystemMaxLen db_system 过滤参数长度上限（OTel db.system 为短标识符）
	dbSystemMaxLen = 64
	// instanceIDMaxLen instance_id 过滤参数长度上限（service.instance.id 为
	// 部署侧标识符；参数化查询无注入面，上限仅防异常放大）
	instanceIDMaxLen = 128
)

// traceIDPattern W3C trace_id 格式：32 位 hex（大小写均可，查询前统一转小写）。
var traceIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

// SettingsReader 系统设置读取（logging.access_log_enabled 控制端点级数据可用性；
// apm_alert.ingest_lag_seconds 为采集滞后判定阈值——P1-01 A2 availability 证据）。
type SettingsReader interface {
	GetBool(ctx context.Context, group, key string, def bool) bool
	GetInt(ctx context.Context, group, key string, def int) int
}

// Repository APM 查询存取抽象（handler 单测以 fake 注入）。
type Repository interface {
	Overview(ctx context.Context, start, end time.Time, accessLogEnabled bool) (*OverviewData, error)
	ListServices(ctx context.Context, f ServicesFilter) ([]ServiceRow, int64, error)
	ServiceDetail(ctx context.Context, id uuid.UUID, start, end time.Time, accessLogEnabled bool) (*ServiceDetailData, error)
	ListEndpoints(ctx context.Context, f EndpointsFilter) ([]EndpointRow, int64, error)
	AppCodeByID(ctx context.Context, id uuid.UUID) (string, error)
	// TraceView P1-01 A2 起携带 availability/correlation 判定证据
	// （accessLogEnabled/ingestLagThreshold 由 handler 从设置读入）
	TraceView(ctx context.Context, traceID string, start, end *time.Time, accessLogEnabled bool, ingestLagThreshold time.Duration) (*TraceViewData, error)
	// SearchTraces OTel trace 检索（阶段2 下半 CH 数据面；未配置/故障降级为空页不报错）
	SearchTraces(ctx context.Context, f TraceSearchFilter) (*TraceSearchData, error)
	// 阶段3 第一批（CH 数据面；未配置/故障一律降级为空数据 + agentless 提示，不报错）：
	ListSQLFingerprints(ctx context.Context, f SQLFilter) (*SQLData, error)
	ListExceptions(ctx context.Context, f ExceptionsFilter) (*ExceptionsData, error)
	ListDependencies(ctx context.Context, f DependenciesFilter) (*DependenciesData, error)
	// ListRuntimeMetrics 运行时指标（阶段3 第二批，CH 数据面 otel_metrics_* 表；
	// 未配置/故障一律降级为空实例 + agentless 提示，不报错）
	ListRuntimeMetrics(ctx context.Context, f RuntimeFilter) (*RuntimeData, error)
}

// Handler APM 查询处理器。
type Handler struct {
	store             Repository
	settings          SettingsReader
	agentOfflineAfter time.Duration // Agent 在线判定阈值（服务列表 observation_mode 用）
}

// NewHandler 创建 APM 处理器。agentOfflineAfter 为 Agent 心跳离线阈值
// （APMConfig.AgentOfflineMinutes；越界夹紧回退 10 分钟，与 Agent 控制面口径一致）。
func NewHandler(store Repository, settings SettingsReader, agentOfflineAfter time.Duration) *Handler {
	if agentOfflineAfter < time.Minute || agentOfflineAfter > 24*time.Hour {
		agentOfflineAfter = 10 * time.Minute
	}
	return &Handler{store: store, settings: settings, agentOfflineAfter: agentOfflineAfter}
}

// RegisterRoutes 注册 /api/v1/apm 路由组（权限点与迁移 000088 种子一致）。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/apm/overview", authz(middleware.RequirePermission("apm.overview.read")(http.HandlerFunc(h.Overview))))
	mux.Handle("GET /api/v1/apm/services", authz(middleware.RequirePermission("apm.services.read")(http.HandlerFunc(h.ListServices))))
	mux.Handle("GET /api/v1/apm/services/{id}", authz(middleware.RequirePermission("apm.services.read")(http.HandlerFunc(h.ServiceDetail))))
	mux.Handle("GET /api/v1/apm/endpoints", authz(middleware.RequirePermission("apm.services.read")(http.HandlerFunc(h.ListEndpoints))))
	mux.Handle("GET /api/v1/apm/trace-search", authz(middleware.RequirePermission("apm.traces.read")(http.HandlerFunc(h.TraceSearch))))
	mux.Handle("GET /api/v1/apm/traces/{trace_id}", authz(middleware.RequirePermission("apm.traces.read")(http.HandlerFunc(h.Trace))))
	// 阶段3 第一批（权限点：000090 apm.sql.read；000088 apm.traces.read / apm.services.read）
	mux.Handle("GET /api/v1/apm/sql", authz(middleware.RequirePermission("apm.sql.read")(http.HandlerFunc(h.ListSQL))))
	mux.Handle("GET /api/v1/apm/exceptions", authz(middleware.RequirePermission("apm.traces.read")(http.HandlerFunc(h.ListExceptions))))
	mux.Handle("GET /api/v1/apm/dependencies", authz(middleware.RequirePermission("apm.services.read")(http.HandlerFunc(h.ListDependencies))))
	// 阶段3 第二批（权限点：000091 apm.runtime.read）
	mux.Handle("GET /api/v1/apm/runtime", authz(middleware.RequirePermission("apm.runtime.read")(http.HandlerFunc(h.ListRuntime))))
}

// accessLogEnabled 读取 logging.access_log_enabled（缺失/异常按关闭降级，不阻断应用级数据）。
func (h *Handler) accessLogEnabled(ctx context.Context) bool {
	if h.settings == nil {
		return false
	}
	return h.settings.GetBool(ctx, "logging", "access_log_enabled", false)
}

// ingestLagThreshold 采集滞后判定阈值（apm_alert.ingest_lag_seconds；
// 键/默认/合法区间与 systemalerts 告警评估同口径，非法值回退默认——availability.go）。
func (h *Handler) ingestLagThreshold(ctx context.Context) time.Duration {
	if h.settings == nil {
		return defaultIngestLagSeconds * time.Second
	}
	if v := h.settings.GetInt(ctx, apmAlertSettingsGroup, apmAlertKeyIngestLagSeconds, defaultIngestLagSeconds); v >= minIngestLagSeconds && v <= maxIngestLagSeconds {
		return time.Duration(v) * time.Second
	}
	return defaultIngestLagSeconds * time.Second
}

// parseWindow 解析 start_time/end_time（RFC3339）。两者均可缺省：end 缺省为 now，
// start 缺省为 end−1h；强制 start < end 且窗口 ≤ 31 天。
func parseWindow(r *http.Request, now time.Time) (time.Time, time.Time, error) {
	return parseWindowCapped(r, now, maxWindow, "31 天")
}

// parseSearchWindow trace-search 专用窗口：缺省最近 1 小时，上限 24 小时
// （CH 原始表扫描必须限窗，口径严于通用列表的 31 天）。
func parseSearchWindow(r *http.Request, now time.Time) (time.Time, time.Time, error) {
	return parseWindowCapped(r, now, traceSearchWindowMax, "24 小时")
}

// parseWindowCapped 窗口解析公共实现（上限文案随调用方口径）。
func parseWindowCapped(r *http.Request, now time.Time, cap time.Duration, capText string) (time.Time, time.Time, error) {
	q := r.URL.Query()
	end := now.UTC()
	if v := strings.TrimSpace(q.Get("end_time")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("无效的 end_time（需 RFC3339 格式）")
		}
		end = t.UTC()
	}
	start := end.Add(-defaultWindow)
	if v := strings.TrimSpace(q.Get("start_time")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("无效的 start_time（需 RFC3339 格式）")
		}
		start = t.UTC()
	}
	if !start.Before(end) {
		return time.Time{}, time.Time{}, fmt.Errorf("start_time 必须早于 end_time")
	}
	if end.Sub(start) > cap {
		return time.Time{}, time.Time{}, fmt.Errorf("查询窗口不能超过 %s", capText)
	}
	return start, end, nil
}

// parseOptionalWindow trace 检索的可选时间窗：两者都缺省时不限时间（点查语义），
// 只给其一为 400；给定时的校验口径与 parseWindow 一致。
func parseOptionalWindow(r *http.Request) (*time.Time, *time.Time, error) {
	q := r.URL.Query()
	sv, ev := strings.TrimSpace(q.Get("start_time")), strings.TrimSpace(q.Get("end_time"))
	if sv == "" && ev == "" {
		return nil, nil, nil
	}
	if sv == "" || ev == "" {
		return nil, nil, fmt.Errorf("start_time 与 end_time 需同时提供")
	}
	start, err1 := time.Parse(time.RFC3339, sv)
	end, err2 := time.Parse(time.RFC3339, ev)
	if err1 != nil || err2 != nil {
		return nil, nil, fmt.Errorf("无效的 start_time/end_time（需 RFC3339 格式）")
	}
	start, end = start.UTC(), end.UTC()
	if !start.Before(end) {
		return nil, nil, fmt.Errorf("start_time 必须早于 end_time")
	}
	if end.Sub(start) > maxWindow {
		return nil, nil, fmt.Errorf("查询窗口不能超过 31 天")
	}
	return &start, &end, nil
}

// parsePage 解析分页参数（非法/越界夹紧到默认值或上限，不报错）。
func parsePage(r *http.Request) (page, pageSize int) {
	page, pageSize = defaultPage, defaultPageSize
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	if v := r.URL.Query().Get("page_size"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			pageSize = n
		}
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	return page, pageSize
}

// badRequest 输出 400 参数错误。
func badRequest(w http.ResponseWriter, r *http.Request, msg string) {
	response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
}

// Overview GET /api/v1/apm/overview（权限 apm.overview.read）。
func (h *Handler) Overview(w http.ResponseWriter, r *http.Request) {
	start, end, err := parseWindow(r, time.Now())
	if err != nil {
		badRequest(w, r, err.Error())
		return
	}
	data, err := h.store.Overview(r.Context(), start, end, h.accessLogEnabled(r.Context()))
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, data)
}

// ListServices GET /api/v1/apm/services（权限 apm.services.read）。
// P1-01 A2：统一分页字段（items/page/page_size/total）不变，追加 availability
// （由真实返回行判定：有流量观测才标 GATEWAY 源；last_collected_at 取各行
// last_seen_at 最大值，无流量为 null，不填 now）。
func (h *Handler) ListServices(w http.ResponseWriter, r *http.Request) {
	start, end, err := parseWindow(r, time.Now())
	if err != nil {
		badRequest(w, r, err.Error())
		return
	}
	page, pageSize := parsePage(r)
	list, total, err := h.store.ListServices(r.Context(), ServicesFilter{
		Keyword:           strings.TrimSpace(r.URL.Query().Get("keyword")),
		Page:              page,
		PageSize:          pageSize,
		Start:             start,
		End:               end,
		AgentOfflineAfter: h.agentOfflineAfter,
	})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"items": list, "page": page, "page_size": pageSize, "total": total,
		"availability": servicesAvailability(list),
	})
}

// servicesAvailability 服务列表 availability（handler 侧由真实返回行判定，
// 不新增存储查询；服务登记数据来自 PG，流量观测来自网关聚合）。
func servicesAvailability(rows []ServiceRow) *Availability {
	observed := false
	var last *time.Time
	for _, row := range rows {
		if row.Requests > 0 {
			observed = true
		}
		if row.LastSeenAt != nil && (last == nil || row.LastSeenAt.After(*last)) {
			last = row.LastSeenAt
		}
	}
	return gatewayAvailability(len(rows) > 0, observed, last)
}

// ServiceDetail GET /api/v1/apm/services/{id}（权限 apm.services.read；应用不存在 404）。
func (h *Handler) ServiceDetail(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		badRequest(w, r, "无效的 id")
		return
	}
	start, end, err := parseWindow(r, time.Now())
	if err != nil {
		badRequest(w, r, err.Error())
		return
	}
	data, err := h.store.ServiceDetail(r.Context(), id, start, end, h.accessLogEnabled(r.Context()))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, data)
}

// ListEndpoints GET /api/v1/apm/endpoints（权限 apm.services.read）。
// data 为分页对象扩展 {list, total, page, page_size, access_log_enabled}；
// access_log 关闭时端点级数据未开启，list 为空数组（能力如实降级，ADR D9）。
func (h *Handler) ListEndpoints(w http.ResponseWriter, r *http.Request) {
	start, end, err := parseWindow(r, time.Now())
	if err != nil {
		badRequest(w, r, err.Error())
		return
	}
	page, pageSize := parsePage(r)
	q := r.URL.Query()
	f := EndpointsFilter{
		Sort:     strings.TrimSpace(q.Get("sort")),
		Page:     page,
		PageSize: pageSize,
		Start:    start,
		End:      end,
	}
	if f.Sort == "" {
		f.Sort = "p95"
	}
	switch f.Sort {
	case "p95", "requests", "error_rate":
	default:
		badRequest(w, r, "无效的 sort（支持 p95/requests/error_rate）")
		return
	}
	if v := strings.TrimSpace(q.Get("application_id")); v != "" {
		appID, err := uuid.Parse(v)
		if err != nil {
			badRequest(w, r, "无效的 application_id")
			return
		}
		code, err := h.store.AppCodeByID(r.Context(), appID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				// 过滤条件指向不存在/已删除的应用：如实返回空页而非 5xx
				response.JSON(w, r, http.StatusOK, map[string]interface{}{
					"list": []EndpointRow{}, "total": 0, "page": page, "page_size": pageSize,
					"access_log_enabled": h.accessLogEnabled(r.Context()),
					"availability":       gatewayAvailability(false, false, nil),
				})
				return
			}
			response.InternalError(w, r, err)
			return
		}
		f.AppCode = &code
	}

	enabled := h.accessLogEnabled(r.Context())
	list, total := []EndpointRow{}, int64(0)
	if enabled {
		list, total, err = h.store.ListEndpoints(r.Context(), f)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"list": list, "total": total, "page": page, "page_size": pageSize,
		"access_log_enabled": enabled,
		"availability":       endpointsAvailability(list, enabled),
	})
}

// endpointsAvailability 端点列表 availability（P1-01 A2）：access_log 关闭时端点级
// 数据未开启（未发生查询，只标 ACCESS_LOG_DISABLED，不标 NO_MATCH）——既有
// access_log_enabled 字段保留。
func endpointsAvailability(rows []EndpointRow, accessLogEnabled bool) *Availability {
	if !accessLogEnabled {
		a := availabilityBase()
		a.QueryState = queryStateEmpty
		a.addReason(reasonAccessLogDisabled)
		return a
	}
	var last *time.Time
	for _, row := range rows {
		if row.LastSeenAt != nil && (last == nil || row.LastSeenAt.After(*last)) {
			last = row.LastSeenAt
		}
	}
	return gatewayAvailability(len(rows) > 0, len(rows) > 0, last)
}

// Trace GET /api/v1/apm/traces/{trace_id}（权限 apm.traces.read）。
// trace_id 严格 32 位 hex（非法 400）；可选 start_time/end_time 限窗；均无命中返回空数组。
// P1-01 A2：响应追加 availability（数据质量自述）与 correlation（trace_id 直达关联判定）。
func (h *Handler) Trace(w http.ResponseWriter, r *http.Request) {
	traceID := strings.ToLower(strings.TrimSpace(r.PathValue("trace_id")))
	if !traceIDPattern.MatchString(traceID) {
		badRequest(w, r, "无效的 trace_id（需 32 位十六进制）")
		return
	}
	start, end, err := parseOptionalWindow(r)
	if err != nil {
		badRequest(w, r, err.Error())
		return
	}
	data, err := h.store.TraceView(r.Context(), traceID, start, end,
		h.accessLogEnabled(r.Context()), h.ingestLagThreshold(r.Context()))
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, data)
}

// TraceSearch GET /api/v1/apm/trace-search（权限 apm.traces.read）。
// OTel trace 检索（CH 数据面）：start_time/end_time 缺省最近 1 小时、上限 24 小时
// （原始表扫描必须限窗）；trace_id 为 32hex 精确直达（与 request_id 同给时 trace_id
// 优先）；request_id 先经 access_logs 解析 trace_id 集合再查 CH。CH 未配置/不可用
// 时返回空页 + data_source=agentless + message 提示，不报 500。
// P1-01 A2：application_id 按应用约束检索（非法 UUID/应用不存在 → 400，不静默忽略；
// 应用无已映射 OTel 服务时如实空页 + message 说明）；request_id 检索追加 correlation
// 关联判定；全部响应追加 availability 数据质量自述。
func (h *Handler) TraceSearch(w http.ResponseWriter, r *http.Request) {
	start, end, err := parseSearchWindow(r, time.Now())
	if err != nil {
		badRequest(w, r, err.Error())
		return
	}
	page, pageSize := parsePage(r)
	q := r.URL.Query()
	f := TraceSearchFilter{Start: start, End: end, Page: page, PageSize: pageSize}

	if v := strings.TrimSpace(q.Get("trace_id")); v != "" {
		id := strings.ToLower(v)
		if !traceIDPattern.MatchString(id) {
			badRequest(w, r, "无效的 trace_id（需 32 位十六进制）")
			return
		}
		f.TraceIDs = []string{id}
	}
	if v := strings.TrimSpace(q.Get("request_id")); v != "" {
		if len(v) > requestIDMaxLen {
			badRequest(w, r, "无效的 request_id（长度不能超过 128）")
			return
		}
		f.RequestID = v
	}
	if v := strings.TrimSpace(q.Get("application_id")); v != "" {
		appID, err := uuid.Parse(v)
		if err != nil {
			badRequest(w, r, "无效的 application_id（需 UUID）")
			return
		}
		if _, err := h.store.AppCodeByID(r.Context(), appID); err != nil {
			if errors.Is(err, ErrNotFound) {
				badRequest(w, r, "无效的 application_id（应用不存在或已删除）")
				return
			}
			response.InternalError(w, r, err)
			return
		}
		f.ApplicationID = &appID
	}
	if v := strings.TrimSpace(q.Get("service")); v != "" {
		if len(v) > serviceNameMaxLen {
			badRequest(w, r, "无效的 service（长度不能超过 128）")
			return
		}
		f.Service = v
	}
	if v := strings.TrimSpace(q.Get("min_duration_ms")); v != "" {
		n, err := strconv.ParseFloat(v, 64)
		if err != nil || n < 0 {
			badRequest(w, r, "无效的 min_duration_ms（需为非负数值）")
			return
		}
		f.MinDurationMS = n
	}
	if v := strings.TrimSpace(q.Get("error")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			badRequest(w, r, "无效的 error（仅支持 true/false）")
			return
		}
		f.ErrorOnly = b
	}
	// availability/correlation 判定证据（访问日志开关与采集滞后阈值）
	f.AccessLogEnabled = h.accessLogEnabled(r.Context())
	f.IngestLagThreshold = h.ingestLagThreshold(r.Context())

	data, err := h.store.SearchTraces(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, data)
}

// ListSQL GET /api/v1/apm/sql（权限 apm.sql.read，迁移 000090）。
// SQL 指纹聚合列表（CH 数据面：002 apm_sql_minutes 分钟聚合 + otel_traces 同窗派生
// p95/命名空间/示例 trace）。start_time/end_time 缺省最近 1 小时、上限 24 小时；
// sort 白名单 calls/avg_ms/p95_ms（默认 p95_ms 倒序）。只出指纹不出原始 statement
// （设计 §11.1）。CH 未配置/不可用时返回空页 + data_source=agentless + message，不 500。
// P1-01 A2：trace_id 参数切换 trace 级精确定位（仅从该 trace 的 DB span 派生指纹；
// 非法 trace_id 400，不静默忽略）；match_mode/match_note 如实标注定位语义
// （窗口聚合 ≠ 特定请求的慢 SQL）；全部响应追加 availability。
func (h *Handler) ListSQL(w http.ResponseWriter, r *http.Request) {
	start, end, err := parseSearchWindow(r, time.Now())
	if err != nil {
		badRequest(w, r, err.Error())
		return
	}
	page, pageSize := parsePage(r)
	q := r.URL.Query()
	f := SQLFilter{Start: start, End: end, Sort: "p95_ms", Page: page, PageSize: pageSize}

	if v := strings.TrimSpace(q.Get("trace_id")); v != "" {
		id := strings.ToLower(v)
		if !traceIDPattern.MatchString(id) {
			badRequest(w, r, "无效的 trace_id（需 32 位十六进制）")
			return
		}
		f.TraceID = id
	}
	if v := strings.TrimSpace(q.Get("service")); v != "" {
		if len(v) > serviceNameMaxLen {
			badRequest(w, r, "无效的 service（长度不能超过 128）")
			return
		}
		f.Service = v
	}
	if v := strings.TrimSpace(q.Get("db_system")); v != "" {
		if len(v) > dbSystemMaxLen {
			badRequest(w, r, "无效的 db_system（长度不能超过 64）")
			return
		}
		f.DBSystem = v
	}
	if v := strings.TrimSpace(q.Get("sort")); v != "" {
		switch v {
		case "calls", "avg_ms", "p95_ms":
			f.Sort = v
		default:
			badRequest(w, r, "无效的 sort（支持 calls/avg_ms/p95_ms）")
			return
		}
	}
	f.IngestLagThreshold = h.ingestLagThreshold(r.Context())

	data, err := h.store.ListSQLFingerprints(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, data)
}

// ListExceptions GET /api/v1/apm/exceptions（权限 apm.traces.read）。
// 异常指纹聚合列表（CH 数据面 002 apm_exception_fingerprints；first/last_seen 为分钟桶
// 粒度）。start_time/end_time 缺省最近 1 小时、上限 24 小时；按事件数倒序分页。
// CH 未配置/不可用时返回空页 + data_source=agentless + message，不 500。
// P1-01 A2：trace_id 参数切换 trace 级精确定位（直读该 trace 的 exception 事件，
// 结果在 trace_exceptions；非法 trace_id 400，不静默忽略）；文本字段经凭据掩码 +
// 长度上限截断（纯文本）；match_mode/match_note 标注定位语义；追加 availability。
func (h *Handler) ListExceptions(w http.ResponseWriter, r *http.Request) {
	start, end, err := parseSearchWindow(r, time.Now())
	if err != nil {
		badRequest(w, r, err.Error())
		return
	}
	page, pageSize := parsePage(r)
	q := r.URL.Query()
	f := ExceptionsFilter{Start: start, End: end, Page: page, PageSize: pageSize}
	if v := strings.TrimSpace(q.Get("trace_id")); v != "" {
		id := strings.ToLower(v)
		if !traceIDPattern.MatchString(id) {
			badRequest(w, r, "无效的 trace_id（需 32 位十六进制）")
			return
		}
		f.TraceID = id
	}
	if v := strings.TrimSpace(q.Get("service")); v != "" {
		if len(v) > serviceNameMaxLen {
			badRequest(w, r, "无效的 service（长度不能超过 128）")
			return
		}
		f.Service = v
	}
	f.IngestLagThreshold = h.ingestLagThreshold(r.Context())

	data, err := h.store.ListExceptions(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, data)
}

// ListDependencies GET /api/v1/apm/dependencies（权限 apm.services.read）。
// 服务依赖边列表（CH 数据面 otel_traces 的 CLIENT/PRODUCER span 单视角派生，
// 无对端 SERVER span 配对——note 如实标注）。start_time/end_time 缺省最近 1 小时、
// 上限 24 小时；单页上限 500 条边，超限截断并在 note 标注。
// CH 未配置/不可用时返回空边列表 + data_source=agentless + note，不 500。
func (h *Handler) ListDependencies(w http.ResponseWriter, r *http.Request) {
	start, end, err := parseSearchWindow(r, time.Now())
	if err != nil {
		badRequest(w, r, err.Error())
		return
	}
	f := DependenciesFilter{Start: start, End: end}
	if v := strings.TrimSpace(r.URL.Query().Get("service")); v != "" {
		if len(v) > serviceNameMaxLen {
			badRequest(w, r, "无效的 service（长度不能超过 128）")
			return
		}
		f.Service = v
	}

	data, err := h.store.ListDependencies(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, data)
}

// ListRuntime GET /api/v1/apm/runtime（权限 apm.runtime.read，迁移 000091）。
// 服务实例运行时指标（CH 数据面 otel_metrics_gauge/sum/histogram 三类表；
// 直方图按 Sum/Count 折算均值）。service/instance_id 均可选：不填列窗口内全部
// 实例（上限 20，超限截断并在 note 标注）；start_time/end_time 缺省最近 1 小时、
// 上限 24 小时。每实例指标 ≤20 个（按名升序截取）、每指标 points ≤200（窗口等分
// 降采样）。指标集按语言/Agent 上报原样返回，不强行统一（设计 §10.3）。
// CH 未配置/不可用时 instances 为空 + data_source=agentless + note，不 500。
func (h *Handler) ListRuntime(w http.ResponseWriter, r *http.Request) {
	start, end, err := parseSearchWindow(r, time.Now())
	if err != nil {
		badRequest(w, r, err.Error())
		return
	}
	f := RuntimeFilter{Start: start, End: end}
	q := r.URL.Query()
	if v := strings.TrimSpace(q.Get("service")); v != "" {
		if len(v) > serviceNameMaxLen {
			badRequest(w, r, "无效的 service（长度不能超过 128）")
			return
		}
		f.Service = v
	}
	if v := strings.TrimSpace(q.Get("instance_id")); v != "" {
		if len(v) > instanceIDMaxLen {
			badRequest(w, r, "无效的 instance_id（长度不能超过 128）")
			return
		}
		f.InstanceID = v
	}

	data, err := h.store.ListRuntimeMetrics(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, data)
}
