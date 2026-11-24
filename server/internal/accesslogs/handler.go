package accesslogs

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apigeo"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/validation"
)

// exportMaxRows 导出行数上限。
const exportMaxRows = 10000

// Handler 是全量访问日志查询处理器。
type Handler struct {
	store     *Store
	audits    *audits.Service
	geoLookup apigeo.GeoLookup
}

// NewHandler 创建访问日志处理器。
func NewHandler(store *Store, au *audits.Service) *Handler {
	return &Handler{store: store, audits: au}
}

// SetGeoLookup 注入统一 GeoIP 归属地查询器。
func (h *Handler) SetGeoLookup(g apigeo.GeoLookup) {
	h.geoLookup = g
}

func (h *Handler) attachGeo(entry *AccessLog) {
	if h == nil || h.geoLookup == nil || entry == nil || entry.ClientIP == "" {
		return
	}
	entry.ClientIPGeo = h.geoLookup.LookupGeo(entry.ClientIP)
}

func (h *Handler) attachGeoSlice(list []AccessLog) {
	if h == nil || h.geoLookup == nil || len(list) == 0 {
		return
	}
	cache := make(map[string]*apigeo.GeoInfo, len(list))
	for i := range list {
		ip := list[i].ClientIP
		if ip == "" {
			continue
		}
		if g, ok := cache[ip]; ok {
			list[i].ClientIPGeo = g
			continue
		}
		g := h.geoLookup.LookupGeo(ip)
		cache[ip] = g
		list[i].ClientIPGeo = g
	}
}

// filterFromQuery 解析查询参数（列表、趋势与导出共用）。
func filterFromQuery(r *http.Request) (ListFilter, error) {
	f := ListFilter{
		Domain:    strings.TrimSpace(r.URL.Query().Get("domain")),
		ClientIP:  strings.TrimSpace(r.URL.Query().Get("client_ip")),
		Method:    strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("method"))),
		URI:       strings.TrimSpace(r.URL.Query().Get("uri")),
		WAFAction: strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("waf_action"))),
		RequestID: strings.TrimSpace(r.URL.Query().Get("request_id")),
		Page:      queryInt(r, "page", 1),
		PageSize:  queryInt(r, "page_size", 20),
	}
	var err error
	if f.StartTime, err = parseAuditTime(r.URL.Query().Get("start_time"), "start_time"); err != nil {
		return f, err
	}
	if f.EndTime, err = parseAuditTime(r.URL.Query().Get("end_time"), "end_time"); err != nil {
		return f, err
	}
	if s := r.URL.Query().Get("status"); s != "" {
		n, parseErr := strconv.Atoi(s)
		if parseErr != nil {
			return f, fmt.Errorf("status 必须是整数")
		}
		f.Status = &n
	}
	if err := validateAuditFilter(&f, r.URL.Query()); err != nil {
		return f, err
	}
	return f, nil
}

// List 访问日志列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f, err := filterFromQuery(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.attachGeoSlice(list)
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Trend 按真实访问日志聚合趋势，默认最近24小时，最长31天。
func (h *Handler) Trend(w http.ResponseWriter, r *http.Request) {
	f, err := filterFromQuery(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	now := time.Now().UTC()
	if f.EndTime == nil {
		f.EndTime = &now
	}
	if f.StartTime == nil {
		start := f.EndTime.Add(-24 * time.Hour)
		f.StartTime = &start
	}
	if f.EndTime.Sub(*f.StartTime) > 31*24*time.Hour {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "趋势时间范围不能超过31天")
		return
	}
	bucketSeconds, err := trendBucketSeconds(*f.StartTime, *f.EndTime, r.URL.Query().Get("bucket_seconds"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	items, err := h.store.Trend(r.Context(), f, bucketSeconds)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"items": items, "bucket_seconds": bucketSeconds,
		"start_time": f.StartTime.UTC(), "end_time": f.EndTime.UTC(),
	})
}

// Flow 返回真实请求集合的来源、应用、API与敏感字段流向；字段原值不参与聚合。
func (h *Handler) Flow(w http.ResponseWriter, r *http.Request) {
	f, err := filterFromQuery(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	now := time.Now().UTC()
	if f.EndTime == nil {
		f.EndTime = &now
	}
	if f.StartTime == nil {
		start := f.EndTime.Add(-24 * time.Hour)
		f.StartTime = &start
	}
	if f.EndTime.Sub(*f.StartTime) > 31*24*time.Hour {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "流向图时间范围不能超过31天")
		return
	}
	nodeLimit := 8
	if raw := strings.TrimSpace(r.URL.Query().Get("node_limit")); raw != "" {
		nodeLimit, err = strconv.Atoi(raw)
		if err != nil || nodeLimit < 1 || nodeLimit > 20 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "node_limit 必须在1到20之间")
			return
		}
	}
	result, err := h.store.Flow(r.Context(), f, nodeLimit)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, result)
}

// Get 访问日志详情（含请求/响应头体留痕）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的日志ID")
		return
	}
	entry, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "访问日志不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.attachGeo(entry)
	response.JSON(w, r, http.StatusOK, entry)
}

// Export 导出访问日志（CSV，上限 exportMaxRows 行；支持筛选导出与勾选 ids 导出）。
func (h *Handler) Export(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	ids, err := validation.ParseExportUUIDs(r.URL.Query(), "ids")
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	f, err := filterFromQuery(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	f.IDs = ids
	f.Page = 1
	f.PageSize = exportMaxRows
	list, _, err := h.store.ListForExport(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "access_logs", "export", "access_log", "", fmt.Sprintf("count=%d", len(list)), audits.ResultSuccess, audits.RiskMedium)

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="access-logs.csv"`)
	_, _ = w.Write([]byte(renderExportCSV(list)))
}

const exportCSVUTF8BOM = "\xef\xbb\xbf"

const exportCSVHeader = "发生时间,客户端 IP,域名,请求方法,请求路径,响应状态码,WAF 动作,请求大小（字节）,响应大小（字节）,耗时（ms）,网关节点,请求 ID\n"

// renderExportCSV 渲染访问日志 CSV（含 UTF-8 BOM、中文表头与枚举中文化、防公式注入）。
func renderExportCSV(list []AccessLog) string {
	var b strings.Builder
	b.WriteString(exportCSVUTF8BOM)
	b.WriteString(exportCSVHeader)
	for _, e := range list {
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%d,%s,%d,%d,%d,%s,%s\n",
			e.OccurredAt.UTC().Format(time.RFC3339),
			csvEscape(e.ClientIP), csvEscape(e.Domain), csvEscape(e.RequestMethod),
			csvEscape(e.RequestURI), e.ResponseStatus, csvEscape(exportWAFActionLabel(e.WAFAction)),
			e.BytesIn, e.BytesOut, e.DurationMS,
			csvEscape(e.GatewayNodeID), csvEscape(e.RequestID))
	}
	return b.String()
}

func exportWAFActionLabel(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "", "ALLOW":
		return "放行"
	case "BLOCK":
		return "阻断"
	case "OBSERVE":
		return "观察"
	default:
		return v
	}
}

// csvEscape CSV 字段转义：=、+、-、@、\t、\r 开头前加 ' 防公式注入（domain/URI 等攻击者可控）；
// 含逗号/引号/换行的字段加双引号并双写内部引号。
func csvEscape(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		s = "'" + s
	}
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, module, action, objType, objID, objName, result, risk string) {
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       module,
		Action:       action,
		ObjectType:   objType,
		ObjectID:     objID,
		ObjectName:   objName,
		Result:       result,
		RiskLevel:    risk,
		RequestID:    response.RequestIDFrom(r),
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
