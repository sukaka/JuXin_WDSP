package accesslogs

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// exportMaxRows 导出行数上限。
const exportMaxRows = 10000

// Handler 是全量访问日志查询处理器。
type Handler struct {
	store  *Store
	audits *audits.Service
}

// NewHandler 创建访问日志处理器。
func NewHandler(store *Store, au *audits.Service) *Handler {
	return &Handler{store: store, audits: au}
}

// filterFromQuery 解析查询参数（列表与导出共用）。
func filterFromQuery(r *http.Request) ListFilter {
	f := ListFilter{
		Domain:    r.URL.Query().Get("domain"),
		ClientIP:  r.URL.Query().Get("client_ip"),
		Method:    r.URL.Query().Get("method"),
		URI:       r.URL.Query().Get("uri"),
		WAFAction: r.URL.Query().Get("waf_action"),
		RequestID: r.URL.Query().Get("request_id"),
		Page:      queryInt(r, "page", 1),
		PageSize:  queryInt(r, "page_size", 20),
	}
	if st := r.URL.Query().Get("start_time"); st != "" {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			f.StartTime = &t
		}
	}
	if et := r.URL.Query().Get("end_time"); et != "" {
		if t, err := time.Parse(time.RFC3339, et); err == nil {
			f.EndTime = &t
		}
	}
	if s := r.URL.Query().Get("status"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			f.Status = &n
		}
	}
	return f
}

// List 访问日志列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f := filterFromQuery(r)
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Get 访问日志详情（含请求/响应头体留痕）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的日志ID")
		return
	}
	entry, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "访问日志不存在")
		return
	}
	response.JSON(w, r, http.StatusOK, entry)
}

// Export 导出访问日志（CSV，上限 exportMaxRows 行）。
func (h *Handler) Export(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	f := filterFromQuery(r)
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
	var b strings.Builder
	b.WriteString("occurred_at,client_ip,domain,method,uri,status,waf_action,bytes_in,bytes_out,duration_ms,gateway_node_id,request_id\n")
	for _, e := range list {
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%d,%s,%d,%d,%d,%s,%s\n",
			e.OccurredAt.UTC().Format(time.RFC3339), e.ClientIP, csvEscape(e.Domain), e.RequestMethod,
			csvEscape(e.RequestURI), e.ResponseStatus, e.WAFAction, e.BytesIn, e.BytesOut, e.DurationMS,
			e.GatewayNodeID, e.RequestID)
	}
	_, _ = w.Write([]byte(b.String()))
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, module, action, objType, objID, objName, result, risk string) {
	_ = h.audits.Record(r.Context(), audits.RecordInput{
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
