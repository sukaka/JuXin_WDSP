package accesscontrolevents

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/validation"
)

// Handler 是访问控制事件处理器。
type Handler struct {
	store  *Store
	audits *audits.Service
}

// NewHandler 创建访问控制事件处理器。
func NewHandler(store *Store, au *audits.Service) *Handler {
	return &Handler{store: store, audits: au}
}

// parseFilter 解析查询筛选（List/Export 共用）。
func parseFilter(r *http.Request) (ListFilter, error) {
	f := ListFilter{
		ClientIP:      r.URL.Query().Get("client_ip"),
		EventType:     r.URL.Query().Get("event_type"),
		Action:        r.URL.Query().Get("action"),
		PolicyID:      r.URL.Query().Get("policy_id"),
		RequestID:     r.URL.Query().Get("request_id"),
		GatewayNodeID: r.URL.Query().Get("gateway_node_id"),
		Page:          queryInt(r, "page", 1),
		PageSize:      queryInt(r, "page_size", 20),
	}
	if st := r.URL.Query().Get("start_time"); st != "" {
		t, err := time.Parse(time.RFC3339, st)
		if err != nil {
			return f, fmt.Errorf("start_time 必须为 RFC3339 时间格式")
		}
		f.StartTime = &t
	}
	if et := r.URL.Query().Get("end_time"); et != "" {
		t, err := time.Parse(time.RFC3339, et)
		if err != nil {
			return f, fmt.Errorf("end_time 必须为 RFC3339 时间格式")
		}
		f.EndTime = &t
	}
	if f.StartTime != nil && f.EndTime != nil && f.EndTime.Before(*f.StartTime) {
		return f, fmt.Errorf("end_time 必须晚于 start_time")
	}
	if appID := r.URL.Query().Get("application_id"); appID != "" {
		id, err := uuid.Parse(appID)
		if err != nil {
			return f, fmt.Errorf("无效的应用ID")
		}
		f.ApplicationID = &id
	}
	return f, nil
}

// List 事件列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if list == nil {
		list = []Event{}
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Get 事件详情。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的事件ID")
		return
	}
	evt, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "事件不存在")
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"event": evt})
}

// ListByRule 按访问控制规则查询关联事件（access_rule_id = 规则 ID；
// IP 黑白名单命中 IP_ALLOW_MATCH/IP_DENY_MATCH 与 L7 规则命中事件均写该列）。
// 规则不存在时返回空分页（列表过滤语义，不单独 404）。记录低风险审计。
func (h *Handler) ListByRule(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	ruleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则ID")
		return
	}
	f, err := parseFilter(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	f.AccessRuleID = ruleID.String()
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if list == nil {
		list = []Event{}
	}
	h.recordAudit(r, p, "list_rule_events", ruleID.String(), "access_rule", audits.ResultSuccess, audits.RiskLow)
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Export 导出事件（CSV，记录导出审计；支持筛选导出与勾选 ids 导出）。
func (h *Handler) Export(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	ids, err := validation.ParseExportUUIDs(r.URL.Query(), "ids")
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	f, err := parseFilter(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	f.IDs = ids
	csvData, err := h.store.Export(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "export", "", fmt.Sprintf("filters=%s", r.URL.RawQuery), audits.ResultSuccess, audits.RiskMedium)

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="access-control-events.csv"`)
	_, _ = w.Write([]byte(csvData))
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, result, risk string) {
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "access_control_events",
		Action:       action,
		ObjectType:   "access_control_event",
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
