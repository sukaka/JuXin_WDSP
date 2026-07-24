package securityevents

import (
	"context"
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

// Handler 是安全事件中心处理器。
type Handler struct {
	store  *Store
	audits *audits.Service
	// exceptionCreator 例外草稿创建（避免循环依赖）
	exceptionCreator ExceptionCreator
}

// ExceptionCreator 是从事件创建例外草稿的接口。
type ExceptionCreator interface {
	CreateFromEvent(ctx context.Context, evt *Event, createdBy uuid.UUID) (uuid.UUID, error)
}

// NewHandler 创建事件中心处理器。
func NewHandler(store *Store, au *audits.Service, ec ExceptionCreator) *Handler {
	return &Handler{store: store, audits: au, exceptionCreator: ec}
}

// List 事件列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f := ListFilter{
		Domain:            r.URL.Query().Get("domain"),
		ClientIP:          r.URL.Query().Get("client_ip"),
		URI:               r.URL.Query().Get("uri"),
		Method:            r.URL.Query().Get("method"),
		AttackType:        r.URL.Query().Get("attack_type"),
		Severity:          r.URL.Query().Get("severity"),
		Action:            r.URL.Query().Get("action"),
		DispositionStatus: r.URL.Query().Get("disposition_status"),
		RequestID:         r.URL.Query().Get("request_id"),
		GatewayNode:       r.URL.Query().Get("gateway_node"),
		Page:              queryInt(r, "page", 1),
		PageSize:          queryInt(r, "page_size", 20),
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
	if appID := r.URL.Query().Get("application_id"); appID != "" {
		if id, err := uuid.Parse(appID); err == nil {
			f.ApplicationID = &id
		}
	}
	if rid := r.URL.Query().Get("rule_id"); rid != "" {
		if id, err := strconv.Atoi(rid); err == nil {
			f.RuleID = &id
		}
	}
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
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
	evt, matches, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "事件不存在")
		return
	}
	notes, _ := h.store.ListNotes(r.Context(), id)
	actions, _ := h.store.ListActions(r.Context(), id)
	related, _ := h.store.RelatedEvents(r.Context(), evt, 10)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"event":   evt,
		"matches": matches,
		"notes":   notes,
		"actions": actions,
		"related": related,
	})
}

// Related 相关事件。
func (h *Handler) Related(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的事件ID")
		return
	}
	evt, _, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "事件不存在")
		return
	}
	related, err := h.store.RelatedEvents(r.Context(), evt, 20)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": related})
}

type noteRequest struct {
	Note string `json:"note"`
}

// AddNote 添加备注。
func (h *Handler) AddNote(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的事件ID")
		return
	}
	var req noteRequest
	if err := response.DecodeJSON(w, r, &req, 2048); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.Note) == "" || len(req.Note) > 1000 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "备注不能为空且不超过1000字符")
		return
	}
	if _, _, err := h.store.GetByID(r.Context(), id); err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "事件不存在")
		return
	}
	if err := h.store.AddNote(r.Context(), id, p.UserID, p.Username, req.Note); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "security_events", "add_note", "security_event", id.String(), "note", audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "备注已添加"})
}

type dispositionRequest struct {
	Result string `json:"result"`
	Note   string `json:"note"`
}

// disposition 通用处置。
func (h *Handler) disposition(w http.ResponseWriter, r *http.Request, status, actionType string) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的事件ID")
		return
	}
	var req dispositionRequest
	_ = response.DecodeJSON(w, r, &req, 4096)
	if _, _, err := h.store.GetByID(r.Context(), id); err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "事件不存在")
		return
	}
	result := req.Result
	if result == "" {
		result = status
	}
	if err := h.store.UpdateDisposition(r.Context(), id, status, result, p.UserID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	detail := result
	if req.Note != "" {
		detail += ": " + req.Note
		_ = h.store.AddNote(r.Context(), id, p.UserID, p.Username, req.Note)
	}
	_ = h.store.AddAction(r.Context(), id, actionType, p.UserID, p.Username, detail, "")
	h.recordAudit(r, p, "security_events", actionType, "security_event", id.String(), result, audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "处置完成"})
}

// ConfirmAttack 确认攻击。
func (h *Handler) ConfirmAttack(w http.ResponseWriter, r *http.Request) {
	h.disposition(w, r, "CONFIRMED_ATTACK", "confirm_attack")
}

// ConfirmFalsePositive 确认误报。
func (h *Handler) ConfirmFalsePositive(w http.ResponseWriter, r *http.Request) {
	h.disposition(w, r, "CONFIRMED_FALSE_POSITIVE", "confirm_false_positive")
}

// Ignore 忽略。
func (h *Handler) Ignore(w http.ResponseWriter, r *http.Request) {
	h.disposition(w, r, "IGNORED", "ignore")
}

// Resolve 标记已处置。
func (h *Handler) Resolve(w http.ResponseWriter, r *http.Request) {
	h.disposition(w, r, "RESOLVED", "resolve")
}

// MarkAnalyzing 标记分析中。
func (h *Handler) MarkAnalyzing(w http.ResponseWriter, r *http.Request) {
	h.disposition(w, r, "ANALYZING", "mark_analyzing")
}

// CreateException 从事件创建例外草稿。
func (h *Handler) CreateException(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的事件ID")
		return
	}
	evt, _, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "事件不存在")
		return
	}
	if h.exceptionCreator == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "例外服务未配置")
		return
	}
	excID, err := h.exceptionCreator.CreateFromEvent(r.Context(), evt, p.UserID)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	_ = h.store.AddAction(r.Context(), id, "create_exception", p.UserID, p.Username, "created exception draft", excID.String())
	h.recordAudit(r, p, "security_events", "create_exception", "security_event", id.String(), excID.String(), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"exception_id": excID,
		"message":      "例外草稿已创建，请前往例外策略页面审核发布",
	})
}

// Export 导出事件（CSV）。
func (h *Handler) Export(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	f := ListFilter{
		Domain:     r.URL.Query().Get("domain"),
		AttackType: r.URL.Query().Get("attack_type"),
		Severity:   r.URL.Query().Get("severity"),
		Page:       1,
		PageSize:   100,
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
	// 分页拉取（List 单页上限 100），导出总量上限 10000 行
	var list []Event
	for page := 1; len(list) < 10000; page++ {
		f.Page = page
		f.PageSize = 100
		batch, total, err := h.store.List(r.Context(), f)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		list = append(list, batch...)
		if int64(len(list)) >= total || len(batch) == 0 {
			break
		}
	}
	h.recordAudit(r, p, "security_events", "export", "security_event", "", fmt.Sprintf("count=%d", len(list)), audits.ResultSuccess, audits.RiskMedium)

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="security-events.csv"`)
	var b strings.Builder
	b.WriteString("occurred_at,client_ip,domain,method,uri,attack_type,severity,anomaly_score,action,response_status,disposition_status,request_id\n")
	for _, e := range list {
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%s,%d,%s,%d,%s,%s\n",
			e.OccurredAt.UTC().Format(time.RFC3339), e.ClientIP, csvEscape(e.Domain), e.Method,
			csvEscape(e.URI), e.AttackType, e.Severity, e.AnomalyScore, e.Action, e.ResponseStatus,
			e.DispositionStatus, e.RequestID)
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
