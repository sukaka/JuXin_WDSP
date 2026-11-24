package securityevents

import (
	"context"
	"fmt"
	"log/slog"
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

// Handler 是安全事件中心处理器。
type Handler struct {
	store  *Store
	audits *audits.Service
	// exceptionCreator 例外草稿创建（避免循环依赖）
	exceptionCreator ExceptionCreator
	// geoLookup 统一 GeoIP 查询器（纯内存实时补齐归属地与运营商；nil 时跳过）
	geoLookup apigeo.GeoLookup
}

// ExceptionCreator 是从事件创建例外草稿的接口。
type ExceptionCreator interface {
	CreateFromEvent(ctx context.Context, evt *Event, createdBy uuid.UUID) (uuid.UUID, error)
}

// NewHandler 创建事件中心处理器。
func NewHandler(store *Store, au *audits.Service, ec ExceptionCreator) *Handler {
	return &Handler{store: store, audits: au, exceptionCreator: ec}
}

// SetGeoLookup 注入统一 GeoIP 归属地查询器。
func (h *Handler) SetGeoLookup(g apigeo.GeoLookup) {
	h.geoLookup = g
}

func (h *Handler) attachGeo(evt *Event) {
	if h == nil || h.geoLookup == nil || evt == nil || evt.ClientIP == "" {
		return
	}
	evt.ClientIPGeo = h.geoLookup.LookupGeo(evt.ClientIP)
}

func (h *Handler) attachGeoSlice(list []Event) {
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

// parseListFilter 解析安全事件查询筛选条件（List 与 Export 共用，确保导出与列表筛选维度完全一致）。
func parseListFilter(r *http.Request) ListFilter {
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
	return f
}

// List 事件列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f := parseListFilter(r)
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.attachGeoSlice(list)
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// RuleEffectStats 返回规则版本按日效果统计。
func (h *Handler) RuleEffectStats(w http.ResponseWriter, r *http.Request) {
	f := RuleEffectStatsFilter{
		RuleVersion: r.URL.Query().Get("rule_version"),
		Page:        queryInt(r, "page", 1),
		PageSize:    queryInt(r, "page_size", 50),
	}
	if raw := r.URL.Query().Get("from"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "from 必须是 RFC3339 时间")
			return
		}
		f.From = &t
	}
	if raw := r.URL.Query().Get("to"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "to 必须是 RFC3339 时间")
			return
		}
		f.To = &t
	}
	if raw := r.URL.Query().Get("rule_id"); raw != "" {
		ruleID, err := strconv.Atoi(raw)
		if err != nil || ruleID <= 0 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "rule_id 必须是正整数")
			return
		}
		f.RuleID = &ruleID
	}
	if f.From != nil && f.To != nil && !f.From.Before(*f.To) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "from 必须早于 to")
		return
	}
	items, total, err := h.store.RuleEffectStats(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, items, total, f.Page, f.PageSize)
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
	// CNNVD 兼容性 P1：matches 联查漏洞编号取现值；联查失败静默降级为空数组，不阻塞详情
	if err := h.store.AttachVulnIDs(r.Context(), matches); err != nil {
		slog.Warn("event detail: attach vuln ids failed", "event_id", id, "error", err)
	}
	notes, err := h.store.ListNotes(r.Context(), id)
	if err != nil {
		slog.Warn("event detail: list notes failed", "event_id", id, "error", err)
	}
	actions, err := h.store.ListActions(r.Context(), id)
	if err != nil {
		slog.Warn("event detail: list actions failed", "event_id", id, "error", err)
	}
	related, err := h.store.RelatedEvents(r.Context(), evt, 10)
	if err != nil {
		slog.Warn("event detail: list related events failed", "event_id", id, "error", err)
		related = &RelatedResult{Events: []Event{}, Mode: "none"}
	}
	h.attachGeo(evt)
	h.attachGeoSlice(related.Events)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"event":              evt,
		"matches":            matches,
		"notes":              notes,
		"actions":            actions,
		"related":            related.Events,
		"related_mode":       related.Mode,
		"related_session_id": related.SessionID,
	})
}

// GetRemediation 返回事件对应攻击类型的修复建议（处置知识库）。
func (h *Handler) GetRemediation(w http.ResponseWriter, r *http.Request) {
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
	ruleIDs := make([]int, 0, len(matches))
	for _, m := range matches {
		ruleIDs = append(ruleIDs, m.RuleID)
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"remediation": RemediationFor(evt.AttackType),
		"event": map[string]interface{}{
			"id":          evt.ID,
			"attack_type": evt.AttackType,
			"request_uri": evt.URI,
			"rule_ids":    ruleIDs,
		},
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
	h.attachGeoSlice(related.Events)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"items":      related.Events,
		"mode":       related.Mode,
		"session_id": related.SessionID,
	})
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
	_, _, err = h.store.GetByID(r.Context(), id)
	if err != nil {
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
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	evt, _, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "事件不存在")
		return
	}
	result := req.Result
	if result == "" {
		result = status
	}
	idempotent, transitionErr := ValidateDispositionTransition(evt.DispositionStatus, status)
	if transitionErr != nil {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "事件已完成该处置，不能重复改变结论")
		return
	}
	if idempotent {
		response.JSON(w, r, http.StatusOK, map[string]string{"message": "处置已是当前状态"})
		return
	}
	updated, err := h.store.UpdateDispositionIfCurrent(r.Context(), id, evt.DispositionStatus, status, result, p.UserID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if !updated {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "事件状态已被其他操作更新，请刷新后重试")
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

// Export 导出事件（CSV，支持全部列表筛选条件以及按勾选 ids 导出）。
func (h *Handler) Export(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	ids, err := validation.ParseExportUUIDs(r.URL.Query(), "ids")
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	f := parseListFilter(r)
	f.IDs = ids
	f.Page = 1
	f.PageSize = 100
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
	_, _ = w.Write([]byte(renderExportCSV(list)))
}

const exportCSVUTF8BOM = "\xef\xbb\xbf"

const exportCSVHeader = "发生时间,客户端 IP,域名,请求方法,请求路径,攻击类型,严重级别,异常评分,动作,响应状态码,处置状态,请求 ID\n"

// renderExportCSV 渲染安全事件 CSV（含 UTF-8 BOM、中文表头与枚举中文化、防公式注入）。
func renderExportCSV(list []Event) string {
	var b strings.Builder
	b.WriteString(exportCSVUTF8BOM)
	b.WriteString(exportCSVHeader)
	for _, e := range list {
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%s,%d,%s,%d,%s,%s\n",
			e.OccurredAt.UTC().Format(time.RFC3339),
			csvEscape(e.ClientIP), csvEscape(e.Domain), csvEscape(e.Method),
			csvEscape(e.URI), csvEscape(exportAttackTypeLabel(e.AttackType)),
			csvEscape(exportSeverityLabel(e.Severity)), e.AnomalyScore,
			csvEscape(exportActionLabel(e.Action)), e.ResponseStatus,
			csvEscape(exportDispositionLabel(e.DispositionStatus)), csvEscape(e.RequestID))
	}
	return b.String()
}

var exportAttackTypeLabels = map[string]string{
	"SQL_INJECTION":          "SQL注入",
	"SQLI":                   "SQL注入",
	"XSS":                    "XSS跨站脚本",
	"COMMAND_INJECTION":      "命令注入",
	"LOCAL_FILE_INCLUSION":   "本地文件包含",
	"REMOTE_FILE_INCLUSION":  "远程文件包含",
	"PATH_TRAVERSAL":         "路径穿越",
	"PHP_INJECTION":          "PHP注入",
	"JAVA_INJECTION":         "Java注入",
	"PROTOCOL_VIOLATION":     "协议违规",
	"SESSION_FIXATION":       "会话固定",
	"SCANNER_DETECTION":      "扫描器探测",
	"SCANNER":                "扫描器探测",
	"INFORMATION_DISCLOSURE": "信息泄露",
	"REMOTE_CODE_EXECUTION":  "远程代码执行",
	"RCE":                    "远程代码执行",
	"SSRF":                   "SSRF",
	"XXE_INJECTION":          "XXE注入",
	"WEBSHELL":               "WebShell",
	"FILE_UPLOAD":            "文件上传攻击",
	"DESERIALIZATION":        "反序列化",
	"SSTI":                   "模板注入",
	"DOS":                    "拒绝服务",
	"MASS_ASSIGNMENT":        "批量赋值",
	"EXCLUSION":              "应用白名单排除",
	"OTHER":                  "其他",
}

func exportAttackTypeLabel(v string) string {
	key := strings.ToUpper(strings.TrimSpace(v))
	if key == "" {
		return ""
	}
	if label, ok := exportAttackTypeLabels[key]; ok {
		return label
	}
	return v
}

func exportSeverityLabel(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "":
		return ""
	case "CRITICAL":
		return "严重"
	case "HIGH":
		return "高"
	case "MEDIUM":
		return "中"
	case "LOW":
		return "低"
	case "INFO":
		return "信息"
	default:
		return v
	}
}

func exportActionLabel(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "":
		return ""
	case "BLOCK":
		return "阻断"
	case "OBSERVE":
		return "观察"
	case "ALLOW":
		return "放行"
	default:
		return v
	}
}

func exportDispositionLabel(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "":
		return ""
	case "UNPROCESSED":
		return "未处置"
	case "ANALYZING":
		return "分析中"
	case "CONFIRMED_ATTACK":
		return "确认攻击"
	case "CONFIRMED_FALSE_POSITIVE":
		return "确认误报"
	case "IGNORED":
		return "已忽略"
	case "RESOLVED":
		return "已处置"
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
