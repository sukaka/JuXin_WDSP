package systemalerts

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/validation"
)

// exportLimit 导出行数上限。
const exportLimit = 10000

// Handler 是系统告警处理器。
type Handler struct {
	store  *Store
	audits *audits.Service
	// notifyResolved 手动解决（RESOLVED/MANUAL）成功后的通知投递函数（装配层注入，
	// 通知层按 notify_resolved 开关决定是否外发；nil 时跳过）。
	notifyResolved func(a Alert)
}

// NewHandler 创建处理器。
func NewHandler(store *Store, au *audits.Service) *Handler {
	return &Handler{store: store, audits: au}
}

// SetNotifyResolvedFunc 设置手动解决告警后的通知投递函数（可为 nil）。
func (h *Handler) SetNotifyResolvedFunc(fn func(a Alert)) { h.notifyResolved = fn }

// List 告警列表（筛选 status/severity/alert_type/component/时间范围）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f, ok := parseListFilter(w, r)
	if !ok {
		return
	}
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	for i := range list {
		list[i].Message = localizeAlertMessage(list[i].Message)
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Get 告警详情（含备注）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的告警ID")
		return
	}
	a, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "告警不存在")
		return
	}
	a.Message = localizeAlertMessage(a.Message)
	notes, err := h.store.ListNotes(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"alert": a,
		"notes": notes,
	})
}

// Acknowledge 确认告警。
func (h *Handler) Acknowledge(w http.ResponseWriter, r *http.Request) {
	h.transition(w, r, "acknowledge", func(id, by uuid.UUID) error {
		return h.store.Acknowledge(r.Context(), id, by, time.Now().UTC())
	})
}

// Resolve 标记已解决。
func (h *Handler) Resolve(w http.ResponseWriter, r *http.Request) {
	h.transition(w, r, "resolve", func(id, by uuid.UUID) error {
		return h.store.ResolveManual(r.Context(), id, by, time.Now().UTC())
	})
}

// Ignore 忽略告警。
func (h *Handler) Ignore(w http.ResponseWriter, r *http.Request) {
	h.transition(w, r, "ignore", func(id, _ uuid.UUID) error {
		return h.store.Ignore(r.Context(), id)
	})
}

// silenceRequest 静默请求体：duration_minutes 为静默时长（分钟）。
type silenceRequest struct {
	DurationMinutes int `json:"duration_minutes"`
}

// 静默时长合法区间：1 分钟 ~ 30 天。
const (
	minSilenceMinutes = 1
	maxSilenceMinutes = 43200
)

// Silence 静默告警（W6-B / P1-08）：设置 silenced_until = now + duration_minutes。
// 静默期间告警保持未关闭状态照常合并记录，同指纹新建告警不重复通知；
// 重复静默视为延长。
func (h *Handler) Silence(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的告警ID")
		return
	}
	var req silenceRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.DurationMinutes < minSilenceMinutes || req.DurationMinutes > maxSilenceMinutes {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("静默时长须在 %d~%d 分钟之间", minSilenceMinutes, maxSilenceMinutes))
		return
	}
	a, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "告警不存在")
		return
	}
	until := time.Now().UTC().Add(time.Duration(req.DurationMinutes) * time.Minute)
	if err := h.store.Silence(r.Context(), id, until); err != nil {
		if errors.Is(err, ErrInvalidTransition) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "当前状态不允许该操作")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "silence", id.String(), a.Title, audits.ResultSuccess, audits.RiskMedium)
	updated, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, updated)
}

// Resume 解除静默（W6-B / P1-08）：清除 silenced_until，恢复同指纹告警通知。
func (h *Handler) Resume(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的告警ID")
		return
	}
	a, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "告警不存在")
		return
	}
	if err := h.store.Resume(r.Context(), id); err != nil {
		if errors.Is(err, ErrInvalidTransition) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "当前状态不允许该操作")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "resume", id.String(), a.Title, audits.ResultSuccess, audits.RiskMedium)
	updated, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, updated)
}

// transition 状态流转公共逻辑（确认/解决/忽略，中风险审计）。
func (h *Handler) transition(w http.ResponseWriter, r *http.Request, action string,
	op func(id, by uuid.UUID) error) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的告警ID")
		return
	}
	a, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "告警不存在")
		return
	}
	if err := op(id, p.UserID); err != nil {
		if errors.Is(err, ErrInvalidTransition) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "当前状态不允许该操作")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, action, id.String(), a.Title, audits.ResultSuccess, audits.RiskMedium)
	updated, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	// 手动解决成功：投递 RESOLVED 事件（通知层按 notify_resolved 开关决定是否外发）；
	// 投递函数 panic 只记日志，不影响处置主流程。
	if action == "resolve" && h.notifyResolved != nil {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("notify resolved hook panicked", "alert_id", id, "panic", rec)
			}
		}()
		h.notifyResolved(*updated)
	}
	response.JSON(w, r, http.StatusOK, updated)
}

type noteRequest struct {
	Note string `json:"note"`
}

// AddNote 添加告警备注。
func (h *Handler) AddNote(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的告警ID")
		return
	}
	var req noteRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	req.Note = strings.TrimSpace(req.Note)
	if req.Note == "" || len(req.Note) > 1000 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "备注不能为空且不超过1000字符")
		return
	}
	a, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "告警不存在")
		return
	}
	n, err := h.store.AddNote(r.Context(), id, req.Note, &p.UserID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	n.Username = p.Username
	h.recordAudit(r, p, "add_note", id.String(), a.Title, audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, n)
}

// Export 导出告警（CSV，防公式注入，最多 10000 条；支持筛选导出与勾选 ids 导出）。
func (h *Handler) Export(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	ids, err := validation.ParseExportUUIDs(r.URL.Query(), "ids")
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	f, ok := parseListFilter(w, r)
	if !ok {
		return
	}
	f.IDs = ids
	f.Page = 1
	f.PageSize = exportLimit
	list, _, err := h.store.ListForExport(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	csvContent := renderExportCSV(list)
	h.recordAudit(r, p, "export", "", "system_alerts", audits.ResultSuccess, audits.RiskLow)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="system-alerts.csv"`)
	_, _ = w.Write([]byte(csvContent))
}

const exportCSVUTF8BOM = "\xef\xbb\xbf"

const exportCSVHeader = "告警 ID,告警类型,严重级别,组件,标题,详情,状态,发生次数,首次发生时间,最近发生时间,解决时间,解决方式\n"

// renderExportCSV 渲染系统告警 CSV（含 UTF-8 BOM、中文表头与枚举中文化、防公式注入）。
func renderExportCSV(list []Alert) string {
	var b strings.Builder
	b.WriteString(exportCSVUTF8BOM)
	b.WriteString(exportCSVHeader)
	for _, a := range list {
		resolvedAt, resolveType := "", ""
		if a.ResolvedAt != nil {
			resolvedAt = a.ResolvedAt.UTC().Format(time.RFC3339)
		}
		if a.ResolveType != nil {
			resolveType = *a.ResolveType
		}
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%s,%d,%s,%s,%s,%s\n",
			csvCell(a.ID.String()),
			csvCell(exportAlertTypeLabel(a.AlertType)),
			csvCell(exportAlertSeverityLabel(a.Severity)),
			csvCell(exportAlertComponentLabel(a.Component)),
			csvCell(a.Title),
			csvCell(localizeAlertMessage(a.Message)),
			csvCell(exportAlertStatusLabel(a.Status)),
			a.OccurrenceCount,
			a.FirstSeenAt.UTC().Format(time.RFC3339),
			a.LastSeenAt.UTC().Format(time.RFC3339),
			resolvedAt,
			csvCell(exportResolveTypeLabel(resolveType)))
	}
	return b.String()
}

var exportAlertTypeLabels = map[string]string{
	TypeGatewayDown:              "网关不可用",
	TypeManagementAPIDown:        "管理 API 不可用",
	TypeDatabaseUnavailable:      "数据库不可用",
	TypeValkeyUnavailable:        "缓存服务不可用",
	TypeEventCollectorLag:        "事件采集积压",
	TypeParseFailureRateHigh:     "事件解析失败率高",
	TypeSourceUnhealthy:          "源站不健康",
	TypeCertificateExpiring:        "证书即将到期",
	TypeCertificateExpired:         "证书已过期",
	TypeCertificateAutoRenewFailed: "自动申请/续约证书失败",
	TypeConfigPublishFailed:      "配置发布失败",
	TypeConfigHashMismatch:       "配置哈希不一致",
	TypeDiskSpaceLow:             "磁盘空间不足",
	TypeDatabaseCapacityHigh:     "数据库容量高",
	TypeFDUsageHigh:              "文件句柄使用率高",
	TypeBackupFailed:             "备份失败",
	TypeBackupVerifyFailed:       "备份校验失败",
	TypeRestoreValidationFailed:  "恢复校验失败",
	TypeRestoreCleanupFailed:     "恢复清理失败",
	TypeReportFailed:             "报告生成失败",
	TypeUpgradeFailed:            "升级失败",
	TypeUpgradeRollbackFailed:    "升级回滚失败",
	TypeUpgradeRolledBack:        "升级已回滚",
	TypeAuditIntegrityFailed:     "审计完整性失败",
	TypeAuditWriteFailed:         "审计写入失败",
	TypeVulnIntelNew:             "漏洞情报",
	TypeAPICriticalFinding:       "API 严重风险发现",
	TypeAPIFindingSpike:          "API 风险发现激增",
	TypeAPIMaskFailure:           "API 响应脱敏失败",
	TypeSecurityEventSpike:       "安全事件激增",
	TypeLoginBruteForce:          "登录暴力破解",
	TypeCCBanSpike:               "CC 封禁激增",
	TypeLicenseInvalid:           "系统授权无效",
	TypeLicenseExpiringSoon:      "系统授权即将到期",
	TypeLicenseQuotaExceeded:     "授权配额超限",
	TypeHAVIPFault:               "高可用虚拟 IP 故障",
	TypeHASplitBrain:             "主备双主脑裂",
	TypeNetworkApplyFailed:       "网络配置应用失败",
	TypeLinkPairDown:             "网桥链路对中断",
	TypeLinkPairSuppressed:       "网桥链路对联动抑制",
	TypeEndpointLatencyHigh:      "端点时延偏高",
	TypeEndpointErrorRateHigh:    "端点错误率偏高",
	TypeAPMSLOBreach:             "APM SLO 违约",
	TypeAPMIngestLag:             "APM 采集入库滞后",
	TypeAIOpsScheduleCircuitOpen: "AI 定时运营任务熔断",
}

func exportAlertTypeLabel(v string) string {
	key := strings.ToUpper(strings.TrimSpace(v))
	if key == "" {
		return ""
	}
	if label, ok := exportAlertTypeLabels[key]; ok {
		return label
	}
	return v
}

func exportAlertSeverityLabel(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "":
		return ""
	case SeverityCritical:
		return "严重"
	case SeverityHigh:
		return "高危"
	case SeverityMedium:
		return "中危"
	case SeverityLow:
		return "低危"
	case SeverityInfo:
		return "提示"
	default:
		return v
	}
}

var exportAlertComponentLabels = map[string]string{
	"GATEWAY":               "防护网关",
	"CORAZA":                "WAF 引擎",
	"GUARD":                 "访问控制模块",
	"API":                   "管理 API",
	"POSTGRES":              "数据库",
	"VALKEY":                "缓存服务",
	"EVENT_COLLECTOR":       "事件采集器",
	"UPSTREAM":              "源站",
	"CERTIFICATE":           "证书",
	"DISK":                  "磁盘",
	"API_SECURITY":          "API 安全采集",
	"APM_CLICKHOUSE":        "APM 时序存储",
	"WAF":                   "WAF 防护",
	"CC":                    "CC 防护",
	"CLICKHOUSE":            "ClickHouse 时序存储",
	"AUDIT":                 "操作审计",
	"LICENSE":               "系统授权",
	"BACKUP":                "系统备份",
	"RESTORE":               "系统恢复",
	"UPGRADE":               "系统升级",
	"REPORT":                "安全报告",
	"HA_VIP":                "主备虚拟 IP",
	"NETWORK":               "网络配置",
	"LINK_PAIR":             "网桥链路对",
	"AI_OPS":                "AI 智能运营",
	"API_GATEWAY_NODES":      "多节点网关",
	"API_GATEWAY_NODE_SYNC":  "网关节点配置同步",
	"API_ENDPOINT_DISCOVERY": "API 端点发现",
}

func exportAlertComponentLabel(v string) string {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return ""
	}
	if label, ok := exportAlertComponentLabels[strings.ToUpper(trimmed)]; ok {
		return label
	}
	if len(trimmed) > len("vuln_intel:") && strings.EqualFold(trimmed[:len("vuln_intel:")], "vuln_intel:") {
		return "漏洞情报:" + trimmed[len("vuln_intel:"):]
	}
	return v
}

func exportAlertStatusLabel(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "":
		return ""
	case StatusOpen:
		return "未处理"
	case StatusAcknowledged:
		return "已确认"
	case StatusResolved:
		return "已解决"
	case StatusIgnored:
		return "已忽略"
	default:
		return v
	}
}

func exportResolveTypeLabel(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "":
		return ""
	case ResolveManual:
		return "人工解决"
	case ResolveRecovered:
		return "自动恢复"
	default:
		return v
	}
}

// ListMaintenanceWindows 维护窗口列表（阶段6 §11.5）。
func (h *Handler) ListMaintenanceWindows(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.ListMaintenanceWindows(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": list, "total": len(list)})
}

// CreateMaintenanceWindow 创建维护窗口：参数校验 + 中风险审计。
func (h *Handler) CreateMaintenanceWindow(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req maintenanceWindowInput
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if msg := req.validate(); msg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return
	}
	mw := req.toWindow(p.UserID)
	if err := h.store.CreateMaintenanceWindow(r.Context(), mw); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAuditObj(r, p, "create", "system_alert_maintenance_window", mw.ID.String(), mw.Name, audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, mw)
}

// DeleteMaintenanceWindow 删除维护窗口（中风险审计）。
func (h *Handler) DeleteMaintenanceWindow(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的维护窗口ID")
		return
	}
	if err := h.store.DeleteMaintenanceWindow(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "维护窗口不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAuditObj(r, p, "delete", "system_alert_maintenance_window", id.String(), "maintenance_window", audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "维护窗口已删除"})
}

// csvCell CSV 单元格转义 + 公式注入防护（= + - @ \t \r 前导字符加单引号）。
func csvCell(s string) string {
	leadingCR := len(s) > 0 && s[0] == '\r'
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if leadingCR {
		s = "'" + s
	} else if len(s) > 0 {
		switch s[0] {
		case '=', '+', '-', '@', '\t':
			s = "'" + s
		}
	}
	if strings.ContainsAny(s, ",\"") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

// parseListFilter 解析并校验列表筛选参数。
func parseListFilter(w http.ResponseWriter, r *http.Request) (ListFilter, bool) {
	f := ListFilter{
		Status:    strings.ToUpper(r.URL.Query().Get("status")),
		Severity:  strings.ToUpper(r.URL.Query().Get("severity")),
		AlertType: strings.ToUpper(r.URL.Query().Get("alert_type")),
		Component: strings.ToUpper(r.URL.Query().Get("component")),
		View:      strings.ToUpper(r.URL.Query().Get("view")),
		Page:      queryInt(r, "page", 1),
		PageSize:  queryInt(r, "page_size", 20),
	}
	if f.Status != "" && !IsValidStatus(f.Status) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的告警状态")
		return f, false
	}
	if f.View != "" {
		if !IsValidView(f.View) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的告警视图（ACTIVE/SILENCED/HISTORY）")
			return f, false
		}
		// view 与 status 口径重叠，同时提供视为参数错误（不静默忽略任一条件）
		if f.Status != "" {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "view 与 status 参数互斥，请只提供其一")
			return f, false
		}
	}
	if f.Severity != "" && !IsValidSeverity(f.Severity) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的告警等级")
		return f, false
	}
	if f.AlertType != "" && !IsValidType(f.AlertType) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的告警类型")
		return f, false
	}
	if st := r.URL.Query().Get("start_time"); st != "" {
		t, err := time.Parse(time.RFC3339, st)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 start_time（RFC3339）")
			return f, false
		}
		f.StartTime = &t
	}
	if et := r.URL.Query().Get("end_time"); et != "" {
		t, err := time.Parse(time.RFC3339, et)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 end_time（RFC3339）")
			return f, false
		}
		f.EndTime = &t
	}
	return f, true
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, result, risk string) {
	h.recordAuditObj(r, p, action, "system_alert", objID, objName, result, risk)
}

func (h *Handler) recordAuditObj(r *http.Request, p *authz.Principal, action, objType, objID, objName, result, risk string) {
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "system_alerts",
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
