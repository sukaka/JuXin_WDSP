// handler.go 漏洞情报提醒 HTTP 接口（VULN_INTEL MVP）。
// 路由（app.go 注册）：
//
//	GET  /api/v1/vuln-intel/overview              概览（vuln_intel.read）
//	GET  /api/v1/vuln-intel/advisories            列表（vuln_intel.read）
//	GET  /api/v1/vuln-intel/advisories/{cve_id}   详情（vuln_intel.read）
//	POST /api/v1/vuln-intel/sync                  手动 NVD 同步（vuln_intel.manage）
//	POST /api/v1/vuln-intel/import                JSON 导入（vuln_intel.manage）
//	GET  /api/v1/vuln-intel/tech-assets           应用技术栈映射（vuln_intel.read）
//	PUT  /api/v1/vuln-intel/tech-assets           整组替换映射（vuln_intel.manage）
//	GET  /api/v1/vuln-intel/settings              订阅设置（vuln_intel.read）
//	PUT  /api/v1/vuln-intel/settings              更新订阅设置（vuln_intel.manage）
//
// 写操作 CSRF/权限由 app.go authChain + RequirePermission 强制；审计在本处理器记录。
package vulnintel

import (
	"context"
	"encoding/json"
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
)

// 请求体大小上限（导入一批漏洞 JSON；单条 raw 已由 MaxRawBytes 约束）。
const maxImportBodyBytes = 4 << 20

// 手动同步整体超时（分页拉取 + 页间限速的最长预算）。
const manualSyncTimeout = 5 * time.Minute

// Handler 是漏洞情报处理器。
type Handler struct {
	store    *Store
	syncer   *Syncer
	alerter  *Alerter
	settings SettingsReader
	writer   SettingsWriter
	audits   *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(store *Store, syncer *Syncer, alerter *Alerter,
	settings SettingsReader, writer SettingsWriter, au *audits.Service) *Handler {
	return &Handler{store: store, syncer: syncer, alerter: alerter, settings: settings, writer: writer, audits: au}
}

// ---------- 概览 ----------

// Overview 返回情报概览：统计 + 订阅配置 + 同步状态。
func (h *Handler) Overview(w http.ResponseWriter, r *http.Request) {
	o, err := h.store.GetOverview(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	state, err := h.store.GetSyncState(r.Context(), SyncSourceNVD)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	sub := LoadSubscription(r.Context(), h.settings)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"total":          o.Total,
		"new_last_7d":    o.NewLast7d,
		"critical_count": o.CriticalCount,
		"high_count":     o.HighCount,
		"watch_techs":    sub.WatchTechs,
		"min_severity":   sub.MinSeverity,
		"sync_enabled":   sub.SyncEnabled,
		"sync_state":     state,
	})
}

// ---------- 列表与详情 ----------

// ListAdvisories 分页过滤查询漏洞情报。
func (h *Handler) ListAdvisories(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := ListFilter{
		Keyword:  strings.TrimSpace(q.Get("keyword")),
		Severity: strings.ToUpper(strings.TrimSpace(q.Get("severity"))),
		Tech:     strings.ToLower(strings.TrimSpace(q.Get("tech"))),
		Source:   strings.ToUpper(strings.TrimSpace(q.Get("source"))),
	}
	if f.Severity != "" && !IsValidSeverity(f.Severity) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "severity 词表非法（CRITICAL/HIGH/MEDIUM/LOW/NONE）")
		return
	}
	if f.Source != "" && !IsValidSource(f.Source) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "source 词表非法（NVD/MANUAL）")
		return
	}
	if f.Tech != "" {
		if err := ValidateTechName(f.Tech); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
	}
	if v := strings.TrimSpace(q.Get("published_start")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "published_start 必须是 RFC3339 时间")
			return
		}
		f.PublishedStart = &t
	}
	if v := strings.TrimSpace(q.Get("published_end")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "published_end 必须是 RFC3339 时间")
			return
		}
		f.PublishedEnd = &t
	}
	if f.PublishedStart != nil && f.PublishedEnd != nil && f.PublishedEnd.Before(*f.PublishedStart) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "published_end 早于 published_start")
		return
	}
	f.Page = parsePositiveInt(q.Get("page"), 1)
	f.PageSize = parsePositiveInt(q.Get("page_size"), 20)
	if len(f.Keyword) > 200 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "keyword 超过 200 字符上限")
		return
	}
	items, total, err := h.store.ListAdvisories(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, items, total, f.Page, f.PageSize)
}

// GetAdvisory 漏洞详情（含各技术标签的受影响应用）。
func (h *Handler) GetAdvisory(w http.ResponseWriter, r *http.Request) {
	cveID := NormalizeCVE(r.PathValue("cve_id"))
	if err := ValidateCVE(cveID); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	adv, err := h.store.GetByCVE(r.Context(), cveID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "漏洞情报不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	type affectedApp struct {
		ApplicationID uuid.UUID `json:"application_id"`
		Code          string    `json:"code"`
		Name          string    `json:"name"`
		Tech          string    `json:"tech"`
	}
	affected := []affectedApp{}
	seen := map[string]bool{}
	for _, tech := range adv.TechTags {
		apps, err := h.store.AffectedApps(r.Context(), tech)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		for _, app := range apps {
			key := app.ID.String() + "|" + tech
			if seen[key] {
				continue
			}
			seen[key] = true
			affected = append(affected, affectedApp{app.ID, app.Code, app.Name, tech})
		}
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"advisory":      adv,
		"affected_apps": affected,
	})
}

// ---------- 手动同步 ----------

// Sync 手动触发一次 NVD 同步（不受 sync_enabled 开关约束；失败如实落同步状态并返回 502）。
func (h *Handler) Sync(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	// M-S12: 手动同步可能耗时达 manualSyncTimeout（5 分钟），显式扩展当前响应的写截止时间，
	// 防止被 HTTP Server 全局 WriteTimeout（默认 30s）提前中断。
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Now().Add(manualSyncTimeout + 10*time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		slog.Warn("vuln intel sync extend write deadline failed", "error", err)
	}
	ctx, cancel := context.WithTimeout(r.Context(), manualSyncTimeout)
	defer cancel()
	res, err := h.syncer.Run(ctx)
	if err != nil {
		if errors.Is(err, ErrSyncRunning) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "已有同步任务在进行中")
			return
		}
		h.recordAudit(r, p, "sync", "NVD", "", auditSummary(map[string]interface{}{"error": err.Error()}),
			audits.ResultFailure, err.Error(), audits.RiskMedium)
		response.Error(w, r, http.StatusBadGateway, response.CodeServiceUnavailable,
			"NVD 同步失败："+err.Error())
		return
	}
	raised := 0
	if h.alerter != nil && len(res.NewAdvisories) > 0 {
		// 情报已落库但提醒失败：如实 500（vuln_alerted 未记，下轮重评估不漏提醒）
		n, aerr := h.alerter.ProcessNew(r.Context(), res.NewAdvisories)
		if aerr != nil {
			response.InternalError(w, r, fmt.Errorf("漏洞情报提醒失败: %w", aerr))
			return
		}
		raised = n
	}
	h.recordAudit(r, p, "sync", "NVD", "",
		auditSummary(map[string]interface{}{
			"fetched": res.Fetched, "upserted": res.Upserted,
			"new": len(res.NewAdvisories), "alerts_raised": raised,
		}),
		audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"source":           res.Source,
		"window_start":     res.WindowStart,
		"window_end":       res.WindowEnd,
		"fetched":          res.Fetched,
		"upserted":         res.Upserted,
		"new_advisories":   len(res.NewAdvisories),
		"alerts_raised":    raised,
		"records_upserted": res.RecordsUpserted,
	})
}

// ---------- 离线导入 ----------

type importAdvisory struct {
	CVEID          string     `json:"cve_id"`
	Title          string     `json:"title"`
	Summary        string     `json:"summary"`
	Severity       string     `json:"severity"`
	CVSSScore      *float64   `json:"cvss_score"`
	PublishedAt    *time.Time `json:"published_at"`
	LastModifiedAt *time.Time `json:"last_modified_at"`
	TechTags       []string   `json:"tech_tags"`
	References     []string   `json:"references"`
}

type importRequest struct {
	Advisories []importAdvisory `json:"advisories"`
}

// importRowError 是一条导入校验失败明细。
type importRowError struct {
	Index  int    `json:"index"`
	CVEID  string `json:"cve_id"`
	Reason string `json:"reason"`
}

// Import JSON 导入漏洞情报（source=MANUAL；与 NVD 同步共用 upsert 与提醒引擎）。
func (h *Handler) Import(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req importRequest
	if err := response.DecodeJSON(w, r, &req, maxImportBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误或内容过大")
		return
	}
	if len(req.Advisories) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "advisories 不能为空")
		return
	}
	if len(req.Advisories) > 500 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "单批导入超过 500 条上限")
		return
	}

	rowErrs := []importRowError{}
	valid := make([]Advisory, 0, len(req.Advisories))
	for i, in := range req.Advisories {
		adv := Advisory{
			CVEID:          in.CVEID,
			Title:          in.Title,
			Summary:        in.Summary,
			Severity:       strings.ToUpper(strings.TrimSpace(in.Severity)),
			CVSSScore:      in.CVSSScore,
			PublishedAt:    in.PublishedAt,
			LastModifiedAt: in.LastModifiedAt,
			TechTags:       in.TechTags,
			References:     in.References,
			Source:         SourceManual,
		}
		if adv.Severity == "" {
			// 未给级别时按 CVSS 分值派生；无分值则 NONE（不虚构级别）
			if adv.CVSSScore != nil {
				adv.Severity = SeverityFromScore(*adv.CVSSScore)
			} else {
				adv.Severity = SeverityNone
			}
		}
		if err := ValidateAdvisory(&adv); err != nil {
			rowErrs = append(rowErrs, importRowError{Index: i, CVEID: NormalizeCVE(in.CVEID), Reason: err.Error()})
			continue
		}
		valid = append(valid, adv)
	}

	inserted, updated := 0, 0
	newAdvisories := []Advisory{}
	for i := range valid {
		isNew, err := h.store.UpsertAdvisory(r.Context(), &valid[i], nil)
		if err != nil {
			response.InternalError(w, r, fmt.Errorf("upsert advisory %s: %w", valid[i].CVEID, err))
			return
		}
		if isNew {
			inserted++
			newAdvisories = append(newAdvisories, valid[i])
		} else {
			updated++
		}
	}
	raised := 0
	if h.alerter != nil && len(newAdvisories) > 0 {
		n, err := h.alerter.ProcessNew(r.Context(), newAdvisories)
		if err != nil {
			response.InternalError(w, r, fmt.Errorf("漏洞情报提醒失败: %w", err))
			return
		}
		raised = n
	}
	h.recordAudit(r, p, "import", "MANUAL", "",
		auditSummary(map[string]interface{}{
			"received": len(req.Advisories), "inserted": inserted, "updated": updated,
			"invalid": len(rowErrs), "alerts_raised": raised,
		}),
		audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"received":        len(req.Advisories),
		"inserted":        inserted,
		"updated":         updated,
		"invalid":         len(rowErrs),
		"invalid_entries": rowErrs,
		"alerts_raised":   raised,
	})
}

// ---------- 应用技术栈映射 ----------

// ListTechAssets 列出全部应用及其技术标签。
func (h *Handler) ListTechAssets(w http.ResponseWriter, r *http.Request) {
	items, err := h.store.ListTechAssets(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": items})
}

type techAssetItem struct {
	ApplicationID string   `json:"application_id"`
	TechTags      []string `json:"tech_tags"`
}

type techAssetsRequest struct {
	Items []techAssetItem `json:"items"`
}

// PutTechAssets 整组替换应用技术栈映射（body 为全量目标态；未列出的应用清空标签）。
func (h *Handler) PutTechAssets(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req techAssetsRequest
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误或内容过大")
		return
	}
	if len(req.Items) > 1000 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "items 超过 1000 条上限")
		return
	}
	items := make([]TechAssetInput, 0, len(req.Items))
	seenApp := map[uuid.UUID]bool{}
	for i, in := range req.Items {
		appID, err := uuid.Parse(strings.TrimSpace(in.ApplicationID))
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				fmt.Sprintf("items[%d].application_id 不是合法 UUID", i))
			return
		}
		if seenApp[appID] {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				fmt.Sprintf("items[%d].application_id 重复: %s", i, appID))
			return
		}
		seenApp[appID] = true
		techs := make([]string, 0, len(in.TechTags))
		seenTech := map[string]bool{}
		for _, tag := range in.TechTags {
			tech := strings.ToLower(strings.TrimSpace(tag))
			if err := ValidateTechName(tech); err != nil {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
					fmt.Sprintf("items[%d]: %v", i, err))
				return
			}
			if seenTech[tech] {
				continue
			}
			seenTech[tech] = true
			techs = append(techs, tech)
		}
		if len(techs) > 20 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				fmt.Sprintf("items[%d].tech_tags 超过 20 项上限", i))
			return
		}
		items = append(items, TechAssetInput{ApplicationID: appID, TechTags: techs})
	}
	if err := h.store.ReplaceAllTechAssets(r.Context(), items); err != nil {
		if errors.Is(err, ErrInvalidInput) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
		response.InternalError(w, r, err)
		return
	}
	tagTotal := 0
	for _, it := range items {
		tagTotal += len(it.TechTags)
	}
	h.recordAudit(r, p, "replace_tech_assets", "application_technologies", "",
		auditSummary(map[string]interface{}{"apps": len(items), "tags": tagTotal}),
		audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"apps": len(items),
		"tags": tagTotal,
	})
}

// ---------- 订阅设置 ----------

// GetSettings 读取订阅设置。
func (h *Handler) GetSettings(w http.ResponseWriter, r *http.Request) {
	response.JSON(w, r, http.StatusOK, LoadSubscription(r.Context(), h.settings))
}

type settingsRequest struct {
	WatchTechs  []string `json:"watch_techs"`
	MinSeverity string   `json:"min_severity"`
	SyncEnabled bool     `json:"sync_enabled"`
}

// PutSettings 更新订阅设置（三键覆盖写入）。
func (h *Handler) PutSettings(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req settingsRequest
	if err := response.DecodeJSON(w, r, &req, 64*1024); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	sub := Subscription{
		WatchTechs:  req.WatchTechs,
		MinSeverity: req.MinSeverity,
		SyncEnabled: req.SyncEnabled,
	}
	if err := ValidateSubscription(&sub); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := SaveSubscription(r.Context(), h.writer, sub, p.UserID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update_settings", "system_settings", SettingsGroup,
		auditSummary(map[string]interface{}{
			"watch_techs": JoinWatchTechs(sub.WatchTechs), "min_severity": sub.MinSeverity,
			"sync_enabled": sub.SyncEnabled,
		}),
		audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, sub)
}

// ---------- 审计 ----------

// auditSummary 生成审计摘要 JSON（json.Marshal 保证转义正确；失败返回占位串不失联）。
func auditSummary(v map[string]interface{}) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return `{"error":"summary marshal failed"}`
	}
	return string(raw)
}

// recordAudit 记录漏洞情报写操作审计（失败进入 fallback 队列，不影响主流程）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objectType, objectID,
	afterSummary, result, failureReason, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "vuln_intel",
		Action:        action,
		ObjectType:    objectType,
		ObjectID:      objectID,
		ObjectName:    "漏洞情报",
		AfterSummary:  afterSummary,
		Result:        result,
		FailureReason: failureReason,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

// parsePositiveInt 解析正整数查询参数（非法/非正回落默认值）。
func parsePositiveInt(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return def
	}
	return n
}
