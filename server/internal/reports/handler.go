package reports

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/notify"
	"github.com/jiuzhang-waf/server/internal/product"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 报告系统处理器（模板 + 报告任务 + 定时计划）。
type Handler struct {
	store     *Store
	db        *pgxpool.Pool
	agg       *aggregations.Store
	audits    *audits.Service
	dataDir   string
	gen       *Generator
	scheduler *Scheduler
}

// NewHandler 创建报告处理器。
// dataDir 为 GATEWAY_DATA_DIR（报告文件写入其 reports/ 子目录）。
func NewHandler(store *Store, db *pgxpool.Pool, aggStore *aggregations.Store, auditSvc *audits.Service, dataDir string) *Handler {
	fontPath := DefaultFontPath()
	return &Handler{
		store:     store,
		db:        db,
		agg:       aggStore,
		audits:    auditSvc,
		dataDir:   dataDir,
		gen:       NewGenerator(store, db, aggStore, dataDir, fontPath, auditSvc),
		scheduler: NewScheduler(store, auditSvc),
	}
}

// SetNotifyStore 注入通知存储（定时计划邮件发送用，app 装配时调用）。
func (h *Handler) SetNotifyStore(ns *notify.Store) {
	h.gen.SetNotifyStore(ns)
}

// Generator 返回内部生成器（供 main.go 启动 Worker）。
func (h *Handler) Generator() *Generator {
	return h.gen
}

// Run 启动报告生成 Worker 与定时计划调度器（供 main.go 后台 goroutine 调用）。
func (h *Handler) Run(ctx context.Context, interval time.Duration) {
	go h.scheduler.Run(ctx)
	h.gen.Run(ctx, interval)
}

// RegisterRoutes 注册报告路由。authChain 为认证链（会话解析+认证+CSRF），
// 权限控制在路由层按权限点强制校验。
func (h *Handler) RegisterRoutes(mux *http.ServeMux, authChain func(http.Handler) http.Handler) {
	// 报告模板（写操作需 report_templates.manage）
	tplRead := requireAnyPermission("report_templates.manage", "reports.read", "reports.create")
	mux.Handle("GET /api/v1/report-templates", authChain(tplRead(http.HandlerFunc(h.TemplateList))))
	mux.Handle("POST /api/v1/report-templates", authChain(middleware.RequirePermission("report_templates.manage")(http.HandlerFunc(h.TemplateCreate))))
	mux.Handle("GET /api/v1/report-templates/{id}", authChain(tplRead(http.HandlerFunc(h.TemplateGet))))
	mux.Handle("PUT /api/v1/report-templates/{id}", authChain(middleware.RequirePermission("report_templates.manage")(http.HandlerFunc(h.TemplateUpdate))))
	mux.Handle("DELETE /api/v1/report-templates/{id}", authChain(middleware.RequirePermission("report_templates.manage")(http.HandlerFunc(h.TemplateDelete))))

	// 报告任务
	reportRead := requireAnyPermission("reports.read", "reports.read_audit")
	mux.Handle("GET /api/v1/reports", authChain(reportRead(http.HandlerFunc(h.List))))
	mux.Handle("POST /api/v1/reports", authChain(middleware.RequirePermission("reports.create")(http.HandlerFunc(h.Create))))
	mux.Handle("GET /api/v1/report-archives", authChain(reportRead(http.HandlerFunc(h.Archives))))
	mux.Handle("GET /api/v1/reports/{id}", authChain(reportRead(http.HandlerFunc(h.Get))))
	mux.Handle("POST /api/v1/reports/{id}/retry", authChain(middleware.RequirePermission("reports.create")(http.HandlerFunc(h.Retry))))
	mux.Handle("GET /api/v1/reports/{id}/preview", authChain(reportRead(http.HandlerFunc(h.Preview))))
	mux.Handle("GET /api/v1/reports/{id}/download", authChain(requireAnyPermission("reports.download", "reports.download_audit")(http.HandlerFunc(h.Download))))
	mux.Handle("DELETE /api/v1/reports/{id}", authChain(middleware.RequirePermission("reports.delete_own")(http.HandlerFunc(h.Delete))))

	// 定时报告计划（读：reports.read/read_audit；写：reports.create）
	mux.Handle("GET /api/v1/report-schedules", authChain(reportRead(http.HandlerFunc(h.ScheduleList))))
	mux.Handle("POST /api/v1/report-schedules", authChain(middleware.RequirePermission("reports.create")(http.HandlerFunc(h.ScheduleCreate))))
	mux.Handle("GET /api/v1/report-schedules/{id}", authChain(reportRead(http.HandlerFunc(h.ScheduleGet))))
	mux.Handle("PUT /api/v1/report-schedules/{id}", authChain(middleware.RequirePermission("reports.create")(http.HandlerFunc(h.ScheduleUpdate))))
	mux.Handle("DELETE /api/v1/report-schedules/{id}", authChain(middleware.RequirePermission("reports.create")(http.HandlerFunc(h.ScheduleDelete))))
	mux.Handle("POST /api/v1/report-schedules/{id}/run-now", authChain(middleware.RequirePermission("reports.create")(http.HandlerFunc(h.ScheduleRunNow))))
}

// requireAnyPermission 要求拥有任一权限点（路由层权限控制）。
func requireAnyPermission(perms ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := authz.PrincipalFrom(r.Context())
			if p == nil {
				response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录或会话已过期")
				return
			}
			for _, perm := range perms {
				if p.HasPermission(perm) {
					next.ServeHTTP(w, r)
					return
				}
			}
			response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "无权执行该操作")
		})
	}
}

// ---------- 模板管理 ----------

// TemplateList 模板列表。
func (h *Handler) TemplateList(w http.ResponseWriter, r *http.Request) {
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListTemplates(r.Context(), page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// TemplateGet 模板详情。
func (h *Handler) TemplateGet(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模板ID")
		return
	}
	t, err := h.store.GetTemplate(r.Context(), id)
	if err != nil {
		h.storeError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"template": t})
}

type templateRequest struct {
	Name           string          `json:"name"`
	CompanyName    string          `json:"company_name"`
	ProductName    string          `json:"product_name"`
	LogoText       string          `json:"logo_text"`
	HeaderText     string          `json:"header_text"`
	FooterText     string          `json:"footer_text"`
	ReportNoFormat string          `json:"report_no_format"`
	PreparedBy     string          `json:"prepared_by"`
	ReviewedBy     string          `json:"reviewed_by"`
	Description    string          `json:"description"`
	Sections       map[string]bool `json:"sections"`
}

func (req *templateRequest) toTemplate() *Template {
	return &Template{
		Name:           req.Name,
		CompanyName:    req.CompanyName,
		ProductName:    req.ProductName,
		LogoText:       req.LogoText,
		HeaderText:     req.HeaderText,
		FooterText:     req.FooterText,
		ReportNoFormat: req.ReportNoFormat,
		PreparedBy:     req.PreparedBy,
		ReviewedBy:     req.ReviewedBy,
		Description:    req.Description,
		Sections:       req.Sections,
	}
}

// TemplateCreate 创建模板。
func (h *Handler) TemplateCreate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req templateRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	t := req.toTemplate()
	if err := h.store.CreateTemplate(r.Context(), t, p.UserID); err != nil {
		h.storeError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create_template", t.ID.String(), t.Name, audits.ResultSuccess, audits.RiskLow, "report_template")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"template": t})
}

// TemplateUpdate 更新模板（内置模板禁止修改）。
func (h *Handler) TemplateUpdate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模板ID")
		return
	}
	var req templateRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	t := req.toTemplate()
	t.ID = id
	if err := h.store.UpdateTemplate(r.Context(), t, p.UserID); err != nil {
		h.storeError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update_template", id.String(), t.Name, audits.ResultSuccess, audits.RiskMedium, "report_template")
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "模板已更新"})
}

// TemplateDelete 删除模板（内置模板禁止删除）。
func (h *Handler) TemplateDelete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模板ID")
		return
	}
	t, err := h.store.GetTemplate(r.Context(), id)
	if err != nil {
		h.storeError(w, r, err)
		return
	}
	if err := h.store.DeleteTemplate(r.Context(), id); err != nil {
		h.storeError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete_template", id.String(), t.Name, audits.ResultSuccess, audits.RiskMedium, "report_template")
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "模板已删除"})
}

// ---------- 报告任务 ----------

// List 报告任务列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	reportType := r.URL.Query().Get("report_type")
	status := r.URL.Query().Get("status")
	if reportType != "" && !validReportType(reportType) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的报告类型")
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListJobs(r.Context(), reportType, status, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

type createReportRequest struct {
	ReportType       string      `json:"report_type"`
	ContentScope     string      `json:"content_scope"`
	IncludeAPIAssets bool        `json:"include_api_assets"`
	PageOrientation  string      `json:"page_orientation"`
	StartTime        *string     `json:"start_time"`
	EndTime          *string     `json:"end_time"`
	ApplicationIDs   []uuid.UUID `json:"application_ids"`
	TemplateID       *uuid.UUID  `json:"template_id"`
	Format           string      `json:"format"`
}

// Create 创建报告任务（DAILY=昨天全天 / WEEKLY=上周一至周日 / MONTHLY=上月 / CUSTOM 需起止；
// content_scope 内容范围 WAF/API/WAF_API，缺省 WAF_API）。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req createReportRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if !validReportType(req.ReportType) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的报告类型（DAILY/WEEKLY/MONTHLY/CUSTOM/API_ASSET/API_RISK/API_WEAK/API_SENS）")
		return
	}
	format := req.Format
	if format == "" {
		format = FormatHTML
	}
	if !validFormat(format) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的导出格式（html/pdf/docx）")
		return
	}
	if !validContentScope(req.ContentScope) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的内容范围（WAF/API/WAF_API）")
		return
	}
	scope := NormalizeContentScope(req.ContentScope)
	if !validPageOrientation(req.PageOrientation) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的纸张方向（P 竖向 / L 横向）")
		return
	}
	if ContentScopeIncludesAPI(scope) && !product.Load().APIDynamicProtectionEnabled() {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "当前环境未启用 API 动态防护，内容范围不能包含 API")
		return
	}
	start, end, err := parseTimeRange(req.ReportType, req.StartTime, req.EndTime)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if req.TemplateID != nil {
		if _, err := h.store.GetTemplate(r.Context(), *req.TemplateID); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "报告模板不存在")
			return
		}
	}
	job := &Job{
		ReportType:       req.ReportType,
		ContentScope:     scope,
		IncludeAPIAssets: req.IncludeAPIAssets,
		PageOrientation:  NormalizePageOrientation(req.PageOrientation),
		Start:            start,
		End:              end,
		ApplicationIDs:   req.ApplicationIDs,
		TemplateID:       req.TemplateID,
		Status:           StatusPending,
		FileFormat:       format,
		RequestedBy:      &p.UserID,
		RequestID:        response.RequestIDFrom(r),
	}
	if err := h.store.CreateJob(r.Context(), job); err != nil {
		h.storeError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", job.ID.String(), reportObjectName(job), audits.ResultSuccess, audits.RiskLow, "report_job")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"report": job})
}

// parseTimeRange 解析请求中的时间范围（CUSTOM 必须给出 RFC3339 起止）。
func parseTimeRange(reportType string, startStr, endStr *string) (time.Time, time.Time, error) {
	var start, end *time.Time
	if startStr != nil && *startStr != "" {
		t, err := time.Parse(time.RFC3339, *startStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("%w: 开始时间格式须为 RFC3339", ErrInvalidRange)
		}
		start = &t
	}
	if endStr != nil && *endStr != "" {
		t, err := time.Parse(time.RFC3339, *endStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("%w: 结束时间格式须为 RFC3339", ErrInvalidRange)
		}
		end = &t
	}
	return ComputeTimeRange(reportType, start, end, time.Now())
}

// Get 报告任务详情。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	job, ok := h.loadJob(w, r)
	if !ok {
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"report": job})
}

// Archives 报告归档列表（report_archives JOIN report_jobs）。
func (h *Handler) Archives(w http.ResponseWriter, r *http.Request) {
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListArchives(r.Context(), page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// Retry 重试失败/已取消的任务（重置为 PENDING 等待 Worker 拾取）。
func (h *Handler) Retry(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	job, ok := h.loadJob(w, r)
	if !ok {
		return
	}
	if job.Status != StatusFailed && job.Status != StatusCancelled {
		response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument, "仅失败或已取消的任务可重试")
		return
	}
	if err := h.store.ResetJobForRetry(r.Context(), job.ID); err != nil {
		h.storeError(w, r, err)
		return
	}
	h.recordAudit(r, p, "retry", job.ID.String(), reportObjectName(job), audits.ResultSuccess, audits.RiskLow, "report_job")
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "任务已重新排队"})
}

// canAccessReportFile 报告文件归属校验（Preview/Download 共用）：仅创建者本人或
// reports.download_audit 权限者可读取报告文件内容，防越权读取他人报告全文。
func canAccessReportFile(job *Job, p *authz.Principal) bool {
	isOwner := job.RequestedBy != nil && p != nil && *job.RequestedBy == p.UserID
	return isOwner || p.HasPermission("reports.download_audit")
}

// Preview 预览报告（SUCCESS 状态返回 HTML 内容；PDF 报告提示使用下载接口）。
// 与 Download 同一归属边界：仅本人或 reports.download_audit 权限者。
func (h *Handler) Preview(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	job, ok := h.loadJob(w, r)
	if !ok {
		return
	}
	// 归属校验：仅创建者本人或审计下载权限者（与 Download 一致）
	if !canAccessReportFile(job, p) {
		response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "仅可预览本人创建的报告")
		return
	}
	if job.Status != StatusSuccess {
		response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument, "报告尚未生成完成")
		return
	}
	if job.FileFormat == FormatPDF || job.FileFormat == FormatDOCX {
		response.JSON(w, r, http.StatusOK, map[string]string{"message": "PDF/Word 报告请使用下载接口获取"})
		return
	}
	if !ValidateReportFileName(job.FileReference, job.ID, job.FileFormat) {
		slog.Error("report file reference invalid", "job_id", job.ID, "ref", job.FileReference)
		response.Error(w, r, http.StatusInternalServerError, response.CodeInternalError, "报告文件引用异常")
		return
	}
	content, err := readReportFile(h.dataDir, job.FileReference)
	if err != nil {
		slog.Error("read report file failed", "job_id", job.ID, "error", err)
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "报告文件不存在")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

// Download 下载报告文件（仅本人或 reports.download_audit 权限者；含完整性与文件名校验、下载审计）。
func (h *Handler) Download(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	job, ok := h.loadJob(w, r)
	if !ok {
		return
	}
	// 归属校验：仅创建者本人或审计下载权限者
	if !canAccessReportFile(job, p) {
		response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "仅可下载本人创建的报告")
		return
	}
	if job.Status != StatusSuccess {
		response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument, "报告尚未生成完成")
		return
	}
	// 文件名安全校验（防路径穿越/任意下载）
	if !ValidateReportFileName(job.FileReference, job.ID, job.FileFormat) {
		slog.Error("report file reference invalid", "job_id", job.ID, "ref", job.FileReference)
		response.Error(w, r, http.StatusInternalServerError, response.CodeInternalError, "报告文件引用异常")
		return
	}
	content, err := readReportFile(h.dataDir, job.FileReference)
	if err != nil {
		slog.Error("read report file failed", "job_id", job.ID, "error", err)
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "报告文件不存在")
		return
	}
	// 完整性校验（sha256）
	if sha256Bytes(content) != job.FileHash {
		slog.Error("report file hash mismatch", "job_id", job.ID)
		response.Error(w, r, http.StatusInternalServerError, response.CodeInternalError, "报告文件完整性校验失败")
		return
	}
	contentType := "text/html; charset=utf-8"
	switch job.FileFormat {
	case FormatPDF:
		contentType = "application/pdf"
	case FormatDOCX:
		contentType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, job.FileReference))
	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(content)), 10))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
	h.recordAudit(r, p, "download", job.ID.String(), reportObjectName(job), audits.ResultSuccess, audits.RiskMedium, "report_job")
}

// Delete 删除报告（本人，或持 reports.delete_all 的管理者；同时删除报告文件并审计）。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	job, ok := h.loadJob(w, r)
	if !ok {
		return
	}
	// 归属校验：创建者本人或 delete_all 管理权限者（与 Download 的 download_audit 升级模式一致）
	isOwner := job.RequestedBy != nil && *job.RequestedBy == p.UserID
	if !isOwner && !p.HasPermission("reports.delete_all") {
		response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "仅可删除本人创建的报告")
		return
	}
	if err := h.store.DeleteJob(r.Context(), job.ID); err != nil {
		h.storeError(w, r, err)
		return
	}
	// 清理报告文件（失败仅记录日志：记录已删除，文件由后续清理机制兜底）
	if job.FileReference != "" {
		if err := removeReportFile(h.dataDir, job.FileReference); err != nil {
			slog.Error("remove report file failed", "job_id", job.ID, "error", err)
		}
	}
	h.recordAudit(r, p, "delete", job.ID.String(), reportObjectName(job), audits.ResultSuccess, audits.RiskMedium, "report_job")
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "报告已删除"})
}

// loadJob 解析路径ID并加载任务。
func (h *Handler) loadJob(w http.ResponseWriter, r *http.Request) (*Job, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的报告ID")
		return nil, false
	}
	job, err := h.store.GetJob(r.Context(), id)
	if err != nil {
		h.storeError(w, r, err)
		return nil, false
	}
	return job, true
}

// storeError 统一存储错误映射。
func (h *Handler) storeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "资源不存在")
	case errors.Is(err, ErrBuiltinTemplate):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "内置模板不允许修改或删除")
	case errors.Is(err, ErrInvalidState):
		response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument, "任务状态不允许该操作")
	case errors.Is(err, ErrInvalidInput):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
	default:
		response.InternalError(w, r, err)
	}
}

// reportObjectName 审计对象名。
func reportObjectName(j *Job) string {
	name := fmt.Sprintf("%s报告(%s)", j.ReportType, j.Start.UTC().Format("2006-01-02"))
	if j.ReportNo != "" {
		name = j.ReportNo
	}
	return name
}

// recordAudit 写入操作审计。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, result, risk, objType string) {
	if err := h.audits.Record(r.Context(), audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "reports",
		Action:       action,
		ObjectType:   objType,
		ObjectID:     objID,
		ObjectName:   objName,
		Result:       result,
		RiskLevel:    risk,
		RequestID:    response.RequestIDFrom(r),
	}); err != nil {
		slog.Error("record report audit failed", "action", action, "object_id", objID, "error", err)
	}
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
