package reports

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/product"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 定时报告计划接口：列表/详情/创建/更新/删除/立即执行。
// 权限：读 = reports.read / reports.read_audit；写 = reports.create（路由层强制）。

type scheduleRequest struct {
	Name             string      `json:"name"`
	ReportType       string      `json:"report_type"`
	ContentScope     string      `json:"content_scope"`
	ApplicationIDs   []uuid.UUID `json:"application_ids"`
	TemplateID       *uuid.UUID  `json:"template_id"`
	FileFormat       string      `json:"file_format"`
	IncludeAPIAssets bool        `json:"include_api_assets"`
	PageOrientation  string      `json:"page_orientation"`
	TimeOfDay        string      `json:"time_of_day"`
	DayOfWeek        int         `json:"day_of_week"`
	DayOfMonth       int         `json:"day_of_month"`
	SendEmail        bool        `json:"send_email"`
	Emails           []string    `json:"emails"`
	Enabled          *bool       `json:"enabled"`
}

func (req *scheduleRequest) toSchedule() *ReportSchedule {
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	return &ReportSchedule{
		Name:             req.Name,
		ReportType:       req.ReportType,
		ContentScope:     req.ContentScope,
		ApplicationIDs:   req.ApplicationIDs,
		TemplateID:       req.TemplateID,
		FileFormat:       req.FileFormat,
		IncludeAPIAssets: req.IncludeAPIAssets,
		PageOrientation:  req.PageOrientation,
		TimeOfDay:        req.TimeOfDay,
		DayOfWeek:        req.DayOfWeek,
		DayOfMonth:       req.DayOfMonth,
		SendEmail:        req.SendEmail,
		Emails:           req.Emails,
		Enabled:          enabled,
	}
}

// validateScopeGate 内容范围含 API 时的环境门控（与报告任务创建一致）。
func validateScopeGate(sch *ReportSchedule) bool {
	return ContentScopeIncludesAPI(sch.ContentScope) && !product.Load().APIDynamicProtectionEnabled()
}

// ScheduleList 计划列表。
func (h *Handler) ScheduleList(w http.ResponseWriter, r *http.Request) {
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListSchedules(r.Context(), page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// ScheduleGet 计划详情。
func (h *Handler) ScheduleGet(w http.ResponseWriter, r *http.Request) {
	sch, ok := h.loadSchedule(w, r)
	if !ok {
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"schedule": sch})
}

// ScheduleCreate 创建计划。
func (h *Handler) ScheduleCreate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req scheduleRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	sch := req.toSchedule()
	if err := sch.Validate(); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if validateScopeGate(sch) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "当前环境未启用 API 动态防护，内容范围不能包含 API")
		return
	}
	if sch.TemplateID != nil {
		if _, err := h.store.GetTemplate(r.Context(), *sch.TemplateID); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "报告模板不存在")
			return
		}
	}
	if err := h.store.CreateSchedule(r.Context(), sch, p.UserID); err != nil {
		h.storeError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create_schedule", sch.ID.String(), sch.Name, audits.ResultSuccess, audits.RiskLow, "report_schedule")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"schedule": sch})
}

// ScheduleUpdate 更新计划。
func (h *Handler) ScheduleUpdate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的计划ID")
		return
	}
	var req scheduleRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	sch := req.toSchedule()
	sch.ID = id
	if err := sch.Validate(); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if validateScopeGate(sch) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "当前环境未启用 API 动态防护，内容范围不能包含 API")
		return
	}
	if sch.TemplateID != nil {
		if _, err := h.store.GetTemplate(r.Context(), *sch.TemplateID); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "报告模板不存在")
			return
		}
	}
	if err := h.store.UpdateSchedule(r.Context(), sch); err != nil {
		h.storeError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update_schedule", id.String(), sch.Name, audits.ResultSuccess, audits.RiskMedium, "report_schedule")
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "计划已更新"})
}

// ScheduleDelete 删除计划。
func (h *Handler) ScheduleDelete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	sch, ok := h.loadSchedule(w, r)
	if !ok {
		return
	}
	if err := h.store.DeleteSchedule(r.Context(), sch.ID); err != nil {
		h.storeError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete_schedule", sch.ID.String(), sch.Name, audits.ResultSuccess, audits.RiskMedium, "report_schedule")
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "计划已删除"})
}

// ScheduleRunNow 立即触发一次（标记到期，交调度器下一轮拾取）。
func (h *Handler) ScheduleRunNow(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	sch, ok := h.loadSchedule(w, r)
	if !ok {
		return
	}
	if err := h.store.MarkScheduleDueNow(r.Context(), sch.ID); err != nil {
		h.storeError(w, r, err)
		return
	}
	h.recordAudit(r, p, "run_now", sch.ID.String(), sch.Name, audits.ResultSuccess, audits.RiskLow, "report_schedule")
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "已加入执行队列，报告生成后将按计划发送邮件"})
}

// loadSchedule 解析路径 ID 并加载计划。
func (h *Handler) loadSchedule(w http.ResponseWriter, r *http.Request) (*ReportSchedule, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的计划ID")
		return nil, false
	}
	sch, err := h.store.GetSchedule(r.Context(), id)
	if err != nil {
		h.storeError(w, r, err)
		return nil, false
	}
	return sch, true
}
