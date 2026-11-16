// handler.go AI 定时运营任务 HTTP 处理器（计划 CRUD/启停/立即执行/执行记录查询）。
// 安全纪律：全部接口登录 + 权限点（api_ai.read / api_ai.execute）+ 参数校验
// （任务类型词表、cron 可解析、config 白名单）；写操作落操作审计；
// 立即执行经 Sweeper.RunNow（全局开关门控、RUNNING 防重入），任务只产出报告不变更业务。
package apiops

import (
	"context"
	"encoding/json"
	"errors"
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

// auditRecorder 操作审计记录接口（由 *audits.Service 实现；单测注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// Runner 立即执行接口（*Sweeper 实现；未装配时 run 返回 503）。
type Runner interface {
	RunNow(ctx context.Context, scheduleID uuid.UUID) (*Run, error)
}

// Handler AI 定时运营任务处理器。
type Handler struct {
	store  Repository
	audits auditRecorder
	runner Runner // nil 时立即执行返回 503
}

// NewHandler 创建处理器（audit 为 nil 时不写审计）。
func NewHandler(store Repository, audit *audits.Service) *Handler {
	h := &Handler{store: store}
	if audit != nil {
		h.audits = audit // 避免 typed-nil 接口导致 recordAudit 空调用
	}
	return h
}

// SetRunner 设置立即执行器（应用装配 Sweeper 时使用）。
func (h *Handler) SetRunner(r Runner) *Handler { h.runner = r; return h }

// ---------- 任务类型 ----------

// ListTaskTypes GET /task-types（内置任务类型词表与说明）。
func (h *Handler) ListTaskTypes(w http.ResponseWriter, r *http.Request) {
	response.JSON(w, r, http.StatusOK, map[string]any{"items": TaskTypeInfos()})
}

// ---------- 计划 ----------

// ListSchedules GET /schedules（过滤 task_type/enabled + 分页）。
func (h *Handler) ListSchedules(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := ScheduleFilter{
		TaskType: strings.ToUpper(strings.TrimSpace(q.Get("task_type"))),
		Page:     queryInt(r, "page", 1),
		PageSize: queryPageSize(r, 20),
	}
	if f.TaskType != "" && !ValidTaskType(f.TaskType) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 task_type 取值")
		return
	}
	if raw := strings.TrimSpace(q.Get("enabled")); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 enabled 取值（true/false）")
			return
		}
		f.Enabled = &v
	}
	list, total, err := h.store.ListSchedules(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// scheduleRequest 计划创建/更新请求体。
type scheduleRequest struct {
	TaskType string          `json:"task_type"`
	Name     string          `json:"name"`
	CronExpr string          `json:"cron_expr"`
	Enabled  *bool           `json:"enabled"` // 创建时可指定（缺省 false）；更新忽略此字段（走启停接口）
	Config   json.RawMessage `json:"config"`
}

// CreateSchedule POST /schedules。
func (h *Handler) CreateSchedule(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req scheduleRequest
	if !decodeRequired(w, r, &req) {
		return
	}
	req.TaskType = strings.ToUpper(strings.TrimSpace(req.TaskType))
	if !ValidTaskType(req.TaskType) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 task_type 取值（内置五种，见 /task-types）")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.CronExpr = strings.TrimSpace(req.CronExpr)
	if err := ValidateScheduleInput(req.Name, req.CronExpr); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if _, err := ParseTaskConfig(req.Config); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	sc := &Schedule{
		TaskType: req.TaskType,
		Name:     req.Name,
		CronExpr: req.CronExpr,
		Config:   normalizeConfig(req.Config),
	}
	if p != nil {
		uid := p.UserID
		sc.CreatedBy = &uid
	}
	if req.Enabled != nil && *req.Enabled {
		next, err := NextCronAfter(sc.CronExpr, time.Now())
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
		sc.Enabled = true
		sc.NextRunAt = &next
	}
	if err := h.store.CreateSchedule(r.Context(), sc); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "ai_schedule_create", sc.ID.String(), sc.Name, "",
		"创建AI运营计划「"+sc.Name+"」（"+sc.TaskType+"，cron "+sc.CronExpr+"）", audits.RiskLow)
	response.JSON(w, r, http.StatusCreated, map[string]any{"schedule": sc})
}

// GetSchedule GET /schedules/{id}。
func (h *Handler) GetSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	sc, err := h.store.GetSchedule(r.Context(), id)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"schedule": sc})
}

// UpdateSchedule PUT /schedules/{id}（name/cron_expr/config；task_type 不可变；启停走专用接口）。
func (h *Handler) UpdateSchedule(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	sc, err := h.store.GetSchedule(r.Context(), id)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	var req scheduleRequest
	if !decodeRequired(w, r, &req) {
		return
	}
	if raw := strings.TrimSpace(string(req.TaskType)); raw != "" && !strings.EqualFold(raw, sc.TaskType) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, ErrTaskTypeImmutable.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.CronExpr = strings.TrimSpace(req.CronExpr)
	if err := ValidateScheduleInput(req.Name, req.CronExpr); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if _, err := ParseTaskConfig(req.Config); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	before := "原计划「" + sc.Name + "」（cron " + sc.CronExpr + "）"
	sc.Name = req.Name
	sc.CronExpr = req.CronExpr
	sc.Config = normalizeConfig(req.Config)
	// cron 变更影响排期：启用中的计划按新表达式重算游标（停用保持无游标）
	if sc.Enabled {
		next, err := NextCronAfter(sc.CronExpr, time.Now())
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
		sc.NextRunAt = &next
	} else {
		sc.NextRunAt = nil
	}
	if err := h.store.UpdateSchedule(r.Context(), sc); err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "ai_schedule_update", sc.ID.String(), sc.Name, before,
		"更新AI运营计划「"+sc.Name+"」（cron "+sc.CronExpr+"）", audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{"schedule": sc})
}

// DeleteSchedule DELETE /schedules/{id}（级联删除执行记录）。
func (h *Handler) DeleteSchedule(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	sc, err := h.store.GetSchedule(r.Context(), id)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	if err := h.store.DeleteSchedule(r.Context(), id); err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "ai_schedule_delete", id.String(), sc.Name,
		"删除前计划「"+sc.Name+"」（"+sc.TaskType+"，cron "+sc.CronExpr+"）", "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"deleted": true})
}

// ---------- 启停 ----------

// setEnabled 启停公共路径（启用时按 cron 重算到期游标，停用清空）。
// 手动启用同时复位连续失败熔断状态（计数/熔断时间/原因清零，store 层同事务），
// 审计摘要如实标注熔断复位——熔断后的恢复动作必须可追溯。
func (h *Handler) setEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	sc, err := h.store.GetSchedule(r.Context(), id)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	// 启用前快照熔断状态（复位事实入审计）
	circuitWasOpen := enabled && sc.CircuitOpenedAt != nil
	var next *time.Time
	if enabled {
		n, err := NextCronAfter(sc.CronExpr, time.Now())
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
		next = &n
	}
	sc, err = h.store.SetScheduleEnabled(r.Context(), id, enabled, next)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	action, desc := "ai_schedule_enable", "启用"
	if !enabled {
		action, desc = "ai_schedule_disable", "停用"
	}
	after := desc + "AI运营计划「" + sc.Name + "」"
	if circuitWasOpen {
		after += "（连续失败熔断状态已复位）"
	}
	h.recordAudit(r, p, action, id.String(), sc.Name, "", after, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{"schedule": sc})
}

// EnableSchedule POST /schedules/{id}/enable。
func (h *Handler) EnableSchedule(w http.ResponseWriter, r *http.Request) { h.setEnabled(w, r, true) }

// DisableSchedule POST /schedules/{id}/disable（停用立即生效，下轮不再触发）。
func (h *Handler) DisableSchedule(w http.ResponseWriter, r *http.Request) { h.setEnabled(w, r, false) }

// ---------- 立即执行 ----------

// RunSchedule POST /schedules/{id}/run（手动触发一次，不改变排期；同步执行并返回执行记录）。
func (h *Handler) RunSchedule(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if h.runner == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "调度器未装配，立即执行不可用")
		return
	}
	run, err := h.runner.RunNow(r.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, ErrSchedulesDisabled):
			response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable,
				"AI 运营定时任务总开关未启用（系统设置 api_ai_ops.schedules_enabled）")
		case errors.Is(err, ErrRunConflict):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, ErrRunConflict.Error())
		default:
			writeStoreError(w, r, err)
		}
		return
	}
	name := ""
	if sc, err := h.store.GetSchedule(r.Context(), id); err == nil {
		name = sc.Name
	}
	h.recordAudit(r, p, "ai_schedule_run", id.String(), name, "",
		"手动触发AI运营计划「"+name+"」立即执行（"+run.Status+"）", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"run": run})
}

// ---------- 执行记录 ----------

// ListRuns GET /schedules/{id}/runs（分页）。
func (h *Handler) ListRuns(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if _, err := h.store.GetSchedule(r.Context(), id); err != nil {
		writeStoreError(w, r, err)
		return
	}
	page, pageSize := queryInt(r, "page", 1), queryPageSize(r, 20)
	list, total, err := h.store.ListRuns(r.Context(), id, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// GetRun GET /runs/{id}（执行记录详情：摘要 + 结构化报告）。
func (h *Handler) GetRun(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	run, err := h.store.GetRun(r.Context(), id)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"run": run})
}

// ---------- 工具 ----------

// parseID 解析路径参数 id（UUID）。
func parseID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 ID")
		return uuid.Nil, false
	}
	return id, true
}

// writeStoreError 仓储错误映射（NotFound → 404，其余 500；包装链经 errors.Is 判定）。
func writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrScheduleNotFound) || errors.Is(err, ErrRunNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, err.Error())
		return
	}
	response.InternalError(w, r, err)
}

// decodeRequired 解码必填 JSON 请求体（非法/为空返回 400；DisallowUnknownFields 白名单键）。
func decodeRequired(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := response.DecodeJSON(w, r, v, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return false
	}
	return true
}

// queryPageSize 分页大小（夹取 ≤100，非法回退默认值；与兄弟包上限口径一致）。
func queryPageSize(r *http.Request, def int) int {
	n := queryInt(r, "page_size", def)
	if n > 100 {
		n = 100
	}
	return n
}

// queryInt 查询参数整型（正数，非法回退默认值）。
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

// recordAudit 写操作审计（未注入或无操作者上下文时跳过，不影响主流程）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, before, after, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_ai_ops",
		Action:        action,
		ObjectType:    "api_ai_schedule",
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        audits.ResultSuccess,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}
