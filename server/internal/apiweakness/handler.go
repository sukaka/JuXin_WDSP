// handler.go API 弱点中心 HTTP 处理器（列表/详情/生命周期流转）。
package apiweakness

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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

// Handler 弱点中心处理器。
type Handler struct {
	store  Repository
	audits auditRecorder
}

// NewHandler 创建处理器。
func NewHandler(store Repository, audit *audits.Service) *Handler {
	return &Handler{store: store, audits: audit}
}

// ---------- 查询 ----------

// List GET /api/v1/api-security/weaknesses
// 过滤 status/severity/category/endpoint_id + 分页。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := ListFilter{
		Status:   strings.ToUpper(strings.TrimSpace(q.Get("status"))),
		Severity: strings.ToUpper(strings.TrimSpace(q.Get("severity"))),
		Category: strings.ToUpper(strings.TrimSpace(q.Get("category"))),
		Page:     queryInt(r, "page", 1),
		PageSize: queryInt(r, "page_size", 20),
	}
	if f.Status != "" && !IsValidStatus(f.Status) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 status 取值")
		return
	}
	if f.Severity != "" && !IsValidSeverity(f.Severity) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 severity 取值（INFO/LOW/MEDIUM/HIGH/CRITICAL）")
		return
	}
	switch f.Category {
	case "", CategoryAuthn, CategoryAuthz, CategoryLifecycle, CategorySensitive, CategorySchema:
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 category 取值（AUTHN/AUTHZ/LIFECYCLE/SENSITIVE/SCHEMA）")
		return
	}
	if raw := strings.TrimSpace(q.Get("endpoint_id")); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的接口ID")
			return
		}
		f.EndpointID = &id
	}
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Detail GET /api/v1/api-security/weaknesses/{id}
// 弱点详情 + 整改/复测历史（api_weakness_actions，最多 100 条）。
func (h *Handler) Detail(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	weakness, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "弱点不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	actions, _, err := h.store.ListActions(r.Context(), id, 1, 100)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"weakness": weakness,
		"actions":  actions,
	})
}

// ---------- 生命周期流转 ----------

// noteRequest 仅备注的请求体（confirm/fixed/ignore/archive）。
type noteRequest struct {
	Note string `json:"note"`
}

// Confirm POST /api/v1/api-security/weaknesses/{id}/confirm（NEW → CONFIRMED）。
func (h *Handler) Confirm(w http.ResponseWriter, r *http.Request) {
	h.noteTransition(w, r, ActionConfirm, "confirm")
}

// assignRequest 指派请求体。
type assignRequest struct {
	Owner   string     `json:"owner"`
	DueDate *time.Time `json:"due_date"`
	Note    string     `json:"note"`
}

// Assign POST /api/v1/api-security/weaknesses/{id}/assign（CONFIRMED/TO_FIX/REPRODUCED → TO_FIX）。
func (h *Handler) Assign(w http.ResponseWriter, r *http.Request) {
	var req assignRequest
	if !decodeRequired(w, r, &req) {
		return
	}
	owner := strings.TrimSpace(req.Owner)
	if owner == "" || utf8.RuneCountInString(owner) > 128 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "owner 必填且不超过 128 字符")
		return
	}
	note, ok := noteOK(w, r, req.Note)
	if !ok {
		return
	}
	h.doTransition(w, r, ActionAssign,
		TransitionInput{Owner: owner, DueDate: req.DueDate, Note: note}, "assign", audits.RiskMedium)
}

// Fixed POST /api/v1/api-security/weaknesses/{id}/fixed（TO_FIX → FIXED）。
func (h *Handler) Fixed(w http.ResponseWriter, r *http.Request) {
	h.noteTransition(w, r, ActionMarkFixed, "fixed")
}

// retestRequest 复测请求体。
type retestRequest struct {
	Result string `json:"result"`
	Note   string `json:"note"`
}

// Retest POST /api/v1/api-security/weaknesses/{id}/retest
// result=PASS → ARCHIVED（复测通过关闭）；result=FAIL → REPRODUCED（复测未通过）。
func (h *Handler) Retest(w http.ResponseWriter, r *http.Request) {
	var req retestRequest
	if !decodeRequired(w, r, &req) {
		return
	}
	var action string
	switch strings.ToUpper(strings.TrimSpace(req.Result)) {
	case RetestPass:
		action = ActionRetestPass
	case RetestFail:
		action = ActionRetestFail
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "result 必填（PASS/FAIL）")
		return
	}
	note, ok := noteOK(w, r, req.Note)
	if !ok {
		return
	}
	h.doTransition(w, r, action, TransitionInput{Note: note}, "retest", audits.RiskMedium)
}

// Ignore POST /api/v1/api-security/weaknesses/{id}/ignore（接受风险/误报 → IGNORED）。
func (h *Handler) Ignore(w http.ResponseWriter, r *http.Request) {
	h.noteTransition(w, r, ActionIgnore, "ignore")
}

// Archive POST /api/v1/api-security/weaknesses/{id}/archive（人工归档关闭 → ARCHIVED）。
func (h *Handler) Archive(w http.ResponseWriter, r *http.Request) {
	h.noteTransition(w, r, ActionArchive, "archive")
}

// noteTransition 仅备注流转的公共入口（confirm/fixed/ignore/archive；body 可空）。
func (h *Handler) noteTransition(w http.ResponseWriter, r *http.Request, action, auditAction string) {
	var req noteRequest
	if !decodeOptional(w, r, &req) {
		return
	}
	note, ok := noteOK(w, r, req.Note)
	if !ok {
		return
	}
	h.doTransition(w, r, action, TransitionInput{Note: note}, auditAction, audits.RiskMedium)
}

// doTransition 生命周期流转公共路径：读取现状 → 状态机流转 → 审计 → 响应。
func (h *Handler) doTransition(w http.ResponseWriter, r *http.Request, action string, in TransitionInput, auditAction, risk string) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "弱点不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if p != nil {
		in.Actor = p.Username
	}
	updated, err := h.store.Transition(r.Context(), id, action, in)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "弱点不存在")
		return
	}
	if errors.Is(err, ErrInvalidTransition) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("当前状态 %s 不允许该操作", before.Status))
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, auditAction, id.String(), before.WeaknessCode,
		fmt.Sprintf("status=%s", before.Status), fmt.Sprintf("status=%s", updated.Status),
		audits.ResultSuccess, risk)
	response.JSON(w, r, http.StatusOK, map[string]any{"weakness": updated})
}

// ---------- 通用 ----------

// parsePathID 解析路径参数 id（非法返回 400）。
func parsePathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的弱点ID")
		return uuid.Nil, false
	}
	return id, true
}

// decodeOptional 解码可选 JSON 请求体（空 body 视为零值；非法 JSON 返回 400）。
func decodeOptional(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Body == nil || r.ContentLength == 0 {
		return true
	}
	return decodeRequired(w, r, v)
}

// decodeRequired 解码必填 JSON 请求体（非法/为空返回 400）。
func decodeRequired(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := response.DecodeJSON(w, r, v, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return false
	}
	return true
}

// noteOK 校验备注长度（超过 512 字符返回 400，不静默截断）；返回归一化后的备注。
func noteOK(w http.ResponseWriter, r *http.Request, note string) (string, bool) {
	note = strings.TrimSpace(note)
	if utf8.RuneCountInString(note) > 512 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "note 长度不能超过 512 字符")
		return "", false
	}
	return note, true
}

// recordAudit 写操作审计（构造注入 audits.Service；未注入或无操作者上下文时跳过，不影响主流程）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, before, after, result, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_security",
		Action:        action,
		ObjectType:    "api_weakness",
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        result,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
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
