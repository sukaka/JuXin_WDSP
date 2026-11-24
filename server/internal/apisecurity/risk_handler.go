// risk_handler.go API 风险中心 HTTP 处理器（详情/降噪聚合/处置流转）。
// 状态机与词表见 risk.go；全部写操作带操作审计，权限点在 routes.go 强制校验。
package apisecurity

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 处置备注/说明长度上限（不静默截断，超长 400；与 apiweakness noteOK 同一纪律）。
const riskNoteMaxRunes = 512

// RiskSummary GET /api/v1/api-security/findings/summary
// 降噪聚合三视图（主体/端点/类型），各桶含 count、hits、max_severity、last_seen_at。
func (h *Handler) RiskSummary(w http.ResponseWriter, r *http.Request) {
	if h.risk == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "风险中心未装配")
		return
	}
	sum, err := h.risk.SummarizeFindings(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, sum)
}

// RiskFindingDetail GET /api/v1/api-security/findings/{id}
// 风险详情：evidence 为生产方落库时已脱敏的证据（字段名/粗类型词表/约束名），
// 原样返回不再二次处理；related_request_ids 来源：api_runtime_events 按
// endpoint_key（IDENTITY 主体附带身份指纹）点查最近事件——dedup upsert 只保留
// 首次 request_id，故为「同端点（同身份）近期请求」近似关联，非精确命中回放。
func (h *Handler) RiskFindingDetail(w http.ResponseWriter, r *http.Request) {
	if h.risk == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "风险中心未装配")
		return
	}
	id, ok := riskPathID(w, r)
	if !ok {
		return
	}
	f, err := h.risk.GetFinding(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "风险发现不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	related, err := h.risk.ListRelatedRequestIDs(r.Context(), f.EndpointKey, f.SubjectType, f.SubjectID, riskRelatedLimit)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"finding":              f,
		"related_request_ids":  related,
		"related_request_note": "同 API（认证身份主体附带身份指纹）近期运行时事件的请求 ID，近似关联，非精确命中回放",
	})
}

// ---------- 处置流转 ----------

// riskNoteRequest 仅备注的处置请求体（confirm/start/ignore/archive）。
type riskNoteRequest struct {
	Note string `json:"note"`
}

// RiskConfirm POST /api/v1/api-security/findings/{id}/confirm（NEW → CONFIRMED）。
func (h *Handler) RiskConfirm(w http.ResponseWriter, r *http.Request) {
	h.riskNoteTransition(w, r, RiskActionConfirm, "confirm")
}

// RiskStart POST /api/v1/api-security/findings/{id}/start（CONFIRMED → IN_PROGRESS）。
func (h *Handler) RiskStart(w http.ResponseWriter, r *http.Request) {
	h.riskNoteTransition(w, r, RiskActionStart, "start")
}

// riskResolveRequest 解决请求体（resolution 必填）。
type riskResolveRequest struct {
	Resolution string `json:"resolution"`
}

// RiskResolve POST /api/v1/api-security/findings/{id}/resolve（CONFIRMED/IN_PROGRESS → RESOLVED）。
func (h *Handler) RiskResolve(w http.ResponseWriter, r *http.Request) {
	var req riskResolveRequest
	if !decodeRiskRequired(w, r, &req) {
		return
	}
	note, ok := riskRequiredNoteOK(w, r, req.Resolution, "resolution")
	if !ok {
		return
	}
	h.doRiskTransition(w, r, RiskActionResolve, RiskHandleInput{Note: note}, "resolve")
}

// riskFalsePositiveRequest 误报请求体（reason 必填）。
type riskFalsePositiveRequest struct {
	Reason string `json:"reason"`
}

// RiskFalsePositive POST /api/v1/api-security/findings/{id}/false-positive
// （NEW/CONFIRMED/IN_PROGRESS → FALSE_POSITIVE）。
func (h *Handler) RiskFalsePositive(w http.ResponseWriter, r *http.Request) {
	var req riskFalsePositiveRequest
	if !decodeRiskRequired(w, r, &req) {
		return
	}
	note, ok := riskRequiredNoteOK(w, r, req.Reason, "reason")
	if !ok {
		return
	}
	h.doRiskTransition(w, r, RiskActionFalsePositive, RiskHandleInput{Note: note}, "false_positive")
}

// RiskIgnore POST /api/v1/api-security/findings/{id}/ignore（NEW/CONFIRMED/IN_PROGRESS → IGNORED）。
func (h *Handler) RiskIgnore(w http.ResponseWriter, r *http.Request) {
	h.riskNoteTransition(w, r, RiskActionIgnore, "ignore")
}

// RiskArchive POST /api/v1/api-security/findings/{id}/archive
// （RESOLVED/FALSE_POSITIVE/IGNORED → ARCHIVED，终态）。
func (h *Handler) RiskArchive(w http.ResponseWriter, r *http.Request) {
	h.riskNoteTransition(w, r, RiskActionArchive, "archive")
}

// riskNoteTransition 仅备注流转的公共入口（confirm/start/ignore/archive；body 可空）。
func (h *Handler) riskNoteTransition(w http.ResponseWriter, r *http.Request, action, auditAction string) {
	var req riskNoteRequest
	if !decodeRiskOptional(w, r, &req) {
		return
	}
	note, ok := riskNoteOK(w, r, req.Note)
	if !ok {
		return
	}
	h.doRiskTransition(w, r, action, RiskHandleInput{Note: note}, auditAction)
}

// doRiskTransition 处置流转公共路径：读取现状 → 状态机流转 → 审计 → 响应。
func (h *Handler) doRiskTransition(w http.ResponseWriter, r *http.Request, action string, in RiskHandleInput, auditAction string) {
	p := authz.PrincipalFrom(r.Context())
	if h.risk == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "风险中心未装配")
		return
	}
	id, ok := riskPathID(w, r)
	if !ok {
		return
	}
	before, err := h.risk.GetFinding(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "风险发现不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if p != nil {
		in.Actor = p.Username
	}
	updated, err := h.risk.TransitionFinding(r.Context(), id, action, in)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "风险发现不存在")
		return
	}
	if errors.Is(err, ErrInvalidRiskTransition) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("当前状态 %s 不允许该操作", before.Status))
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, auditAction, "api_runtime_finding", id.String(),
		fmt.Sprintf("%s/%s", updated.FindingType, updated.Severity),
		fmt.Sprintf("status=%s", before.Status), fmt.Sprintf("status=%s", updated.Status),
		audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"finding": updated})
}

// ---------- 通用 ----------

// riskPathID 解析路径参数 id（非法返回 400）。
func riskPathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的风险发现ID")
		return uuid.Nil, false
	}
	return id, true
}

// decodeRiskOptional 解码可选 JSON 请求体（空 body 视为零值；非法 JSON 返回 400）。
func decodeRiskOptional(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Body == nil || r.ContentLength == 0 {
		return true
	}
	return decodeRiskRequired(w, r, v)
}

// decodeRiskRequired 解码必填 JSON 请求体（非法/为空返回 400）。
func decodeRiskRequired(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := response.DecodeJSON(w, r, v, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return false
	}
	return true
}

// riskNoteOK 校验可选备注长度（超过 riskNoteMaxRunes 返回 400）；返回归一化后的备注。
func riskNoteOK(w http.ResponseWriter, r *http.Request, note string) (string, bool) {
	note = strings.TrimSpace(note)
	if utf8.RuneCountInString(note) > riskNoteMaxRunes {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("note 长度不能超过 %d 字符", riskNoteMaxRunes))
		return "", false
	}
	return note, true
}

// riskRequiredNoteOK 校验必填说明（resolve 的 resolution / false-positive 的 reason）：
// 去空白后必填且不超过 riskNoteMaxRunes。
func riskRequiredNoteOK(w http.ResponseWriter, r *http.Request, note, field string) (string, bool) {
	note = strings.TrimSpace(note)
	if note == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, field+" 必填")
		return "", false
	}
	if utf8.RuneCountInString(note) > riskNoteMaxRunes {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("%s 长度不能超过 %d 字符", field, riskNoteMaxRunes))
		return "", false
	}
	return note, true
}
