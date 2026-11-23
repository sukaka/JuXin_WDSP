package urlwhitelists

import (
	"errors"
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

// Handler 是 URL 白名单规则 HTTP 处理器。
type Handler struct {
	store  *Store
	audits *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(store *Store, au *audits.Service) *Handler {
	return &Handler{store: store, audits: au}
}

// List 规则列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f, err := listFilterFrom(r)
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
		list = []Rule{}
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Get 规则详情。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	rule, ok := h.getRule(w, r)
	if !ok {
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"rule": rule})
}

type ruleRequest struct {
	Name           string     `json:"name"`
	ScopeType      string     `json:"scope_type"`
	ApplicationID  *uuid.UUID `json:"application_id"`
	MatchType      string     `json:"match_type"`
	URIPattern     string     `json:"uri_pattern"`
	Methods        []string   `json:"methods"`
	Priority       *int       `json:"priority"`
	ValidityType   string     `json:"validity_type"`
	EffectiveFrom  *string    `json:"effective_from"`
	EffectiveUntil *string    `json:"effective_until"`
	Reason         string     `json:"reason"`
	SourceType     string     `json:"source_type"`
	SourceEventID  *uuid.UUID `json:"source_event_id"`
}

func (req *ruleRequest) toCreateInput() (CreateInput, error) {
	in := CreateInput{
		Name:          req.Name,
		ScopeType:     req.ScopeType,
		ApplicationID: req.ApplicationID,
		MatchType:     req.MatchType,
		URIPattern:    req.URIPattern,
		Methods:       req.Methods,
		ValidityType:  req.ValidityType,
		Reason:        req.Reason,
		SourceType:    req.SourceType,
		SourceEventID: req.SourceEventID,
	}
	if req.Priority != nil {
		in.Priority = *req.Priority
	}
	if req.EffectiveFrom != nil && *req.EffectiveFrom != "" {
		t, err := parseTimeFlex(*req.EffectiveFrom)
		if err != nil {
			return in, fmt.Errorf("effective_from: %w", err)
		}
		in.EffectiveFrom = &t
	}
	if req.EffectiveUntil != nil && *req.EffectiveUntil != "" {
		t, err := parseTimeFlex(*req.EffectiveUntil)
		if err != nil {
			return in, fmt.Errorf("effective_until: %w", err)
		}
		in.EffectiveUntil = &t
	}
	return in, nil
}

// Create 新建 URL 白名单规则。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req ruleRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	in, err := req.toCreateInput()
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := ValidateInput(&in, time.Now()); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if in.SourceType == SourceSecurityEvent {
		exists, err := h.store.EventExists(r.Context(), *in.SourceEventID)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		if !exists {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "来源安全事件不存在")
			return
		}
	}
	rule, err := h.store.Create(r.Context(), in, p.UserID)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", rule.ID.String(), rule.Name, "", ruleSummary(rule),
		audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"rule": rule})
}

type updateRuleRequest struct {
	Name           string   `json:"name"`
	MatchType      string   `json:"match_type"`
	URIPattern     string   `json:"uri_pattern"`
	Methods        []string `json:"methods"`
	Priority       *int     `json:"priority"`
	ValidityType   string   `json:"validity_type"`
	EffectiveFrom  *string  `json:"effective_from"`
	EffectiveUntil *string  `json:"effective_until"`
	Reason         string   `json:"reason"`
	Version        int      `json:"version"`
}

// Update 更新规则（乐观锁）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	cur, ok := h.getRule(w, r)
	if !ok {
		return
	}
	var req updateRuleRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Version != cur.Version {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "规则已被其他人修改，请刷新后重试")
		return
	}
	in := UpdateInput{
		ID:           cur.ID,
		Version:      req.Version,
		Name:         req.Name,
		MatchType:    req.MatchType,
		URIPattern:   req.URIPattern,
		Methods:      req.Methods,
		Priority:     cur.Priority,
		ValidityType: req.ValidityType,
		Reason:       req.Reason,
	}
	if req.Priority != nil {
		in.Priority = *req.Priority
	}
	if req.EffectiveFrom != nil && *req.EffectiveFrom != "" {
		t, err := parseTimeFlex(*req.EffectiveFrom)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "effective_from: "+err.Error())
			return
		}
		in.EffectiveFrom = &t
	}
	if req.EffectiveUntil != nil && *req.EffectiveUntil != "" {
		t, err := parseTimeFlex(*req.EffectiveUntil)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "effective_until: "+err.Error())
			return
		}
		in.EffectiveUntil = &t
	}
	if err := validateUpdateInput(&in, time.Now()); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	before := ruleSummary(cur)
	rule, err := h.store.Update(r.Context(), in, p.UserID)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", rule.ID.String(), rule.Name, before, ruleSummary(rule),
		audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"rule": rule})
}

// Delete 软删除规则。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	rule, ok := h.getRule(w, r)
	if !ok {
		return
	}
	if err := h.store.SoftDelete(r.Context(), rule.ID, p.UserID); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", rule.ID.String(), rule.Name, ruleSummary(rule), "deleted=true",
		audits.ResultSuccess, "", audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "规则已删除"})
}

// Enable 启用规则。
func (h *Handler) Enable(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, StatusActive, "enable")
}

// Disable 停用规则。
func (h *Handler) Disable(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, StatusDisabled, "disable")
}

func (h *Handler) setStatus(w http.ResponseWriter, r *http.Request, status, action string) {
	p := authz.PrincipalFrom(r.Context())
	rule, ok := h.getRule(w, r)
	if !ok {
		return
	}
	if err := ValidateStatusTransition(rule.Status, status); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := h.store.SetStatus(r.Context(), rule.ID, status, p.UserID); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, action, rule.ID.String(), rule.Name, "status="+rule.Status, "status="+status,
		audits.ResultSuccess, "", audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "操作成功"})
}

type extendRequest struct {
	EffectiveUntil string `json:"effective_until"`
}

// Extend 延长临时规则失效时间。
func (h *Handler) Extend(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	rule, ok := h.getRule(w, r)
	if !ok {
		return
	}
	var req extendRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if rule.ValidityType != ValidityTemporary {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "仅临时规则支持延期")
		return
	}
	until, err := parseTimeFlex(req.EffectiveUntil)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if !until.After(time.Now()) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "失效时间必须晚于当前时间")
		return
	}
	if rule.EffectiveFrom != nil && !until.After(*rule.EffectiveFrom) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "失效时间必须晚于生效时间")
		return
	}
	if err := h.store.Extend(r.Context(), rule.ID, until, p.UserID); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "extend", rule.ID.String(), rule.Name, ruleSummary(rule), "until="+until.Format(time.RFC3339),
		audits.ResultSuccess, "", audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "规则已延期"})
}

// Release 提前结束临时规则（标记为 EXPIRED）。
func (h *Handler) Release(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	rule, ok := h.getRule(w, r)
	if !ok {
		return
	}
	if rule.ValidityType != ValidityTemporary {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "仅临时规则支持提前结束")
		return
	}
	if err := h.store.SetStatus(r.Context(), rule.ID, StatusExpired, p.UserID); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "release", rule.ID.String(), rule.Name, "status="+rule.Status, "status="+StatusExpired,
		audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "操作成功"})
}

func (h *Handler) getRule(w http.ResponseWriter, r *http.Request) (*Rule, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则 ID")
		return nil, false
	}
	rule, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		h.writeStoreError(w, r, err)
		return nil, false
	}
	return rule, true
}

func (h *Handler) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "URL 白名单规则不存在")
	case errors.Is(err, ErrConflict), errors.Is(err, ErrVersionConflict):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
	case errors.Is(err, ErrAppNotFound):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "目标应用不存在")
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrInvalidTime), errors.Is(err, ErrInvalidState):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
	default:
		response.InternalError(w, r, err)
	}
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, before, after, result, failure, risk string) {
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "url_whitelists",
		Action:        action,
		ObjectType:    "url_whitelist_rule",
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        result,
		FailureReason: failure,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

func ruleSummary(r *Rule) string {
	return fmt.Sprintf("scope=%s match=%s uri=%s methods=%s status=%s validity=%s",
		r.ScopeType, r.MatchType, r.URIPattern, strings.Join(r.Methods, ","), r.Status, r.ValidityType)
}

func listFilterFrom(r *http.Request) (ListFilter, error) {
	q := r.URL.Query()
	f := ListFilter{
		ScopeType:  q.Get("scope_type"),
		MatchType:  q.Get("match_type"),
		Status:     q.Get("status"),
		SourceType: q.Get("source_type"),
		Keyword:    q.Get("keyword"),
		Page:       queryInt(r, "page", 1),
		PageSize:   queryInt(r, "page_size", 20),
	}
	if appStr := strings.TrimSpace(q.Get("application_id")); appStr != "" {
		id, err := uuid.Parse(appStr)
		if err != nil {
			return f, fmt.Errorf("无效的 application_id")
		}
		f.ApplicationID = &id
	}
	return f, nil
}

func queryInt(r *http.Request, key string, def int) int {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func parseTimeFlex(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("时间格式须为 RFC3339")
}
