package ruleoverrides

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 规则覆盖 API。
type Handler struct {
	store  *Store
	audits *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(store *Store, au *audits.Service) *Handler {
	return &Handler{store: store, audits: au}
}

// List GET /api/v1/rule-overrides
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f := ListFilter{
		RuleID:    queryInt(r, "rule_id", 0),
		ScopeType: r.URL.Query().Get("scope_type"),
		Action:    r.URL.Query().Get("action"),
		Page:      queryInt(r, "page", 1),
		PageSize:  queryInt(r, "page_size", 20),
	}
	if sid := r.URL.Query().Get("scope_id"); sid != "" {
		id, err := uuid.Parse(sid)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 scope_id")
			return
		}
		f.ScopeID = &id
	}
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Get GET /api/v1/rule-overrides/{id}
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的覆盖ID")
		return
	}
	o, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规则覆盖不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"override": o})
}

type overrideRequest struct {
	RuleID           int     `json:"rule_id"`
	ScopeType        string  `json:"scope_type"`
	ScopeID          *string `json:"scope_id"`
	Action           string  `json:"action"`
	SeverityOverride string  `json:"severity_override"`
	EffectiveFrom    *string `json:"effective_from"`
	EffectiveUntil   *string `json:"effective_until"`
	Reason           string  `json:"reason"`
	Version          int     `json:"version"`
}

func parseOverrideReq(req *overrideRequest) (*Override, error) {
	o := &Override{
		RuleID:           req.RuleID,
		ScopeType:        req.ScopeType,
		Action:           req.Action,
		SeverityOverride: req.SeverityOverride,
		Reason:           req.Reason,
		Version:          req.Version,
	}
	if req.ScopeID != nil && *req.ScopeID != "" {
		id, err := uuid.Parse(*req.ScopeID)
		if err != nil {
			return nil, fmtError("无效的 scope_id")
		}
		o.ScopeID = &id
	}
	if req.EffectiveFrom != nil && *req.EffectiveFrom != "" {
		t, err := time.Parse(time.RFC3339, *req.EffectiveFrom)
		if err != nil {
			return nil, fmtError("effective_from 须为 RFC3339")
		}
		t = t.UTC()
		o.EffectiveFrom = &t
	}
	if req.EffectiveUntil != nil && *req.EffectiveUntil != "" {
		t, err := time.Parse(time.RFC3339, *req.EffectiveUntil)
		if err != nil {
			return nil, fmtError("effective_until 须为 RFC3339")
		}
		t = t.UTC()
		o.EffectiveUntil = &t
	}
	return o, nil
}

type simpleError string

func (e simpleError) Error() string { return string(e) }

func fmtError(s string) error { return simpleError(s) }

// Create POST /api/v1/rule-overrides
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req overrideRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	o, err := parseOverrideReq(&req)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := h.store.Create(r.Context(), o, p.UserID); err != nil {
		if errors.Is(err, ErrConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
			return
		}
		if errors.Is(err, ErrInvalidInput) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
		// ValidateInput wraps ErrInvalidInput with %w
		if errors.Is(err, ErrInvalidInput) || containsInvalid(err) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "create", o.ID.String(), strconv.Itoa(o.RuleID), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"override": o,
		"message":  "规则覆盖已创建，请发布配置后生效",
	})
}

func containsInvalid(err error) bool {
	return err != nil && (errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrConflict))
}

// Update PUT /api/v1/rule-overrides/{id}
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的覆盖ID")
		return
	}
	var req overrideRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	existing, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规则覆盖不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if req.Version != 0 && req.Version != existing.Version {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "覆盖已被修改，请刷新后重试")
		return
	}
	o, err := parseOverrideReq(&req)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	o.ID = id
	o.Version = existing.Version
	if err := h.store.Update(r.Context(), o, p.UserID); err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "覆盖已被修改，请刷新后重试")
			return
		}
		if errors.Is(err, ErrConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "update", o.ID.String(), strconv.Itoa(o.RuleID), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"override": o,
		"message":  "规则覆盖已更新，请发布配置后生效",
	})
}

// Delete DELETE /api/v1/rule-overrides/{id}
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的覆盖ID")
		return
	}
	o, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规则覆盖不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.Delete(r.Context(), id); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", id.String(), strconv.Itoa(o.RuleID), audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "规则覆盖已删除，请发布配置后生效"})
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, result, risk string) {
	_ = h.audits.Record(r.Context(), audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.RemoteIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "rule_overrides",
		Action:       action,
		ObjectType:   "rule_override",
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
	if err != nil {
		return def
	}
	return n
}
