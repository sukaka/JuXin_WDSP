package exceptions

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 是例外策略处理器。
type Handler struct {
	store  *Store
	audits *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(store *Store, au *audits.Service) *Handler {
	return &Handler{store: store, audits: au}
}

// List 例外列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	scopeType := r.URL.Query().Get("scope_type")
	status := r.URL.Query().Get("status")
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.List(r.Context(), scopeType, status, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// Get 例外详情。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的例外ID")
		return
	}
	e, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "例外不存在")
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"exception": e,
		"is_broad":  e.IsBroad(),
	})
}

type exceptionRequest struct {
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	ScopeType        string     `json:"scope_type"`
	ApplicationID    *uuid.UUID `json:"application_id"`
	Domain           string     `json:"domain"`
	URIExact         string     `json:"uri_exact"`
	URIPrefix        string     `json:"uri_prefix"`
	URIRegex         string     `json:"uri_regex"`
	Methods          []string   `json:"methods"`
	SourceIPs        []string   `json:"source_ips"`
	ParamNames       []string   `json:"param_names"`
	CookieNames      []string   `json:"cookie_names"`
	HeaderNames      []string   `json:"header_names"`
	RuleIDs          []int      `json:"rule_ids"`
	RuleTags         []string   `json:"rule_tags"`
	AttackTypes      []string   `json:"attack_types"`
	ContentTypes     []string   `json:"content_types"`
	ExceptionAction  string     `json:"exception_action"`
	ActionTarget     string     `json:"action_target"`
	IsTemporary      bool       `json:"is_temporary"`
	EffectiveFrom    *string    `json:"effective_from"`
	EffectiveUntil   *string    `json:"effective_until"`
	RiskAcknowledged bool       `json:"risk_acknowledged"`
	Reason           string     `json:"reason"`
	Version          int        `json:"version"` // 乐观锁（更新必填）
}

// Create 创建例外。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req exceptionRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	e := buildException(&req)
	e.Status = "ENABLED"
	if err := h.store.Create(r.Context(), e, p.UserID); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	risk := audits.RiskMedium
	if e.IsBroad() {
		risk = audits.RiskHigh
	}
	h.recordAudit(r, p, "create", e.ID.String(), e.Name, audits.ResultSuccess, risk)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"exception": e,
		"is_broad":  e.IsBroad(),
	})
}

// Update 更新例外（乐观锁 version，请求体 version 必填）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的例外ID")
		return
	}
	existing, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "例外不存在")
		return
	}
	var req exceptionRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Version <= 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "version 必填（乐观锁）")
		return
	}
	e := buildException(&req)
	e.ID = id
	e.Status = existing.Status
	if err := h.store.Update(r.Context(), e, req.Version); err != nil {
		if err == ErrNotFound {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "例外不存在或版本冲突，请刷新后重试")
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	risk := audits.RiskMedium
	if e.IsBroad() {
		risk = audits.RiskHigh
	}
	h.recordAudit(r, p, "update", e.ID.String(), e.Name, audits.ResultSuccess, risk)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"exception": e,
		"is_broad":  e.IsBroad(),
	})
}

// Delete 删除例外。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的例外ID")
		return
	}
	e, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "例外不存在")
		return
	}
	if err := h.store.Delete(r.Context(), id); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", id.String(), e.Name, audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "例外已删除"})
}

// Enable 启用例外。
func (h *Handler) Enable(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, "ENABLED", "enable")
}

// Disable 停用例外。
func (h *Handler) Disable(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, "DISABLED", "disable")
}

func (h *Handler) setStatus(w http.ResponseWriter, r *http.Request, status, action string) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的例外ID")
		return
	}
	e, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "例外不存在")
		return
	}
	if err := h.store.SetStatus(r.Context(), id, status); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, action, id.String(), e.Name, audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "操作成功"})
}

func buildException(req *exceptionRequest) *Exception {
	e := &Exception{
		Name:             req.Name,
		Description:      req.Description,
		ScopeType:        req.ScopeType,
		ApplicationID:    req.ApplicationID,
		Domain:           req.Domain,
		URIExact:         req.URIExact,
		URIPrefix:        req.URIPrefix,
		URIRegex:         req.URIRegex,
		Methods:          req.Methods,
		SourceIPs:        req.SourceIPs,
		ParamNames:       req.ParamNames,
		CookieNames:      req.CookieNames,
		HeaderNames:      req.HeaderNames,
		RuleIDs:          req.RuleIDs,
		RuleTags:         req.RuleTags,
		AttackTypes:      req.AttackTypes,
		ContentTypes:     req.ContentTypes,
		ExceptionAction:  req.ExceptionAction,
		ActionTarget:     req.ActionTarget,
		IsTemporary:      req.IsTemporary,
		RiskAcknowledged: req.RiskAcknowledged,
		Reason:           req.Reason,
	}
	return e
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName string, result, risk string) {
	_ = h.audits.Record(r.Context(), audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.RemoteIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "exceptions",
		Action:        action,
		ObjectType:    "exception_policy",
		ObjectID:      objID,
		ObjectName:    objName,
		Result:        result,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
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
