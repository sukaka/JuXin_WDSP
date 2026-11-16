package apillm

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

type SecurityPolicyHandler struct {
	store  SecurityPolicyRepository
	audits *audits.Service
}

func NewSecurityPolicyHandler(store SecurityPolicyRepository, audit *audits.Service) *SecurityPolicyHandler {
	return &SecurityPolicyHandler{store: store, audits: audit}
}

func RegisterSecurityPolicyRoutes(mux *http.ServeMux, authzFn func(http.Handler) http.Handler, h *SecurityPolicyHandler) {
	mux.Handle("GET /api/v1/api-security/llm/security-policies", authzFn(middleware.RequirePermission(PermSecurityRead)(http.HandlerFunc(h.List))))
	mux.Handle("POST /api/v1/api-security/llm/security-policies", authzFn(middleware.RequirePermission(PermSecurityManage)(http.HandlerFunc(h.Create))))
	mux.Handle("PATCH /api/v1/api-security/llm/security-policies/{id}", authzFn(middleware.RequirePermission(PermSecurityManage)(http.HandlerFunc(h.Update))))
	mux.Handle("DELETE /api/v1/api-security/llm/security-policies/{id}", authzFn(middleware.RequirePermission(PermSecurityManage)(http.HandlerFunc(h.Delete))))
	mux.Handle("GET /api/v1/api-security/llm/security-policies/{id}/versions", authzFn(middleware.RequirePermission(PermSecurityRead)(http.HandlerFunc(h.Versions))))
}

type securityPolicyRequest struct {
	ApplicationID          *string   `json:"application_id"`
	Name                   *string   `json:"name"`
	Mode                   *string   `json:"mode"`
	PromptInjectionEnabled *bool     `json:"prompt_injection_enabled"`
	InputContentEnabled    *bool     `json:"input_content_enabled"`
	PIIDetectionEnabled    *bool     `json:"pii_detection_enabled"`
	OutputContentEnabled   *bool     `json:"output_content_enabled"`
	OutputPIIEnabled       *bool     `json:"output_pii_enabled"`
	BlockedTopics          *[]string `json:"blocked_topics"`
	MaxPromptBytes         *int      `json:"max_prompt_bytes"`
	MaxOutputTokens        *int      `json:"max_output_tokens"`
	Enabled                *bool     `json:"enabled"`
}

func newSecurityPolicyRequest(req securityPolicyRequest) (*SecurityPolicy, error) {
	if req.ApplicationID == nil || req.Name == nil {
		return nil, errors.New("应用与策略名称不能为空")
	}
	applicationID, err := uuid.Parse(*req.ApplicationID)
	if err != nil {
		return nil, errors.New("无效的应用 ID")
	}
	p := &SecurityPolicy{ApplicationID: applicationID, Mode: SecurityPolicyModeObserve,
		PromptInjectionEnabled: true, InputContentEnabled: true, PIIDetectionEnabled: true, OutputContentEnabled: true,
		OutputPIIEnabled: true, Enabled: true, BlockedTopics: []string{}}
	if req.Name != nil {
		p.Name = *req.Name
	}
	applySecurityPolicyRequest(p, req)
	return p, p.NormalizeAndValidate()
}

func applySecurityPolicyRequest(p *SecurityPolicy, req securityPolicyRequest) {
	if req.Name != nil {
		p.Name = *req.Name
	}
	if req.Mode != nil {
		p.Mode = *req.Mode
	}
	if req.PromptInjectionEnabled != nil {
		p.PromptInjectionEnabled = *req.PromptInjectionEnabled
	}
	if req.InputContentEnabled != nil {
		p.InputContentEnabled = *req.InputContentEnabled
	}
	if req.PIIDetectionEnabled != nil {
		p.PIIDetectionEnabled = *req.PIIDetectionEnabled
	}
	if req.OutputContentEnabled != nil {
		p.OutputContentEnabled = *req.OutputContentEnabled
	}
	if req.OutputPIIEnabled != nil {
		p.OutputPIIEnabled = *req.OutputPIIEnabled
	}
	if req.BlockedTopics != nil {
		p.BlockedTopics = *req.BlockedTopics
	}
	if req.MaxPromptBytes != nil {
		p.MaxPromptBytes = *req.MaxPromptBytes
	}
	if req.MaxOutputTokens != nil {
		p.MaxOutputTokens = *req.MaxOutputTokens
	}
	if req.Enabled != nil {
		p.Enabled = *req.Enabled
	}
}

func decodeSecurityPolicyRequest(w http.ResponseWriter, r *http.Request) (securityPolicyRequest, bool) {
	var req securityPolicyRequest
	if err := response.DecodeJSON(w, r, &req, 64<<10); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return req, false
	}
	return req, true
}

func writeSecurityPolicyError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrSecurityPolicyNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, err.Error())
	case errors.Is(err, ErrSecurityPolicyConflict):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
	default:
		response.InternalError(w, r, err)
	}
}

func (h *SecurityPolicyHandler) List(w http.ResponseWriter, r *http.Request) {
	items, err := h.store.ListSecurityPolicies(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func (h *SecurityPolicyHandler) Create(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	req, ok := decodeSecurityPolicyRequest(w, r)
	if !ok {
		return
	}
	p, err := newSecurityPolicyRequest(req)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if principal != nil {
		p.CreatedBy = &principal.UserID
		p.UpdatedBy = &principal.UserID
	}
	if err := h.store.CreateSecurityPolicy(r.Context(), p); err != nil {
		writeSecurityPolicyError(w, r, err)
		return
	}
	h.recordAudit(r, principal, "create", p, "")
	response.JSON(w, r, http.StatusOK, p)
}

func (h *SecurityPolicyHandler) Update(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的策略 ID")
		return
	}
	req, ok := decodeSecurityPolicyRequest(w, r)
	if !ok {
		return
	}
	p, err := h.store.GetSecurityPolicy(r.Context(), id)
	if err != nil {
		writeSecurityPolicyError(w, r, err)
		return
	}
	before, _ := json.Marshal(p)
	applySecurityPolicyRequest(p, req)
	if err := p.NormalizeAndValidate(); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if principal != nil {
		p.UpdatedBy = &principal.UserID
	}
	if err := h.store.UpdateSecurityPolicy(r.Context(), p); err != nil {
		writeSecurityPolicyError(w, r, err)
		return
	}
	h.recordAudit(r, principal, "update", p, string(before))
	response.JSON(w, r, http.StatusOK, p)
}

func (h *SecurityPolicyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的策略 ID")
		return
	}
	p, err := h.store.GetSecurityPolicy(r.Context(), id)
	if err != nil {
		writeSecurityPolicyError(w, r, err)
		return
	}
	before, _ := json.Marshal(p)
	if err := h.store.DeleteSecurityPolicy(r.Context(), id); err != nil {
		writeSecurityPolicyError(w, r, err)
		return
	}
	h.recordAudit(r, principal, "delete", p, string(before))
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *SecurityPolicyHandler) Versions(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的策略 ID")
		return
	}
	if _, err := h.store.GetSecurityPolicy(r.Context(), id); err != nil {
		writeSecurityPolicyError(w, r, err)
		return
	}
	items, err := h.store.ListSecurityPolicyVersions(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func (h *SecurityPolicyHandler) recordAudit(r *http.Request, principal *authz.Principal, action string, p *SecurityPolicy, before string) {
	if h.audits == nil || principal == nil {
		return
	}
	after, _ := json.Marshal(p)
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID: &principal.UserID, Username: principal.Username,
		SourceIP: middleware.RemoteIP(r), ConnectionIP: middleware.ConnectionIP(r), UserAgent: r.UserAgent(),
		Module: "api_llm", Action: action, ObjectType: "api_llm_security_policy",
		ObjectID: p.ID.String(), ObjectName: p.Name, BeforeSummary: before, AfterSummary: string(after),
		Result: audits.ResultSuccess, RiskLevel: audits.RiskHigh, RequestID: response.RequestIDFrom(r),
	})
}
