// handler.go A2A 协议安全治理与 AgBOM 管理面接口（Phase 9C-1；路由在 app.go 注册）：
//
//	GET    /api/v1/applications/{id}/a2a-policy  读取应用 A2A 安全策略草稿与状态摘要（api_a2a.read）
//	PUT    /api/v1/applications/{id}/a2a-policy  校验并保存应用 A2A 安全策略草稿（api_a2a.manage）
//	GET    /api/v1/api-security/a2a/agents       分页查询 Agent 物料清单 AgBOM（api_a2a.read）
//	POST   /api/v1/api-security/a2a/agents       人工登记 Agent 资产（api_a2a.manage）
//	PUT    /api/v1/api-security/a2a/agents/{id}  审批/编辑 Agent 资产（api_a2a.manage）
//	DELETE /api/v1/api-security/a2a/agents/{id}  删除 Agent 资产（api_a2a.manage）
//	GET    /api/v1/api-security/a2a/events       分页查询 A2A 安全事件（api_a2a.read）
package apia2a

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// AppGetter 应用查询接口（applications.Store 实现）。
type AppGetter interface {
	GetByID(ctx context.Context, id uuid.UUID) (*applications.Application, error)
}

// auditRecorder 操作审计记录接口（*audits.Service 实现；单测可注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// Handler 是 A2A 协议安全治理与 AgBOM HTTP 处理器。
type Handler struct {
	store  Repository
	apps   AppGetter
	audits auditRecorder
}

// NewHandler 创建处理器。
func NewHandler(store Repository, apps AppGetter, au *audits.Service) *Handler {
	h := &Handler{store: store, apps: apps}
	if au != nil {
		h.audits = au
	}
	return h
}

// ---------- 请求 DTO ----------

type putPolicyRequest struct {
	Mode                     string   `json:"mode"`
	ExpectedVersion          int      `json:"expected_version"`
	CardDiscoveryEnabled     *bool    `json:"card_discovery_enabled"`
	A2APathPrefixes          []string `json:"a2a_path_prefixes"`
	AllowedCallerAgents      []string `json:"allowed_caller_agents"`
	MaxDelegationDepth       *int     `json:"max_delegation_depth"`
	EnforceScopeAttenuation  *bool    `json:"enforce_scope_attenuation"`
	LoopWindowSeconds        *int     `json:"loop_window_seconds"`
	MaxCallsPerTaskWindow    *int     `json:"max_calls_per_task_window"`
	LethalTrifectaEnabled    *bool    `json:"lethal_trifecta_enabled"`
	ConfidentialReadPatterns []string `json:"confidential_read_patterns"`
	ExternalEgressPatterns   []string `json:"external_egress_patterns"`
	Reason                   string   `json:"reason"`
}

func (r *putPolicyRequest) toPolicy(appID uuid.UUID) *Policy {
	p := DefaultPolicy(appID)
	p.Mode = r.Mode
	if r.CardDiscoveryEnabled != nil {
		p.CardDiscoveryEnabled = *r.CardDiscoveryEnabled
	}
	if r.A2APathPrefixes != nil {
		p.A2APathPrefixes = append([]string{}, r.A2APathPrefixes...)
	}
	if r.AllowedCallerAgents != nil {
		p.AllowedCallerAgents = append([]string{}, r.AllowedCallerAgents...)
	}
	if r.MaxDelegationDepth != nil {
		p.MaxDelegationDepth = *r.MaxDelegationDepth
	}
	if r.EnforceScopeAttenuation != nil {
		p.EnforceScopeAttenuation = *r.EnforceScopeAttenuation
	}
	if r.LoopWindowSeconds != nil {
		p.LoopWindowSeconds = *r.LoopWindowSeconds
	}
	if r.MaxCallsPerTaskWindow != nil {
		p.MaxCallsPerTaskWindow = *r.MaxCallsPerTaskWindow
	}
	if r.LethalTrifectaEnabled != nil {
		p.LethalTrifectaEnabled = *r.LethalTrifectaEnabled
	}
	if r.ConfidentialReadPatterns != nil {
		p.ConfidentialReadPatterns = append([]string{}, r.ConfidentialReadPatterns...)
	}
	if r.ExternalEgressPatterns != nil {
		p.ExternalEgressPatterns = append([]string{}, r.ExternalEgressPatterns...)
	}
	NormalizePolicy(p)
	return p
}

type createAgentRequest struct {
	ApplicationID string   `json:"application_id"`
	AgentName     string   `json:"agent_name"`
	AgentURL      string   `json:"agent_url"`
	AgentVersion  string   `json:"agent_version"`
	Status        string   `json:"status"`
	Description   string   `json:"description"`
	Skills        []string `json:"skills"`
	AllowedSkills []string `json:"allowed_skills"`
	AuthSchemes   []string `json:"auth_schemes"`
}

type updateAgentRequest struct {
	Status        string   `json:"status"`
	Description   string   `json:"description"`
	AllowedSkills []string `json:"allowed_skills"`
}

// ---------- 应用级 A2A 策略接口 ----------

// GetPolicy GET /api/v1/applications/{id}/a2a-policy
func (h *Handler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	app, ok := h.resolveApp(w, r)
	if !ok {
		return
	}
	p, err := h.store.GetPolicyByApp(r.Context(), app.ID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			p = DefaultPolicy(app.ID)
		} else {
			response.InternalError(w, r, err)
			return
		}
	}
	published, err := h.store.PublishedVersion(r.Context(), app.Code)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	summary := StatusSummary{
		State:            StateNotConfigured,
		DraftVersion:     p.Version,
		PublishedVersion: published,
	}
	if p.Version > 0 {
		if p.Version == published {
			summary.State = StatePublished
		} else {
			summary.State = StateDraftPending
		}
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"policy":  p,
		"summary": summary,
	})
}

// PutPolicy PUT /api/v1/applications/{id}/a2a-policy
func (h *Handler) PutPolicy(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	app, ok := h.resolveApp(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetPolicyByApp(r.Context(), app.ID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		response.InternalError(w, r, err)
		return
	}

	var req putPolicyRequest
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过",
			[]FieldError{{Field: "reason", Message: "变更理由不能为空"}})
		return
	}
	if len(req.Reason) > MaxReasonLen {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过",
			[]FieldError{{Field: "reason", Message: fmt.Sprintf("变更理由不能超过 %d 字符", MaxReasonLen)}})
		return
	}
	if req.ExpectedVersion < 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过",
			[]FieldError{{Field: "expected_version", Message: "expected_version 不能为负数"}})
		return
	}
	if before != nil && req.ExpectedVersion == 0 {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
		return
	}
	if before == nil && req.ExpectedVersion != 0 {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
		return
	}

	p := req.toPolicy(app.ID)
	if errs := ValidatePolicy(p); len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过", errs)
		return
	}

	username := principalUsername(principal)
	if err := h.store.SavePolicyDraft(r.Context(), p, req.ExpectedVersion, req.Reason, username); err != nil {
		if errors.Is(err, ErrConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
			return
		}
		var ve *ValidationError
		if errors.As(err, &ve) {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过", ve.Errors)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordPolicyAudit(r, principal, app, before, p, req.Reason)

	final, err := h.store.GetPolicyByApp(r.Context(), app.ID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"policy": final})
}

// ---------- AgBOM Agent 资产接口 ----------

// ListAgents GET /api/v1/api-security/a2a/agents
func (h *Handler) ListAgents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := AgentFilter{
		Status:   strings.ToUpper(strings.TrimSpace(q.Get("status"))),
		Keyword:  strings.TrimSpace(q.Get("keyword")),
		Page:     queryInt(r, "page", 1),
		PageSize: queryInt(r, "page_size", 20),
	}
	if rawAppID := strings.TrimSpace(q.Get("application_id")); rawAppID != "" {
		id, err := uuid.Parse(rawAppID)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的 application_id")
			return
		}
		f.ApplicationID = &id
	}
	if f.Status != "" && !validAgentStatus(f.Status) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的 status 筛选值")
		return
	}
	f.Page, f.PageSize = normalizePage(f.Page, f.PageSize)

	items, total, err := h.store.ListAgents(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if items == nil {
		items = []Agent{}
	}
	response.Page(w, r, items, total, f.Page, f.PageSize)
}

// CreateAgent POST /api/v1/api-security/a2a/agents
func (h *Handler) CreateAgent(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	var req createAgentRequest
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	appID, err := uuid.Parse(strings.TrimSpace(req.ApplicationID))
	if err != nil {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "Agent 校验未通过",
			[]FieldError{{Field: "application_id", Message: "application_id 须为合法 UUID"}})
		return
	}
	if _, err := h.apps.GetByID(r.Context(), appID); err != nil {
		if errors.Is(err, applications.ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}

	status := strings.ToUpper(strings.TrimSpace(req.Status))
	if status == "" {
		status = AgentStatusApproved
	}
	ag := Agent{
		ApplicationID: appID,
		AgentName:     req.AgentName,
		AgentURL:      req.AgentURL,
		AgentVersion:  req.AgentVersion,
		Status:        status,
		Description:   req.Description,
		Skills:        req.Skills,
		AllowedSkills: req.AllowedSkills,
		AuthSchemes:   req.AuthSchemes,
	}
	NormalizeAgent(&ag)
	if errs := ValidateCreateAgent(&ag); len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "Agent 校验未通过", errs)
		return
	}

	if err := h.store.CreateAgent(r.Context(), &ag); err != nil {
		if errors.Is(err, ErrConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "该应用下已存在同名同地址的 Agent 记录")
			return
		}
		var ve *ValidationError
		if errors.As(err, &ve) {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "Agent 校验未通过", ve.Errors)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAgentAudit(r, principal, "create", nil, &ag)
	response.JSON(w, r, http.StatusCreated, map[string]interface{}{"agent": ag})
}

// UpdateAgent PUT /api/v1/api-security/a2a/agents/{id}
func (h *Handler) UpdateAgent(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的 Agent ID")
		return
	}
	before, err := h.store.GetAgent(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Agent 记录不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}

	var req updateAgentRequest
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	status := strings.ToUpper(strings.TrimSpace(req.Status))
	desc := strings.TrimSpace(req.Description)
	allowedSkills := normalizeStrings(req.AllowedSkills)
	if errs := ValidateUpdateAgent(status, desc, allowedSkills); len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "Agent 审批校验未通过", errs)
		return
	}

	updated, err := h.store.UpdateAgent(r.Context(), id, status, desc, allowedSkills)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Agent 记录不存在")
			return
		}
		var ve *ValidationError
		if errors.As(err, &ve) {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "Agent 审批校验未通过", ve.Errors)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAgentAudit(r, principal, "update", before, updated)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"agent": updated})
}

// DeleteAgent DELETE /api/v1/api-security/a2a/agents/{id}
func (h *Handler) DeleteAgent(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的 Agent ID")
		return
	}
	before, err := h.store.GetAgent(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Agent 记录不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.DeleteAgent(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Agent 记录不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAgentAudit(r, principal, "delete", before, nil)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"deleted": true,
		"id":      id.String(),
	})
}

// ---------- A2A 安全事件接口 ----------

// ListEvents GET /api/v1/api-security/a2a/events
func (h *Handler) ListEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := EventFilter{
		EventType: strings.ToUpper(strings.TrimSpace(q.Get("event_type"))),
		RuleID:    strings.TrimSpace(q.Get("rule_id")),
		Page:      queryInt(r, "page", 1),
		PageSize:  queryInt(r, "page_size", 20),
	}
	if rawAppID := strings.TrimSpace(q.Get("application_id")); rawAppID != "" {
		id, err := uuid.Parse(rawAppID)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的 application_id")
			return
		}
		f.ApplicationID = &id
	}
	if f.EventType != "" && !validEventTypeFilter(f.EventType) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的 event_type 筛选值")
		return
	}
	f.Page, f.PageSize = normalizePage(f.Page, f.PageSize)

	items, total, err := h.store.ListEvents(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if items == nil {
		items = []Event{}
	}
	response.Page(w, r, items, total, f.Page, f.PageSize)
}

// ---------- 辅助与审计 ----------

func (h *Handler) resolveApp(w http.ResponseWriter, r *http.Request) (*applications.Application, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的应用 ID")
		return nil, false
	}
	app, err := h.apps.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, applications.ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
			return nil, false
		}
		response.InternalError(w, r, err)
		return nil, false
	}
	return app, true
}

func principalUsername(p *authz.Principal) string {
	if p == nil {
		return ""
	}
	return p.Username
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

func summarizePolicy(p *Policy, reason string) map[string]interface{} {
	if p == nil {
		return nil
	}
	return map[string]interface{}{
		"mode":                      p.Mode,
		"version":                   p.Version,
		"card_discovery_enabled":    p.CardDiscoveryEnabled,
		"a2a_path_prefixes_count":   len(p.A2APathPrefixes),
		"allowed_caller_agents":     len(p.AllowedCallerAgents),
		"max_delegation_depth":      p.MaxDelegationDepth,
		"enforce_scope_attenuation": p.EnforceScopeAttenuation,
		"loop_window_seconds":       p.LoopWindowSeconds,
		"max_calls_per_task_window": p.MaxCallsPerTaskWindow,
		"lethal_trifecta_enabled":   p.LethalTrifectaEnabled,
		"reason":                    reason,
	}
}

func (h *Handler) recordPolicyAudit(r *http.Request, p *authz.Principal, app *applications.Application, before, after *Policy, reason string) {
	if p == nil || h.audits == nil {
		return
	}
	var beforeJSON, afterJSON []byte
	if before != nil {
		beforeJSON, _ = json.Marshal(summarizePolicy(before, ""))
	}
	if after != nil {
		afterJSON, _ = json.Marshal(summarizePolicy(after, reason))
	}
	risk := audits.RiskMedium
	if after != nil && after.Mode == ModeProtect {
		risk = audits.RiskHigh
	}
	objID := app.ID.String()
	if after != nil && after.ID != uuid.Nil {
		objID = after.ID.String()
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_security",
		Action:        "update",
		ObjectType:    "api_a2a_policy",
		ObjectID:      objID,
		ObjectName:    app.Code,
		BeforeSummary: string(beforeJSON),
		AfterSummary:  string(afterJSON),
		Result:        audits.ResultSuccess,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

func summarizeAgent(a *Agent) map[string]interface{} {
	if a == nil {
		return nil
	}
	return map[string]interface{}{
		"application_id":      a.ApplicationID.String(),
		"agent_name":          a.AgentName,
		"agent_url":           a.AgentURL,
		"agent_version":       a.AgentVersion,
		"status":              a.Status,
		"skills_count":        len(a.Skills),
		"allowed_skills":      a.AllowedSkills,
		"auth_schemes_count":  len(a.AuthSchemes),
	}
}

func (h *Handler) recordAgentAudit(r *http.Request, p *authz.Principal, action string, before, after *Agent) {
	if p == nil || h.audits == nil {
		return
	}
	var beforeJSON, afterJSON []byte
	if before != nil {
		beforeJSON, _ = json.Marshal(summarizeAgent(before))
	}
	if after != nil {
		afterJSON, _ = json.Marshal(summarizeAgent(after))
	}
	objID, objName := "", ""
	if after != nil {
		objID, objName = after.ID.String(), after.AgentName
	} else if before != nil {
		objID, objName = before.ID.String(), before.AgentName
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_security",
		Action:        action,
		ObjectType:    "api_a2a_agent",
		ObjectID:      objID,
		ObjectName:    trimMax(objName, 255),
		BeforeSummary: string(beforeJSON),
		AfterSummary:  string(afterJSON),
		Result:        audits.ResultSuccess,
		RiskLevel:     audits.RiskMedium,
		RequestID:     response.RequestIDFrom(r),
	})
}
