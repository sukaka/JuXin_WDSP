// handler.go 本地离线 ONNX/SLM 语义防火墙管理面接口（Phase 9C-2；路由在 app.go 注册）：
//
//	GET /api/v1/semantic-guard/status                   探测本地 Unix Socket 边车状态（semantic_guard.read）
//	GET /api/v1/applications/{id}/semantic-guard-policy 读取应用语义防火墙策略草稿与状态摘要（semantic_guard.read）
//	PUT /api/v1/applications/{id}/semantic-guard-policy 校验并保存应用语义防火墙策略草稿（semantic_guard.manage）
package semanticguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

// Handler 是本地离线语义防火墙 HTTP 处理器。
type Handler struct {
	store  Repository
	apps   AppGetter
	audits auditRecorder
	prober StatusProber
}

// NewHandler 创建处理器（默认使用生产受控 UnixHealthProber）。
func NewHandler(store Repository, apps AppGetter, au *audits.Service) *Handler {
	h := &Handler{
		store:  store,
		apps:   apps,
		prober: NewUnixHealthProber(defaultProbeTimeout),
	}
	if au != nil {
		h.audits = au
	}
	return h
}

// SetProber 覆盖边车健康探测器（主要用于单测注入临时 Socket 目录探测器）。
func (h *Handler) SetProber(p StatusProber) {
	if p != nil {
		h.prober = p
	}
}

type putPolicyRequest struct {
	Mode                    string   `json:"mode"`
	ExpectedVersion         int      `json:"expected_version"`
	SocketPath              *string  `json:"socket_path"`
	TimeoutMs               *int     `json:"timeout_ms"`
	MaxConcurrency          *int     `json:"max_concurrency"`
	MaxInputRunes           *int     `json:"max_input_runes"`
	BlockThreshold          *float64 `json:"block_threshold"`
	ObserveThreshold        *float64 `json:"observe_threshold"`
	FailPolicy              *string  `json:"fail_policy"`
	InspectLLMPrompts       *bool    `json:"inspect_llm_prompts"`
	InspectMCPContent       *bool    `json:"inspect_mcp_content"`
	InspectWebGrayzone      *bool    `json:"inspect_web_grayzone"`
	CircuitFailureThreshold *int     `json:"circuit_failure_threshold"`
	CircuitOpenSeconds      *int     `json:"circuit_open_seconds"`
	Reason                  string   `json:"reason"`
}

func (r *putPolicyRequest) toPolicy(appID uuid.UUID) *Policy {
	p := DefaultPolicy(appID)
	p.Mode = r.Mode
	if r.SocketPath != nil {
		p.SocketPath = *r.SocketPath
	}
	if r.TimeoutMs != nil {
		p.TimeoutMs = *r.TimeoutMs
	}
	if r.MaxConcurrency != nil {
		p.MaxConcurrency = *r.MaxConcurrency
	}
	if r.MaxInputRunes != nil {
		p.MaxInputRunes = *r.MaxInputRunes
	}
	if r.BlockThreshold != nil {
		p.BlockThreshold = *r.BlockThreshold
	}
	if r.ObserveThreshold != nil {
		p.ObserveThreshold = *r.ObserveThreshold
	}
	if r.FailPolicy != nil {
		p.FailPolicy = *r.FailPolicy
	}
	if r.InspectLLMPrompts != nil {
		p.InspectLLMPrompts = *r.InspectLLMPrompts
	}
	if r.InspectMCPContent != nil {
		p.InspectMCPContent = *r.InspectMCPContent
	}
	if r.InspectWebGrayzone != nil {
		p.InspectWebGrayzone = *r.InspectWebGrayzone
	}
	if r.CircuitFailureThreshold != nil {
		p.CircuitFailureThreshold = *r.CircuitFailureThreshold
	}
	if r.CircuitOpenSeconds != nil {
		p.CircuitOpenSeconds = *r.CircuitOpenSeconds
	}
	NormalizePolicy(p)
	return p
}

// GetStatus GET /api/v1/semantic-guard/status
func (h *Handler) GetStatus(w http.ResponseWriter, r *http.Request) {
	socketPath := strings.TrimSpace(r.URL.Query().Get("socket_path"))
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	prober := h.prober
	if prober == nil {
		prober = NewUnixHealthProber(defaultProbeTimeout)
	}
	if msg := prober.ValidateSocketPath(socketPath); msg != "" {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的 Unix Socket 路径",
			[]FieldError{{Field: "socket_path", Message: msg}})
		return
	}
	status := prober.Probe(r.Context(), socketPath)
	response.JSON(w, r, http.StatusOK, status)
}

// GetPolicy GET /api/v1/applications/{id}/semantic-guard-policy
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

// PutPolicy PUT /api/v1/applications/{id}/semantic-guard-policy
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
	if hasDisallowedTextControlChars(req.Reason) {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过",
			[]FieldError{{Field: "reason", Message: "变更理由不得包含非法控制字符"}})
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

func summarizePolicy(p *Policy, reason string) map[string]interface{} {
	if p == nil {
		return nil
	}
	return map[string]interface{}{
		"mode":                      p.Mode,
		"version":                   p.Version,
		"socket_path":               p.SocketPath,
		"timeout_ms":                p.TimeoutMs,
		"max_concurrency":           p.MaxConcurrency,
		"max_input_runes":           p.MaxInputRunes,
		"block_threshold":           p.BlockThreshold,
		"observe_threshold":         p.ObserveThreshold,
		"fail_policy":               p.FailPolicy,
		"inspect_llm_prompts":       p.InspectLLMPrompts,
		"inspect_mcp_content":       p.InspectMCPContent,
		"inspect_web_grayzone":      p.InspectWebGrayzone,
		"circuit_failure_threshold": p.CircuitFailureThreshold,
		"circuit_open_seconds":      p.CircuitOpenSeconds,
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
	if after != nil && (after.Mode == ModeProtect || after.FailPolicy == FailPolicyClosed) {
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
		Module:        "security",
		Action:        "update",
		ObjectType:    "semantic_guard_policy",
		ObjectID:      objID,
		ObjectName:    app.Code,
		BeforeSummary: string(beforeJSON),
		AfterSummary:  string(afterJSON),
		Result:        audits.ResultSuccess,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}
