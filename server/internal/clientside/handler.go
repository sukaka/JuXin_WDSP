// handler.go 客户端供应链安全管理面接口（Phase 9B；路由在 app.go 注册）：
//
//	GET    /api/v1/applications/{id}/client-side-policy 读取应用策略草稿与状态摘要（client_side.read）
//	PUT    /api/v1/applications/{id}/client-side-policy 校验并保存应用策略草稿（client_side.manage）
//	GET    /api/v1/client-side/scripts                  分页查询脚本资产清单（client_side.read）
//	POST   /api/v1/client-side/scripts                  新增预授权/封禁脚本资产（client_side.manage）
//	PUT    /api/v1/client-side/scripts/{id}             审批/编辑脚本资产与 SRI（client_side.manage）
//	DELETE /api/v1/client-side/scripts/{id}             删除脚本资产（client_side.manage）
//	GET    /api/v1/client-side/violations               分页查询篡改与 CSP 违规告警（client_side.read）
//	PUT    /api/v1/client-side/violations/{id}/status   更新违规告警处置状态与备注（client_side.manage）
//	GET    /api/v1/client-side/compliance-export        导出 PCI DSS 4.0 合规证据 CSV（client_side.read）
package clientside

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

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

// Handler 是客户端供应链安全 HTTP 处理器。
type Handler struct {
	store  Repository
	apps   AppGetter
	audits *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(store Repository, apps AppGetter, au *audits.Service) *Handler {
	return &Handler{store: store, apps: apps, audits: au}
}

// ---------- 请求 DTO ----------

type putPolicyRequest struct {
	Mode                     string   `json:"mode"`
	ExpectedVersion          int      `json:"expected_version"`
	CSPMode                  string   `json:"csp_mode"`
	SensitivePaths           []string `json:"sensitive_paths"`
	ProbeEnabled             bool     `json:"probe_enabled"`
	StripUnauthorizedScripts bool     `json:"strip_unauthorized_scripts"`
	AllowedScriptOrigins     []string `json:"allowed_script_origins"`
	AllowedConnectOrigins    []string `json:"allowed_connect_origins"`
	AllowedFormOrigins       []string `json:"allowed_form_origins"`
	CustomCSPDirectives      string   `json:"custom_csp_directives"`
	Reason                   string   `json:"reason"`
}

func (r *putPolicyRequest) toPolicy(appID uuid.UUID) *Policy {
	p := DefaultPolicy(appID)
	p.Mode = r.Mode
	p.CSPMode = r.CSPMode
	p.SensitivePaths = append([]string{}, r.SensitivePaths...)
	p.ProbeEnabled = r.ProbeEnabled
	p.StripUnauthorizedScripts = r.StripUnauthorizedScripts
	p.AllowedScriptOrigins = append([]string{}, r.AllowedScriptOrigins...)
	p.AllowedConnectOrigins = append([]string{}, r.AllowedConnectOrigins...)
	p.AllowedFormOrigins = append([]string{}, r.AllowedFormOrigins...)
	p.CustomCSPDirectives = r.CustomCSPDirectives
	NormalizePolicy(p)
	return p
}

type createScriptRequest struct {
	ApplicationID string `json:"application_id"`
	ScriptURL     string `json:"script_url"`
	ScriptType    string `json:"script_type"`
	SRIHash       string `json:"sri_hash"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

type updateScriptRequest struct {
	SRIHash       string `json:"sri_hash"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

type updateViolationStatusRequest struct {
	Status string `json:"status"`
	Note   string `json:"note"`
}

// ---------- 应用级策略接口 ----------

// GetPolicy GET /api/v1/applications/{id}/client-side-policy
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

// PutPolicy PUT /api/v1/applications/{id}/client-side-policy
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

// ---------- 脚本资产清单接口 ----------

// ListScripts GET /api/v1/client-side/scripts
func (h *Handler) ListScripts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := ScriptFilter{
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
	if f.Status != "" && !validScriptStatus(f.Status) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的 status 筛选值")
		return
	}
	f.Page, f.PageSize = normalizePage(f.Page, f.PageSize)

	items, total, err := h.store.ListScripts(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if items == nil {
		items = []Script{}
	}
	response.Page(w, r, items, total, f.Page, f.PageSize)
}

// CreateScript POST /api/v1/client-side/scripts
func (h *Handler) CreateScript(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	var req createScriptRequest
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	appID, err := uuid.Parse(strings.TrimSpace(req.ApplicationID))
	if err != nil {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "脚本校验未通过",
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
		status = ScriptStatusAuthorized
	}
	sc := Script{
		ApplicationID: appID,
		ScriptURL:     req.ScriptURL,
		ScriptType:    req.ScriptType,
		SRIHash:       req.SRIHash,
		Status:        status,
		Justification: req.Justification,
	}
	NormalizeScript(&sc)
	if errs := ValidateCreateScript(&sc); len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "脚本校验未通过", errs)
		return
	}
	if sc.Status == ScriptStatusAuthorized {
		now := time.Now().UTC()
		sc.ApprovedBy = principalUsername(principal)
		sc.ApprovedAt = &now
	}

	if err := h.store.CreateScript(r.Context(), &sc); err != nil {
		if errors.Is(err, ErrConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "该应用下已存在同类型的脚本记录")
			return
		}
		var ve *ValidationError
		if errors.As(err, &ve) {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "脚本校验未通过", ve.Errors)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordScriptAudit(r, principal, "create", nil, &sc)
	response.JSON(w, r, http.StatusCreated, map[string]interface{}{"script": sc})
}

// UpdateScript PUT /api/v1/client-side/scripts/{id}
func (h *Handler) UpdateScript(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的脚本 ID")
		return
	}
	before, err := h.store.GetScript(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "脚本记录不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}

	var req updateScriptRequest
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	sriHash := strings.TrimSpace(req.SRIHash)
	status := strings.ToUpper(strings.TrimSpace(req.Status))
	justification := strings.TrimSpace(req.Justification)
	if errs := ValidateUpdateScript(sriHash, status, justification); len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "脚本审批校验未通过", errs)
		return
	}

	var approvedBy string
	var approvedAt *time.Time
	if status == ScriptStatusAuthorized {
		now := time.Now().UTC()
		approvedBy = principalUsername(principal)
		approvedAt = &now
	}

	updated, err := h.store.UpdateScript(r.Context(), id, sriHash, status, justification, approvedBy, approvedAt)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "脚本记录不存在")
			return
		}
		var ve *ValidationError
		if errors.As(err, &ve) {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "脚本审批校验未通过", ve.Errors)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordScriptAudit(r, principal, "update", before, updated)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"script": updated})
}

// DeleteScript DELETE /api/v1/client-side/scripts/{id}
func (h *Handler) DeleteScript(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的脚本 ID")
		return
	}
	before, err := h.store.GetScript(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "脚本记录不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.DeleteScript(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "脚本记录不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordScriptAudit(r, principal, "delete", before, nil)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"deleted": true,
		"id":      id.String(),
	})
}

// ---------- 违规与篡改告警接口 ----------

// ListViolations GET /api/v1/client-side/violations
func (h *Handler) ListViolations(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := ViolationFilter{
		ViolationType: strings.ToUpper(strings.TrimSpace(q.Get("violation_type"))),
		Status:        strings.ToUpper(strings.TrimSpace(q.Get("status"))),
		Page:          queryInt(r, "page", 1),
		PageSize:      queryInt(r, "page_size", 20),
	}
	if rawAppID := strings.TrimSpace(q.Get("application_id")); rawAppID != "" {
		id, err := uuid.Parse(rawAppID)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的 application_id")
			return
		}
		f.ApplicationID = &id
	}
	if f.ViolationType != "" && !validViolationType(f.ViolationType) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的 violation_type 筛选值")
		return
	}
	if f.Status != "" && !validViolationStatus(f.Status) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的 status 筛选值")
		return
	}
	f.Page, f.PageSize = normalizePage(f.Page, f.PageSize)

	items, total, err := h.store.ListViolations(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if items == nil {
		items = []Violation{}
	}
	response.Page(w, r, items, total, f.Page, f.PageSize)
}

// UpdateViolationStatus PUT /api/v1/client-side/violations/{id}/status
func (h *Handler) UpdateViolationStatus(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的违规记录 ID")
		return
	}
	before, err := h.store.GetViolation(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "违规记录不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}

	var req updateViolationStatusRequest
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	status := strings.ToUpper(strings.TrimSpace(req.Status))
	note := strings.TrimSpace(req.Note)
	if errs := ValidateViolationStatusUpdate(status, note); len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "违规处置参数校验未通过", errs)
		return
	}

	updated, err := h.store.UpdateViolationStatus(r.Context(), id, status, note, principalUsername(principal), time.Now().UTC())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "违规记录不存在")
			return
		}
		var ve *ValidationError
		if errors.As(err, &ve) {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "违规处置参数校验未通过", ve.Errors)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordViolationAudit(r, principal, before, updated)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"violation": updated})
}

// ---------- PCI DSS 4.0 合规证据导出 ----------

// ExportCompliance GET /api/v1/client-side/compliance-export
func (h *Handler) ExportCompliance(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	var appID *uuid.UUID
	if rawAppID := strings.TrimSpace(r.URL.Query().Get("application_id")); rawAppID != "" {
		id, err := uuid.Parse(rawAppID)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的 application_id")
			return
		}
		appID = &id
	}
	scripts, violations, summary, err := h.store.ExportComplianceData(r.Context(), appID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	csvData := RenderComplianceCSV(scripts, violations, summary)
	h.recordExportAudit(r, principal, appID, len(scripts), len(violations))

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="pci-dss-client-side-compliance.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(csvData))
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
		"mode":                       p.Mode,
		"version":                    p.Version,
		"csp_mode":                   p.CSPMode,
		"probe_enabled":              p.ProbeEnabled,
		"strip_unauthorized_scripts": p.StripUnauthorizedScripts,
		"sensitive_paths_count":      len(p.SensitivePaths),
		"allowed_script_origins":     len(p.AllowedScriptOrigins),
		"allowed_connect_origins":    len(p.AllowedConnectOrigins),
		"allowed_form_origins":       len(p.AllowedFormOrigins),
		"reason":                     reason,
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
	if after != nil && (after.Mode == ModeProtect || after.CSPMode == CSPModeEnforce) {
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
		ObjectType:    "client_side_policy",
		ObjectID:      objID,
		ObjectName:    app.Code,
		BeforeSummary: string(beforeJSON),
		AfterSummary:  string(afterJSON),
		Result:        audits.ResultSuccess,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

func summarizeScript(s *Script) map[string]interface{} {
	if s == nil {
		return nil
	}
	return map[string]interface{}{
		"application_id": s.ApplicationID.String(),
		"script_url":     s.ScriptURL,
		"script_type":    s.ScriptType,
		"sri_hash":       s.SRIHash,
		"status":         s.Status,
		"justification":  s.Justification,
		"approved_by":    s.ApprovedBy,
	}
}

func (h *Handler) recordScriptAudit(r *http.Request, p *authz.Principal, action string, before, after *Script) {
	if p == nil || h.audits == nil {
		return
	}
	var beforeJSON, afterJSON []byte
	if before != nil {
		beforeJSON, _ = json.Marshal(summarizeScript(before))
	}
	if after != nil {
		afterJSON, _ = json.Marshal(summarizeScript(after))
	}
	objID, objName := "", ""
	if after != nil {
		objID, objName = after.ID.String(), after.ScriptURL
	} else if before != nil {
		objID, objName = before.ID.String(), before.ScriptURL
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "security",
		Action:        action,
		ObjectType:    "client_script_inventory",
		ObjectID:      objID,
		ObjectName:    trimMax(objName, 255),
		BeforeSummary: string(beforeJSON),
		AfterSummary:  string(afterJSON),
		Result:        audits.ResultSuccess,
		RiskLevel:     audits.RiskMedium,
		RequestID:     response.RequestIDFrom(r),
	})
}

func (h *Handler) recordViolationAudit(r *http.Request, p *authz.Principal, before, after *Violation) {
	if p == nil || h.audits == nil {
		return
	}
	beforeJSON, _ := json.Marshal(map[string]interface{}{"status": before.Status, "note": before.Note})
	afterJSON, _ := json.Marshal(map[string]interface{}{"status": after.Status, "note": after.Note})
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "security",
		Action:        "update_status",
		ObjectType:    "client_side_violation",
		ObjectID:      after.ID.String(),
		ObjectName:    after.ViolationType,
		BeforeSummary: string(beforeJSON),
		AfterSummary:  string(afterJSON),
		Result:        audits.ResultSuccess,
		RiskLevel:     audits.RiskLow,
		RequestID:     response.RequestIDFrom(r),
	})
}

func (h *Handler) recordExportAudit(r *http.Request, p *authz.Principal, appID *uuid.UUID, scriptsCount, violationsCount int) {
	if p == nil || h.audits == nil {
		return
	}
	objID := "all"
	if appID != nil {
		objID = appID.String()
	}
	afterJSON, _ := json.Marshal(map[string]interface{}{
		"application_id":   objID,
		"scripts_count":    scriptsCount,
		"violations_count": violationsCount,
	})
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "security",
		Action:       "export",
		ObjectType:   "client_side_compliance",
		ObjectID:     objID,
		ObjectName:   "pci-dss-client-side-compliance.csv",
		AfterSummary: string(afterJSON),
		Result:       audits.ResultSuccess,
		RiskLevel:    audits.RiskMedium,
		RequestID:    response.RequestIDFrom(r),
	})
}
