// handler.go Wasm 自定义检测插件管理面 HTTP 接口（Phase 9D-1；路由在 app.go 注册）：
//
//	GET    /api/v1/wasm-plugins               分页列表（wasm_plugins.read；绝不返回 wasm_binary/wasm_base64）
//	POST   /api/v1/wasm-plugins               上传并创建插件 v1（wasm_plugins.manage）
//	GET    /api/v1/wasm-plugins/{id}          插件详情 + 不可变版本历史（wasm_plugins.read；绝不返回二进制）
//	PUT    /api/v1/wasm-plugins/{id}          更新配置或替换二进制（wasm_plugins.manage；409 乐观锁冲突）
//	POST   /api/v1/wasm-plugins/{id}/rollback 回滚到历史版本（wasm_plugins.manage；克隆为 version+1）
//	DELETE /api/v1/wasm-plugins/{id}          删除插件（wasm_plugins.manage）
package wasmplugins

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

// Handler 是 Wasm 检测插件 HTTP 处理器。
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

type createPluginRequest struct {
	Name           string   `json:"name"`
	ApplicationID  *string  `json:"application_id"`
	Description    *string  `json:"description"`
	ABIVersion     string   `json:"abi_version"`
	Mode           string   `json:"mode"`
	WasmBase64     string   `json:"wasm_base64"`
	ExpectedSHA256 string   `json:"expected_sha256"`
	Priority       *int     `json:"priority"`
	TimeoutMs      *int     `json:"timeout_ms"`
	MaxMemoryKB    *int     `json:"max_memory_kb"`
	MaxBodyBytes   *int     `json:"max_body_bytes"`
	FailPolicy     *string  `json:"fail_policy"`
	PathPrefixes   []string `json:"path_prefixes"`
	Reason         string   `json:"reason"`
}

type updatePluginRequest struct {
	ExpectedVersion int      `json:"expected_version"`
	Description     *string  `json:"description"`
	ABIVersion      string   `json:"abi_version"`
	Mode            string   `json:"mode"`
	WasmBase64      *string  `json:"wasm_base64"`
	ExpectedSHA256  string   `json:"expected_sha256"`
	Priority        *int     `json:"priority"`
	TimeoutMs       *int     `json:"timeout_ms"`
	MaxMemoryKB     *int     `json:"max_memory_kb"`
	MaxBodyBytes    *int     `json:"max_body_bytes"`
	FailPolicy      *string  `json:"fail_policy"`
	PathPrefixes    []string `json:"path_prefixes"`
	Reason          string   `json:"reason"`
}

type rollbackPluginRequest struct {
	TargetVersion   int    `json:"target_version"`
	ExpectedVersion int    `json:"expected_version"`
	Reason          string `json:"reason"`
}

// List GET /api/v1/wasm-plugins
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := ListFilter{
		Keyword:  strings.TrimSpace(q.Get("keyword")),
		Page:     DefaultPage,
		PageSize: DefaultPageSize,
	}

	if rawApp := strings.TrimSpace(q.Get("application_id")); rawApp != "" {
		if strings.EqualFold(rawApp, "global") {
			filter.GlobalOnly = true
		} else {
			appID, err := uuid.Parse(rawApp)
			if err != nil {
				response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "查询参数非法",
					[]FieldError{{Field: "application_id", Message: "application_id 必须为合法 UUID 或 global"}})
				return
			}
			filter.ApplicationID = &appID
		}
	}

	if rawMode := strings.TrimSpace(q.Get("mode")); rawMode != "" {
		mode := strings.ToUpper(rawMode)
		if !validMode(mode) {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "查询参数非法",
				[]FieldError{{Field: "mode", Message: "仅支持 OFF / OBSERVE / PROTECT"}})
			return
		}
		filter.Mode = mode
	}

	if rawPage := strings.TrimSpace(q.Get("page")); rawPage != "" {
		n, err := strconv.Atoi(rawPage)
		if err != nil || n < 1 {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "查询参数非法",
				[]FieldError{{Field: "page", Message: "page 必须为大于等于 1 的整数"}})
			return
		}
		filter.Page = n
	}
	if rawSize := strings.TrimSpace(q.Get("page_size")); rawSize != "" {
		n, err := strconv.Atoi(rawSize)
		if err != nil || n < 1 || n > MaxPageSize {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "查询参数非法",
				[]FieldError{{Field: "page_size", Message: fmt.Sprintf("page_size 必须在 1~%d 之间", MaxPageSize)}})
			return
		}
		filter.PageSize = n
	}

	items, total, err := h.store.List(r.Context(), filter)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if items == nil {
		items = []Plugin{}
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"items":     items,
		"total":     total,
		"page":      filter.Page,
		"page_size": filter.PageSize,
	})
}

// Create POST /api/v1/wasm-plugins
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())

	var req createPluginRequest
	if err := response.DecodeJSON(w, r, &req, MaxRequestBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误或体积超过上限")
		return
	}

	var appID *uuid.UUID
	if req.ApplicationID != nil {
		trimmed := strings.TrimSpace(*req.ApplicationID)
		if trimmed != "" && !strings.EqualFold(trimmed, "global") {
			parsed, err := uuid.Parse(trimmed)
			if err != nil {
				response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "插件校验未通过",
					[]FieldError{{Field: "application_id", Message: "非法的应用 ID"}})
				return
			}
			appID = &parsed
		}
	}

	name := strings.TrimSpace(req.Name)
	description := ""
	if req.Description != nil {
		description = strings.TrimSpace(*req.Description)
	}
	abiVersion := strings.TrimSpace(req.ABIVersion)
	if abiVersion == "" {
		abiVersion = ABIVersionWDSPV1
	}
	mode := strings.ToUpper(strings.TrimSpace(req.Mode))
	priority := DefaultPriority
	if req.Priority != nil {
		priority = *req.Priority
	}
	timeoutMs := DefaultTimeoutMs
	if req.TimeoutMs != nil {
		timeoutMs = *req.TimeoutMs
	}
	maxMemoryKB := DefaultMaxMemoryKB
	if req.MaxMemoryKB != nil {
		maxMemoryKB = *req.MaxMemoryKB
	}
	maxBodyBytes := DefaultMaxBodyBytes
	if req.MaxBodyBytes != nil {
		maxBodyBytes = *req.MaxBodyBytes
	}
	failPolicy := FailPolicyOpen
	if req.FailPolicy != nil {
		failPolicy = strings.ToUpper(strings.TrimSpace(*req.FailPolicy))
	}
	pathPrefixes := NormalizePathPrefixes(req.PathPrefixes)
	reason := strings.TrimSpace(req.Reason)

	errs := ValidateConfigFields(name, true, description, abiVersion, mode, priority, timeoutMs, maxMemoryKB, maxBodyBytes, failPolicy, pathPrefixes)
	if fe := ValidateReason(reason); fe != nil {
		errs = append(errs, *fe)
	}
	rawBinary, shaHex, binErrs := DecodeAndValidateWasmBase64(req.WasmBase64)
	errs = append(errs, binErrs...)
	if len(binErrs) == 0 && strings.TrimSpace(req.ExpectedSHA256) != "" {
		if msg := VerifySHA256ConstantTime(req.ExpectedSHA256, shaHex); msg != "" {
			errs = append(errs, FieldError{Field: "expected_sha256", Message: msg})
		}
	}
	if len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "插件校验未通过", errs)
		return
	}

	if appID != nil && h.apps != nil {
		if _, err := h.apps.GetByID(r.Context(), *appID); err != nil {
			if errors.Is(err, applications.ErrNotFound) {
				response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
				return
			}
			response.InternalError(w, r, err)
			return
		}
	}

	created, err := h.store.Create(r.Context(), CreateInput{
		ApplicationID: appID,
		Name:          name,
		Description:   description,
		ABIVersion:    abiVersion,
		Mode:          mode,
		SHA256:        shaHex,
		WasmBinary:    rawBinary,
		Priority:      priority,
		TimeoutMs:     timeoutMs,
		MaxMemoryKB:   maxMemoryKB,
		MaxBodyBytes:  maxBodyBytes,
		FailPolicy:    failPolicy,
		PathPrefixes:  pathPrefixes,
		Reason:        reason,
		CreatedBy:     principalUsername(principal),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrDuplicateName):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "当前作用域下已存在同名 Wasm 插件")
		case errors.Is(err, ErrScopeLimitReached):
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				fmt.Sprintf("当前作用域 Wasm 插件数量已达上限（%d 个）", MaxPluginsPerScope),
				[]FieldError{{Field: "application_id", Message: fmt.Sprintf("每个作用域最多配置 %d 个 Wasm 插件", MaxPluginsPerScope)}})
		default:
			response.InternalError(w, r, err)
		}
		return
	}

	h.recordAudit(r, principal, "create", nil, created, reason, 0)
	response.JSON(w, r, http.StatusCreated, map[string]interface{}{"plugin": created})
}

// Get GET /api/v1/wasm-plugins/{id}
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的插件 ID")
		return
	}
	plugin, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Wasm 插件不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	versions, err := h.store.ListVersions(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if versions == nil {
		versions = []PluginVersion{}
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"plugin":   plugin,
		"versions": versions,
	})
}

// Update PUT /api/v1/wasm-plugins/{id}
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的插件 ID")
		return
	}

	var req updatePluginRequest
	if err := response.DecodeJSON(w, r, &req, MaxRequestBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误或体积超过上限")
		return
	}

	errs := []FieldError{}
	if req.ExpectedVersion < 1 {
		errs = append(errs, FieldError{Field: "expected_version", Message: "expected_version 必须为大于等于 1 的整数"})
	}

	descriptionVal := ""
	var descriptionPtr *string
	if req.Description != nil {
		descriptionVal = strings.TrimSpace(*req.Description)
		descriptionPtr = &descriptionVal
	}
	abiVersion := strings.TrimSpace(req.ABIVersion)
	mode := strings.ToUpper(strings.TrimSpace(req.Mode))
	priority := DefaultPriority
	if req.Priority != nil {
		priority = *req.Priority
	}
	timeoutMs := DefaultTimeoutMs
	if req.TimeoutMs != nil {
		timeoutMs = *req.TimeoutMs
	}
	maxMemoryKB := DefaultMaxMemoryKB
	if req.MaxMemoryKB != nil {
		maxMemoryKB = *req.MaxMemoryKB
	}
	maxBodyBytes := DefaultMaxBodyBytes
	if req.MaxBodyBytes != nil {
		maxBodyBytes = *req.MaxBodyBytes
	}
	failPolicy := FailPolicyOpen
	if req.FailPolicy != nil {
		failPolicy = strings.ToUpper(strings.TrimSpace(*req.FailPolicy))
	}
	pathPrefixes := NormalizePathPrefixes(req.PathPrefixes)
	reason := strings.TrimSpace(req.Reason)

	errs = append(errs, ValidateConfigFields("", false, descriptionVal, abiVersion, mode, priority, timeoutMs, maxMemoryKB, maxBodyBytes, failPolicy, pathPrefixes)...)
	if fe := ValidateReason(reason); fe != nil {
		errs = append(errs, *fe)
	}

	var (
		rawBinary []byte
		shaHex    string
	)
	hasNewBinary := req.WasmBase64 != nil && stripBase64Whitespace(*req.WasmBase64) != ""
	if hasNewBinary {
		var binErrs []FieldError
		rawBinary, shaHex, binErrs = DecodeAndValidateWasmBase64(*req.WasmBase64)
		errs = append(errs, binErrs...)
		if len(binErrs) == 0 && strings.TrimSpace(req.ExpectedSHA256) != "" {
			if msg := VerifySHA256ConstantTime(req.ExpectedSHA256, shaHex); msg != "" {
				errs = append(errs, FieldError{Field: "expected_sha256", Message: msg})
			}
		}
	} else if strings.TrimSpace(req.ExpectedSHA256) != "" {
		if !sha256Pattern.MatchString(strings.TrimSpace(req.ExpectedSHA256)) {
			errs = append(errs, FieldError{Field: "expected_sha256", Message: "expected_sha256 必须为 64 位十六进制 SHA-256 摘要"})
		}
	}

	if len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "插件校验未通过", errs)
		return
	}

	before, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Wasm 插件不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if before.Version != req.ExpectedVersion {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "插件已被其他人修改，请刷新后重试")
		return
	}

	updated, err := h.store.Update(r.Context(), UpdateInput{
		ID:              id,
		ExpectedVersion: req.ExpectedVersion,
		Description:     descriptionPtr,
		Mode:            mode,
		SHA256:          shaHex,
		WasmBinary:      rawBinary,
		ExpectedSHA256:  strings.TrimSpace(req.ExpectedSHA256),
		Priority:        priority,
		TimeoutMs:       timeoutMs,
		MaxMemoryKB:     maxMemoryKB,
		MaxBodyBytes:    maxBodyBytes,
		FailPolicy:      failPolicy,
		PathPrefixes:    pathPrefixes,
		Reason:          reason,
		UpdatedBy:       principalUsername(principal),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Wasm 插件不存在")
		case errors.Is(err, ErrConflict):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "插件已被其他人修改，请刷新后重试")
		case errors.Is(err, ErrSHA256Mismatch):
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "插件校验未通过",
				[]FieldError{{Field: "expected_sha256", Message: "当前 Wasm 二进制 SHA-256 摘要与 expected_sha256 不一致"}})
		default:
			response.InternalError(w, r, err)
		}
		return
	}

	h.recordAudit(r, principal, "update", before, updated, reason, 0)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"plugin": updated})
}

// Rollback POST /api/v1/wasm-plugins/{id}/rollback
func (h *Handler) Rollback(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的插件 ID")
		return
	}

	var req rollbackPluginRequest
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}

	errs := []FieldError{}
	if req.TargetVersion < 1 {
		errs = append(errs, FieldError{Field: "target_version", Message: "target_version 必须为大于等于 1 的整数"})
	}
	if req.ExpectedVersion < 1 {
		errs = append(errs, FieldError{Field: "expected_version", Message: "expected_version 必须为大于等于 1 的整数"})
	}
	reason := strings.TrimSpace(req.Reason)
	if fe := ValidateReason(reason); fe != nil {
		errs = append(errs, *fe)
	}
	if len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "回滚参数校验未通过", errs)
		return
	}

	before, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Wasm 插件不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if before.Version != req.ExpectedVersion {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "插件已被其他人修改，请刷新后重试")
		return
	}

	updated, err := h.store.Rollback(r.Context(), RollbackInput{
		ID:              id,
		TargetVersion:   req.TargetVersion,
		ExpectedVersion: req.ExpectedVersion,
		Reason:          reason,
		UpdatedBy:       principalUsername(principal),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Wasm 插件不存在")
		case errors.Is(err, ErrVersionNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "目标历史版本不存在")
		case errors.Is(err, ErrConflict):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "插件已被其他人修改，请刷新后重试")
		default:
			response.InternalError(w, r, err)
		}
		return
	}

	h.recordAudit(r, principal, "rollback", before, updated, reason, req.TargetVersion)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"plugin": updated})
}

// Delete DELETE /api/v1/wasm-plugins/{id}
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的插件 ID")
		return
	}

	before, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Wasm 插件不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}

	if err := h.store.Delete(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Wasm 插件不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}

	h.recordAudit(r, principal, "delete", before, nil, "", 0)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"deleted": true,
		"id":      id.String(),
	})
}

func principalUsername(p *authz.Principal) string {
	if p == nil {
		return ""
	}
	return p.Username
}

func summarizePlugin(p *Plugin, reason string, targetVersion int) map[string]interface{} {
	if p == nil {
		return nil
	}
	m := map[string]interface{}{
		"name":           p.Name,
		"application_id": p.ApplicationID,
		"version":        p.Version,
		"abi_version":    p.ABIVersion,
		"mode":           p.Mode,
		"sha256":         p.SHA256,
		"wasm_size":      p.WasmSize,
		"priority":       p.Priority,
		"timeout_ms":     p.TimeoutMs,
		"max_memory_kb":  p.MaxMemoryKB,
		"max_body_bytes": p.MaxBodyBytes,
		"fail_policy":    p.FailPolicy,
		"path_prefixes":  p.PathPrefixes,
	}
	if reason != "" {
		m["reason"] = reason
	}
	if targetVersion > 0 {
		m["target_version"] = targetVersion
	}
	return m
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action string, before, after *Plugin, reason string, targetVersion int) {
	if p == nil || h.audits == nil {
		return
	}
	var beforeJSON, afterJSON []byte
	if before != nil {
		beforeJSON, _ = json.Marshal(summarizePlugin(before, "", 0))
	}
	if after != nil {
		afterJSON, _ = json.Marshal(summarizePlugin(after, reason, targetVersion))
	}

	target := after
	if target == nil {
		target = before
	}
	objID := ""
	objName := ""
	risk := audits.RiskMedium
	if target != nil {
		objID = target.ID.String()
		objName = target.Name
		if target.Mode == ModeProtect || target.FailPolicy == FailPolicyClosed {
			risk = audits.RiskHigh
		}
	}
	if action == "delete" || action == "rollback" {
		risk = audits.RiskHigh
	}

	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "wasm_plugins",
		Action:        action,
		ObjectType:    "wasm_plugin",
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: string(beforeJSON),
		AfterSummary:  string(afterJSON),
		Result:        audits.ResultSuccess,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}
