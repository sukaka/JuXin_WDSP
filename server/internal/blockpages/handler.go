// handler.go 自定义拦截页面与多版本管理 HTTP 接口：
//
//	GET    /api/v1/block-pages                模板分页列表 + 内置主题/变量/场景目录（block_pages.read）
//	POST   /api/v1/block-pages                新建模板 v1，支持可视化/源码与从已有模板复制（block_pages.manage）
//	POST   /api/v1/block-pages/preview        无状态安全渲染预览（block_pages.read）
//	GET    /api/v1/block-pages/bindings       生效绑定列表（block_pages.read）
//	PUT    /api/v1/block-pages/bindings       创建/更新生效绑定（block_pages.manage）
//	DELETE /api/v1/block-pages/bindings/{id}  解除生效绑定（block_pages.manage）
//	GET    /api/v1/block-pages/{id}           模板详情 + 不可变修订历史 + 绑定引用（block_pages.read）
//	PUT    /api/v1/block-pages/{id}           乐观锁更新并追加新修订版本（block_pages.manage）
//	POST   /api/v1/block-pages/{id}/rollback  回滚到历史版本（追加 version+1）（block_pages.manage）
//	DELETE /api/v1/block-pages/{id}           删除自定义模板（block_pages.manage）
package blockpages

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

// AppGetter 应用存在性校验接口（*applications.Store 实现）。
type AppGetter interface {
	GetByID(ctx context.Context, id uuid.UUID) (*applications.Application, error)
}

type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// Handler 自定义拦截页面 HTTP 处理器。
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

type createPageRequest struct {
	Name             string        `json:"name"`
	Description      string        `json:"description"`
	EditorMode       string        `json:"editor_mode"`
	Theme            string        `json:"theme"`
	VisualConfig     *VisualConfig `json:"visual_config"`
	HTMLContent      string        `json:"html_content"`
	StatusCode       int           `json:"status_code"`
	JSONCode         string        `json:"json_code"`
	JSONMessage      string        `json:"json_message"`
	ChangeNote       string        `json:"change_note"`
	CloneFromID      *string       `json:"clone_from_id"`
	CloneFromVersion *int          `json:"clone_from_version"`
}

type updatePageRequest struct {
	ExpectedVersion int           `json:"expected_version"`
	Name            string        `json:"name"`
	Description     string        `json:"description"`
	EditorMode      string        `json:"editor_mode"`
	Theme           string        `json:"theme"`
	VisualConfig    *VisualConfig `json:"visual_config"`
	HTMLContent     string        `json:"html_content"`
	StatusCode      int           `json:"status_code"`
	JSONCode        string        `json:"json_code"`
	JSONMessage     string        `json:"json_message"`
	ChangeNote      string        `json:"change_note"`
}

type rollbackPageRequest struct {
	ExpectedVersion int    `json:"expected_version"`
	TargetVersion   int    `json:"target_version"`
	ChangeNote      string `json:"change_note"`
}

type previewRequest struct {
	BlockPageID  *string       `json:"block_page_id"`
	Version      *int          `json:"version"`
	EditorMode   string        `json:"editor_mode"`
	Theme        string        `json:"theme"`
	VisualConfig *VisualConfig `json:"visual_config"`
	HTMLContent  string        `json:"html_content"`
	StatusCode   int           `json:"status_code"`
	Scene        string        `json:"scene"`
	SampleDomain string        `json:"sample_domain"`
	SamplePath   string        `json:"sample_path"`
	SampleIP     string        `json:"sample_ip"`
	SampleApp    string        `json:"sample_app_code"`
}

type upsertBindingRequest struct {
	ApplicationID *string `json:"application_id"`
	Scene         string  `json:"scene"`
	BlockPageID   string  `json:"block_page_id"`
	PinnedVersion *int    `json:"pinned_version"`
	Enabled       *bool   `json:"enabled"`
}

// List GET /api/v1/block-pages
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := ListFilter{
		Keyword:  strings.TrimSpace(q.Get("keyword")),
		Page:     DefaultPage,
		PageSize: DefaultPageSize,
	}
	if rawMode := strings.ToUpper(strings.TrimSpace(q.Get("editor_mode"))); rawMode != "" {
		if !ValidEditorMode(rawMode) {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "查询参数非法",
				[]FieldError{{Field: "editor_mode", Message: "仅支持 VISUAL 或 HTML"}})
			return
		}
		filter.EditorMode = rawMode
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
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"items":        items,
		"total":        total,
		"page":         filter.Page,
		"page_size":    filter.PageSize,
		"themes":       BuiltinThemes(),
		"placeholders": SupportedPlaceholders(),
		"scenes":       SupportedScenes(),
	})
}

// Create POST /api/v1/block-pages
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())

	var req createPageRequest
	if err := response.DecodeJSON(w, r, &req, MaxRequestBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误或体积超过上限")
		return
	}

	mode := strings.ToUpper(strings.TrimSpace(req.EditorMode))
	theme := strings.TrimSpace(req.Theme)
	vc := DefaultVisualConfig()
	if req.VisualConfig != nil {
		vc = *req.VisualConfig
	}
	htmlContent := req.HTMLContent
	statusCode := req.StatusCode
	jsonCode := strings.TrimSpace(req.JSONCode)
	jsonMessage := strings.TrimSpace(req.JSONMessage)
	description := strings.TrimSpace(req.Description)
	changeNote := strings.TrimSpace(req.ChangeNote)

	// 支持从现有模板（或指定历史版本）克隆创建新模板
	if req.CloneFromID != nil && strings.TrimSpace(*req.CloneFromID) != "" {
		srcID, err := uuid.Parse(strings.TrimSpace(*req.CloneFromID))
		if err != nil {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "参数校验未通过",
				[]FieldError{{Field: "clone_from_id", Message: "非法的源模板 ID"}})
			return
		}
		if req.CloneFromVersion != nil && *req.CloneFromVersion > 0 {
			sv, err := h.store.GetVersion(r.Context(), srcID, *req.CloneFromVersion)
			if err != nil {
				if errors.Is(err, ErrVersionNotFound) {
					response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "指定的源模板历史版本不存在")
					return
				}
				response.InternalError(w, r, err)
				return
			}
			mode, theme, vc, htmlContent = sv.EditorMode, sv.Theme, sv.VisualConfig, sv.HTMLContent
			statusCode, jsonCode, jsonMessage = sv.StatusCode, sv.JSONCode, sv.JSONMessage
			if changeNote == "" {
				changeNote = fmt.Sprintf("复制自模板版本 v%d", sv.Version)
			}
		} else {
			sp, err := h.store.GetByID(r.Context(), srcID)
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "源模板不存在")
					return
				}
				response.InternalError(w, r, err)
				return
			}
			mode, theme, vc, htmlContent = sp.EditorMode, sp.Theme, sp.VisualConfig, sp.HTMLContent
			statusCode, jsonCode, jsonMessage = sp.StatusCode, sp.JSONCode, sp.JSONMessage
			if description == "" {
				description = sp.Description
			}
			if changeNote == "" {
				changeNote = fmt.Sprintf("复制自「%s」v%d", sp.Name, sp.Version)
			}
		}
	}

	if mode == "" {
		mode = EditorModeVisual
	}

	compiled, errs := CompileAndValidate(CompileInput{
		Name:         req.Name,
		CheckName:    true,
		Description:  description,
		EditorMode:   mode,
		Theme:        theme,
		VisualConfig: vc,
		HTMLContent:  htmlContent,
		StatusCode:   statusCode,
		JSONCode:     jsonCode,
		JSONMessage:  jsonMessage,
		ChangeNote:   changeNote,
	})
	if len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "拦截页配置校验未通过", errs)
		return
	}

	page, ver, err := h.store.Create(r.Context(), CreateInput{
		Name:         strings.TrimSpace(req.Name),
		Description:  description,
		EditorMode:   mode,
		Theme:        compiled.Theme,
		VisualConfig: vc,
		HTMLContent:  htmlContent,
		RenderedHTML: compiled.RenderedHTML,
		StatusCode:   statusCode,
		JSONCode:     jsonCode,
		JSONMessage:  jsonMessage,
		ChangeNote:   changeNote,
		CreatedBy:    principalUsername(principal),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrDuplicateName):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "已存在同名拦截页模板")
		case errors.Is(err, ErrTemplateLimitReached):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, fmt.Sprintf("拦截页模板总数已达上限（%d 个）", MaxTemplatesTotal))
		default:
			response.InternalError(w, r, err)
		}
		return
	}

	h.recordPageAudit(r, principal, "create", nil, page, changeNote, 0)
	response.JSON(w, r, http.StatusCreated, map[string]interface{}{
		"block_page": page,
		"version":    ver,
		"warnings":   compiled.Warnings,
	})
}

// Get GET /api/v1/block-pages/{id}
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的模板 ID")
		return
	}
	page, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "拦截页模板不存在")
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
	bindings, err := h.store.ListBindingsByPage(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"block_page": page,
		"versions":   versions,
		"bindings":   bindings,
	})
}

// Update PUT /api/v1/block-pages/{id}
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的模板 ID")
		return
	}

	var req updatePageRequest
	if err := response.DecodeJSON(w, r, &req, MaxRequestBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误或体积超过上限")
		return
	}
	if req.ExpectedVersion < 1 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "参数校验未通过",
			[]FieldError{{Field: "expected_version", Message: "expected_version 必须为大于等于 1 的整数"}})
		return
	}

	before, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "拦截页模板不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = before.Name
	}
	mode := strings.ToUpper(strings.TrimSpace(req.EditorMode))
	if mode == "" {
		mode = before.EditorMode
	}
	vc := before.VisualConfig
	if req.VisualConfig != nil {
		vc = *req.VisualConfig
	}

	compiled, errs := CompileAndValidate(CompileInput{
		Name:         name,
		CheckName:    true,
		Description:  strings.TrimSpace(req.Description),
		EditorMode:   mode,
		Theme:        strings.TrimSpace(req.Theme),
		VisualConfig: vc,
		HTMLContent:  req.HTMLContent,
		StatusCode:   req.StatusCode,
		JSONCode:     strings.TrimSpace(req.JSONCode),
		JSONMessage:  strings.TrimSpace(req.JSONMessage),
		ChangeNote:   strings.TrimSpace(req.ChangeNote),
	})
	if len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "拦截页配置校验未通过", errs)
		return
	}

	updated, ver, err := h.store.Update(r.Context(), UpdateInput{
		ID:              id,
		ExpectedVersion: req.ExpectedVersion,
		Name:            name,
		Description:     strings.TrimSpace(req.Description),
		EditorMode:      mode,
		Theme:           compiled.Theme,
		VisualConfig:    vc,
		HTMLContent:     req.HTMLContent,
		RenderedHTML:    compiled.RenderedHTML,
		StatusCode:      req.StatusCode,
		JSONCode:        strings.TrimSpace(req.JSONCode),
		JSONMessage:     strings.TrimSpace(req.JSONMessage),
		ChangeNote:      strings.TrimSpace(req.ChangeNote),
		UpdatedBy:       principalUsername(principal),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "拦截页模板不存在")
		case errors.Is(err, ErrConflict):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "模板已被他人修改，请刷新后重试")
		case errors.Is(err, ErrDuplicateName):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "已存在同名拦截页模板")
		default:
			response.InternalError(w, r, err)
		}
		return
	}

	h.recordPageAudit(r, principal, "update", before, updated, strings.TrimSpace(req.ChangeNote), 0)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"block_page": updated,
		"version":    ver,
		"warnings":   compiled.Warnings,
	})
}

// Rollback POST /api/v1/block-pages/{id}/rollback
func (h *Handler) Rollback(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的模板 ID")
		return
	}

	var req rollbackPageRequest
	if err := response.DecodeJSON(w, r, &req, MaxRequestBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	var errs []FieldError
	if req.ExpectedVersion < 1 {
		errs = append(errs, FieldError{Field: "expected_version", Message: "expected_version 必须为大于等于 1 的整数"})
	}
	if req.TargetVersion < 1 {
		errs = append(errs, FieldError{Field: "target_version", Message: "target_version 必须为大于等于 1 的整数"})
	}
	if len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "参数校验未通过", errs)
		return
	}

	before, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "拦截页模板不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}

	updated, ver, err := h.store.Rollback(r.Context(), RollbackInput{
		ID:              id,
		ExpectedVersion: req.ExpectedVersion,
		TargetVersion:   req.TargetVersion,
		ChangeNote:      strings.TrimSpace(req.ChangeNote),
		UpdatedBy:       principalUsername(principal),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "拦截页模板不存在")
		case errors.Is(err, ErrVersionNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "目标历史版本不存在")
		case errors.Is(err, ErrConflict):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "模板已被他人修改，请刷新后重试")
		default:
			response.InternalError(w, r, err)
		}
		return
	}

	h.recordPageAudit(r, principal, "rollback", before, updated, strings.TrimSpace(req.ChangeNote), req.TargetVersion)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"block_page": updated,
		"version":    ver,
	})
}

// Delete DELETE /api/v1/block-pages/{id}
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的模板 ID")
		return
	}
	before, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "拦截页模板不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.Delete(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, ErrBuiltinProtected):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "系统内置预设模板不可删除，可复制后自由编辑或取消生效绑定")
		case errors.Is(err, ErrInUse):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "该模板已被全局或应用绑定使用，请先解除绑定后再删除")
		case errors.Is(err, ErrNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "拦截页模板不存在")
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	h.recordPageAudit(r, principal, "delete", before, nil, "", 0)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"deleted": true,
		"id":      id.String(),
	})
}

// Preview POST /api/v1/block-pages/preview
func (h *Handler) Preview(w http.ResponseWriter, r *http.Request) {
	var req previewRequest
	if err := response.DecodeJSON(w, r, &req, MaxRequestBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误或体积超过上限")
		return
	}

	var (
		templateHTML string
		warnings     []string
		statusCode   = req.StatusCode
	)

	// 支持按已有模板 + 可选历史版本快捷预览
	if req.BlockPageID != nil && strings.TrimSpace(*req.BlockPageID) != "" {
		pid, err := uuid.Parse(strings.TrimSpace(*req.BlockPageID))
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的模板 ID")
			return
		}
		if req.Version != nil && *req.Version > 0 {
			ver, err := h.store.GetVersion(r.Context(), pid, *req.Version)
			if err != nil {
				if errors.Is(err, ErrVersionNotFound) {
					response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "目标历史版本不存在")
					return
				}
				response.InternalError(w, r, err)
				return
			}
			templateHTML = ver.RenderedHTML
			if statusCode == 0 {
				statusCode = ver.StatusCode
			}
		} else {
			page, err := h.store.GetByID(r.Context(), pid)
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "拦截页模板不存在")
					return
				}
				response.InternalError(w, r, err)
				return
			}
			templateHTML = page.RenderedHTML
			if statusCode == 0 {
				statusCode = page.StatusCode
			}
		}
	} else {
		mode := strings.ToUpper(strings.TrimSpace(req.EditorMode))
		if mode == "" {
			mode = EditorModeVisual
		}
		vc := DefaultVisualConfig()
		if req.VisualConfig != nil {
			vc = *req.VisualConfig
		}
		compiled, errs := CompileAndValidate(CompileInput{
			CheckName:    false,
			EditorMode:   mode,
			Theme:        strings.TrimSpace(req.Theme),
			VisualConfig: vc,
			HTMLContent:  req.HTMLContent,
			StatusCode:   req.StatusCode,
		})
		if len(errs) > 0 {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "预览内容校验未通过", errs)
			return
		}
		templateHTML = compiled.RenderedHTML
		warnings = compiled.Warnings
	}

	scene := strings.ToUpper(strings.TrimSpace(req.Scene))
	if !ValidScene(scene) {
		scene = SceneWAF
	}
	effectiveStatus := statusCode
	if effectiveStatus == 0 {
		if scene == SceneRateLimit {
			effectiveStatus = http.StatusTooManyRequests
		} else {
			effectiveStatus = http.StatusForbidden
		}
	}
	nowUTC := time.Now().UTC()
	cst := time.FixedZone("CST", 8*3600)
	domain := strings.TrimSpace(req.SampleDomain)
	if domain == "" {
		domain = "shop.example.com"
	}
	samplePath := strings.TrimSpace(req.SamplePath)
	if samplePath == "" {
		samplePath = "/api/v1/orders"
	}
	sampleIP := strings.TrimSpace(req.SampleIP)
	if sampleIP == "" {
		sampleIP = "203.0.113.42"
	}
	sampleApp := strings.TrimSpace(req.SampleApp)
	if sampleApp == "" {
		sampleApp = "demo-app"
	}
	retryAfter := "-"
	if scene == SceneRateLimit {
		retryAfter = "60"
	}

	rendered := SubstitutePlaceholders(templateHTML, PlaceholderValues{
		RequestID:  "req-preview-8f2a9c41",
		TimeUTC:    nowUTC.Format("2006-01-02 15:04:05 UTC"),
		TimeLocal:  nowUTC.In(cst).Format("2006-01-02 15:04:05 +0800"),
		ClientIP:   sampleIP,
		Domain:     domain,
		Path:       samplePath,
		StatusCode: strconv.Itoa(effectiveStatus),
		Scene:      scene,
		SceneLabel: SceneLabel(scene),
		AppCode:    sampleApp,
		RetryAfter: retryAfter,
		Message:    "当前请求触发安全防护策略，已被拦截",
	})

	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"rendered_html":           rendered,
		"sanitized_template_html": templateHTML,
		"warnings":                warnings,
		"byte_size":               len(templateHTML),
		"max_bytes":               MaxHTMLBytes,
		"effective_status_code":   effectiveStatus,
	})
}

// ListBindings GET /api/v1/block-pages/bindings
func (h *Handler) ListBindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var filter BindingFilter
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
	if rawScene := strings.ToUpper(strings.TrimSpace(q.Get("scene"))); rawScene != "" {
		if !ValidScene(rawScene) {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "查询参数非法",
				[]FieldError{{Field: "scene", Message: "场景仅支持 DEFAULT / WAF / ACCESS_CONTROL / RATE_LIMIT"}})
			return
		}
		filter.Scene = rawScene
	}

	items, err := h.store.ListBindings(r.Context(), filter)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"items": items,
	})
}

// UpsertBinding PUT /api/v1/block-pages/bindings
func (h *Handler) UpsertBinding(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())

	var req upsertBindingRequest
	if err := response.DecodeJSON(w, r, &req, MaxRequestBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}

	var (
		errs  []FieldError
		appID *uuid.UUID
	)
	if req.ApplicationID != nil {
		trimmed := strings.TrimSpace(*req.ApplicationID)
		if trimmed != "" && !strings.EqualFold(trimmed, "global") {
			parsed, err := uuid.Parse(trimmed)
			if err != nil {
				errs = append(errs, FieldError{Field: "application_id", Message: "非法的应用 ID"})
			} else {
				appID = &parsed
			}
		}
	}
	scene := strings.ToUpper(strings.TrimSpace(req.Scene))
	if scene == "" {
		scene = SceneDefault
	}
	if !ValidScene(scene) {
		errs = append(errs, FieldError{Field: "scene", Message: "场景仅支持 DEFAULT / WAF / ACCESS_CONTROL / RATE_LIMIT"})
	}
	pageID, err := uuid.Parse(strings.TrimSpace(req.BlockPageID))
	if err != nil {
		errs = append(errs, FieldError{Field: "block_page_id", Message: "非法的拦截页模板 ID"})
	}
	if req.PinnedVersion != nil && *req.PinnedVersion < 1 {
		errs = append(errs, FieldError{Field: "pinned_version", Message: "锁定版本号必须大于等于 1"})
	}
	if len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "绑定参数校验未通过", errs)
		return
	}

	if appID != nil && h.apps != nil {
		if _, err := h.apps.GetByID(r.Context(), *appID); err != nil {
			if errors.Is(err, applications.ErrNotFound) {
				response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "目标应用不存在")
				return
			}
			response.InternalError(w, r, err)
			return
		}
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	binding, err := h.store.UpsertBinding(r.Context(), UpsertBindingInput{
		ApplicationID: appID,
		Scene:         scene,
		BlockPageID:   pageID,
		PinnedVersion: req.PinnedVersion,
		Enabled:       enabled,
		UpdatedBy:     principalUsername(principal),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "指定的拦截页模板不存在")
		case errors.Is(err, ErrVersionNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "指定的锁定历史版本不存在")
		default:
			response.InternalError(w, r, err)
		}
		return
	}

	h.recordBindingAudit(r, principal, "bind", nil, binding)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"binding": binding,
	})
}

// DeleteBinding DELETE /api/v1/block-pages/bindings/{id}
func (h *Handler) DeleteBinding(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的绑定 ID")
		return
	}
	before, err := h.store.GetBindingByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "拦截页绑定不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.DeleteBinding(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "拦截页绑定不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordBindingAudit(r, principal, "unbind", before, nil)
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

func summarizePage(p *BlockPage, changeNote string, targetVersion int) map[string]interface{} {
	if p == nil {
		return nil
	}
	m := map[string]interface{}{
		"name":        p.Name,
		"editor_mode": p.EditorMode,
		"theme":       p.Theme,
		"status_code": p.StatusCode,
		"version":     p.Version,
		"html_bytes":  len(p.RenderedHTML),
		"is_builtin":  p.IsBuiltin,
	}
	if changeNote != "" {
		m["change_note"] = changeNote
	}
	if targetVersion > 0 {
		m["target_version"] = targetVersion
	}
	return m
}

func (h *Handler) recordPageAudit(r *http.Request, p *authz.Principal, action string, before, after *BlockPage, changeNote string, targetVersion int) {
	if p == nil || h.audits == nil {
		return
	}
	var beforeJSON, afterJSON []byte
	if before != nil {
		beforeJSON, _ = json.Marshal(summarizePage(before, "", 0))
	}
	if after != nil {
		afterJSON, _ = json.Marshal(summarizePage(after, changeNote, targetVersion))
	}
	target := after
	if target == nil {
		target = before
	}
	objID, objName := "", ""
	if target != nil {
		objID = target.ID.String()
		objName = target.Name
	}
	risk := audits.RiskMedium
	if action == "delete" || action == "rollback" {
		risk = audits.RiskHigh
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "block_pages",
		Action:        action,
		ObjectType:    "block_page",
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: string(beforeJSON),
		AfterSummary:  string(afterJSON),
		Result:        audits.ResultSuccess,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

func (h *Handler) recordBindingAudit(r *http.Request, p *authz.Principal, action string, before, after *BlockPageBinding) {
	if p == nil || h.audits == nil {
		return
	}
	var beforeJSON, afterJSON []byte
	if before != nil {
		beforeJSON, _ = json.Marshal(before)
	}
	if after != nil {
		afterJSON, _ = json.Marshal(after)
	}
	target := after
	if target == nil {
		target = before
	}
	objID, objName := "", ""
	if target != nil {
		objID = target.ID.String()
		scope := "全局默认"
		if target.ApplicationCode != "" {
			scope = target.ApplicationCode
		}
		objName = fmt.Sprintf("%s/%s -> %s", scope, target.Scene, target.BlockPageName)
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "block_pages",
		Action:        action,
		ObjectType:    "block_page_binding",
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: string(beforeJSON),
		AfterSummary:  string(afterJSON),
		Result:        audits.ResultSuccess,
		RiskLevel:     audits.RiskMedium,
		RequestID:     response.RequestIDFrom(r),
	})
}
