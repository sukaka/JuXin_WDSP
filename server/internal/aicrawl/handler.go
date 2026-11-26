// handler.go AI 爬虫治理管理面接口（Phase 9A-2；路由在 app.go 注册）：
//
//	GET    /api/v1/ai-crawl/directories              列出全部爬虫公钥目录（ai_crawl.read）
//	POST   /api/v1/ai-crawl/directories              新增爬虫公钥目录（ai_crawl.manage）
//	PUT    /api/v1/ai-crawl/directories/{id}         更新爬虫公钥目录（ai_crawl.manage）
//	DELETE /api/v1/ai-crawl/directories/{id}         删除非内置爬虫公钥目录（ai_crawl.manage）
//	POST   /api/v1/ai-crawl/directories/import       离线 JSON 包批量导入（ai_crawl.manage）
//	POST   /api/v1/ai-crawl/directories/{id}/sync    SSRF 防护手动同步 RFC 9421 目录（ai_crawl.manage）
//	GET    /api/v1/applications/{id}/ai-crawl-policy 读取应用 AI 爬虫策略草稿与状态摘要（ai_crawl.read）
//	PUT    /api/v1/applications/{id}/ai-crawl-policy 校验并保存应用 AI 爬虫策略草稿（ai_crawl.manage）
package aicrawl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/outboundhttp"
	"github.com/jiuzhang-waf/server/internal/response"
)

// AppGetter 应用查询接口（applications.Store 实现）。
type AppGetter interface {
	GetByID(ctx context.Context, id uuid.UUID) (*applications.Application, error)
}

// AllowlistFunc 读取爬虫目录同步允许清单（system_settings ai_crawl:directory_sync_allowlist）。
type AllowlistFunc func(ctx context.Context) string

// EnsureLabyrinthKeyFunc 确保加密存储的 AI 迷宫 HMAC 密钥已初始化（labyrinth_enabled=true 时调用）。
type EnsureLabyrinthKeyFunc func(ctx context.Context, operatorID uuid.UUID) error

// Handler 是 AI 爬虫治理 HTTP 处理器。
type Handler struct {
	store              *Store
	apps               AppGetter
	audits             *audits.Service
	allowlist          AllowlistFunc
	resolver           outboundhttp.Resolver
	dirFetch           func(ctx context.Context, rawURL string, policy *outboundhttp.Policy) ([]CrawlerKey, error)
	ensureLabyrinthKey EnsureLabyrinthKeyFunc
}

// NewHandler 创建处理器。
func NewHandler(store *Store, apps AppGetter, au *audits.Service) *Handler {
	return &Handler{store: store, apps: apps, audits: au}
}

// SetAllowlist 注入远程目录同步允许清单读取。
func (h *Handler) SetAllowlist(fn AllowlistFunc) { h.allowlist = fn }

// SetResolver 注入 DNS 解析器（测试用）。
func (h *Handler) SetResolver(r outboundhttp.Resolver) { h.resolver = r }

// SetDirectoryFetch 注入远程目录拉取实现（测试用；nil 时使用 FetchDirectoryKeys）。
func (h *Handler) SetDirectoryFetch(fn func(ctx context.Context, rawURL string, policy *outboundhttp.Policy) ([]CrawlerKey, error)) {
	h.dirFetch = fn
}

// SetEnsureLabyrinthKey 注入迷宫签名密钥按需初始化钩子。
func (h *Handler) SetEnsureLabyrinthKey(fn EnsureLabyrinthKeyFunc) {
	h.ensureLabyrinthKey = fn
}

func (h *Handler) outboundPolicy(ctx context.Context) (*outboundhttp.Policy, error) {
	allow := ""
	if h.allowlist != nil {
		allow = h.allowlist(ctx)
	}
	return outboundhttp.NewPolicy(outboundhttp.Options{
		Timeout:      directorySyncTimeout,
		MaxRedirects: 0,
		Resolver:     h.resolver,
		Allowlist:    allow,
	})
}

// ---------- 目录请求 DTO ----------

type directoryRequest struct {
	Slug           string       `json:"slug"`
	Name           string       `json:"name"`
	Category       string       `json:"category"`
	SignatureAgent string       `json:"signature_agent"`
	DirectoryURL   string       `json:"directory_url"`
	Keys           []CrawlerKey `json:"keys"`
	Enabled        *bool        `json:"enabled"`
}

func (r *directoryRequest) toDirectory(defaultEnabled bool) Directory {
	enabled := defaultEnabled
	if r.Enabled != nil {
		enabled = *r.Enabled
	}
	keys := make([]CrawlerKey, len(r.Keys))
	copy(keys, r.Keys)
	d := Directory{
		Slug:           r.Slug,
		Name:           r.Name,
		Category:       r.Category,
		SignatureAgent: r.SignatureAgent,
		DirectoryURL:   r.DirectoryURL,
		Keys:           keys,
		Enabled:        enabled,
	}
	NormalizeDirectory(&d)
	return d
}

type importDirectoriesRequest struct {
	Directories []directoryRequest `json:"directories"`
}

// ---------- 策略请求 DTO ----------

type putPolicyRequest struct {
	Mode                    string         `json:"mode"`
	ExpectedVersion         int            `json:"expected_version"`
	DefaultAIAction         string         `json:"default_ai_action"`
	ContentSignal           string         `json:"content_signal"`
	VerifyWebBotAuth        *bool          `json:"verify_web_bot_auth"`
	LabyrinthEnabled        bool           `json:"labyrinth_enabled"`
	LabyrinthInjectLinks    bool           `json:"labyrinth_inject_links"`
	LabyrinthMaxDepth       *int           `json:"labyrinth_max_depth"`
	LabyrinthMaxConcurrency *int           `json:"labyrinth_max_concurrency"`
	LabyrinthDelayMs        *int           `json:"labyrinth_delay_ms"`
	HTTP402                 *HTTP402Config `json:"http_402"`
	Rules                   []Rule         `json:"rules"`
	Reason                  string         `json:"reason"`
}

func (r *putPolicyRequest) toPolicy(appID uuid.UUID) *Policy {
	p := DefaultPolicy(appID)
	p.Mode = r.Mode
	p.DefaultAIAction = r.DefaultAIAction
	p.ContentSignal = r.ContentSignal
	if r.VerifyWebBotAuth != nil {
		p.VerifyWebBotAuth = *r.VerifyWebBotAuth
	}
	p.LabyrinthEnabled = r.LabyrinthEnabled
	p.LabyrinthInjectLinks = r.LabyrinthInjectLinks
	if r.LabyrinthMaxDepth != nil {
		p.LabyrinthMaxDepth = *r.LabyrinthMaxDepth
	}
	if r.LabyrinthMaxConcurrency != nil {
		p.LabyrinthMaxConcurrency = *r.LabyrinthMaxConcurrency
	}
	if r.LabyrinthDelayMs != nil {
		p.LabyrinthDelayMs = *r.LabyrinthDelayMs
	}
	if r.HTTP402 != nil {
		p.HTTP402 = *r.HTTP402
	}
	if r.Rules != nil {
		p.Rules = append([]Rule{}, r.Rules...)
	}
	NormalizePolicy(p)
	return p
}

// ---------- 目录 CRUD ----------

// ListDirectories GET /api/v1/ai-crawl/directories
func (h *Handler) ListDirectories(w http.ResponseWriter, r *http.Request) {
	items, err := h.store.ListDirectories(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": items})
}

// CreateDirectory POST /api/v1/ai-crawl/directories
func (h *Handler) CreateDirectory(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	var req directoryRequest
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	d := req.toDirectory(true)
	if errs := ValidateDirectory(&d); len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "目录校验未通过", errs)
		return
	}
	if d.DirectoryURL != "" {
		outbound, err := h.outboundPolicy(r.Context())
		if err != nil {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "目录校验未通过",
				[]FieldError{{Field: "directory_url", Message: "允许清单配置非法: " + err.Error()}})
			return
		}
		if fe := ValidateDirectoryURLSSRF(r.Context(), d.DirectoryURL, outbound); fe != nil {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "目录校验未通过", []FieldError{*fe})
			return
		}
	}
	if err := h.store.CreateDirectory(r.Context(), &d); err != nil {
		if errors.Is(err, ErrConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "目录 slug 已存在")
			return
		}
		var ve *ValidationError
		if errors.As(err, &ve) {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "目录校验未通过", ve.Errors)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordDirectoryAudit(r, principal, "create", nil, &d, audits.ResultSuccess, "")
	response.JSON(w, r, http.StatusCreated, map[string]interface{}{"directory": d})
}

// UpdateDirectory PUT /api/v1/ai-crawl/directories/{id}
func (h *Handler) UpdateDirectory(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的目录 ID")
		return
	}
	before, err := h.store.GetDirectory(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "爬虫目录不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	var req directoryRequest
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	d := req.toDirectory(before.Enabled)
	d.ID = id
	if before.IsBuiltin && d.Slug != before.Slug {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "目录校验未通过",
			[]FieldError{{Field: "slug", Message: "内置目录不允许修改 slug"}})
		return
	}
	if errs := ValidateDirectory(&d); len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "目录校验未通过", errs)
		return
	}
	if d.DirectoryURL != "" {
		outbound, err := h.outboundPolicy(r.Context())
		if err != nil {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "目录校验未通过",
				[]FieldError{{Field: "directory_url", Message: "允许清单配置非法: " + err.Error()}})
			return
		}
		if fe := ValidateDirectoryURLSSRF(r.Context(), d.DirectoryURL, outbound); fe != nil {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "目录校验未通过", []FieldError{*fe})
			return
		}
	}
	if err := h.store.UpdateDirectory(r.Context(), &d); err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "爬虫目录不存在")
			return
		}
		if errors.Is(err, ErrConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "目录 slug 已被占用")
			return
		}
		var ve *ValidationError
		if errors.As(err, &ve) {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "目录校验未通过", ve.Errors)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordDirectoryAudit(r, principal, "update", before, &d, audits.ResultSuccess, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"directory": d})
}

// DeleteDirectory DELETE /api/v1/ai-crawl/directories/{id}
func (h *Handler) DeleteDirectory(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的目录 ID")
		return
	}
	before, err := h.store.GetDirectory(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "爬虫目录不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.DeleteDirectory(r.Context(), id); err != nil {
		if errors.Is(err, ErrBuiltinProtected) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "内置爬虫目录不可删除，可通过禁用停用")
			return
		}
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "爬虫目录不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordDirectoryAudit(r, principal, "delete", before, nil, audits.ResultSuccess, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"deleted": true, "id": id.String()})
}

// ImportDirectories POST /api/v1/ai-crawl/directories/import
func (h *Handler) ImportDirectories(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	var req importDirectoriesRequest
	if err := response.DecodeJSON(w, r, &req, 2<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "导入包 JSON 格式错误")
		return
	}
	if len(req.Directories) == 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "导入校验未通过",
			[]FieldError{{Field: "directories", Message: "directories 不能为空"}})
		return
	}
	if len(req.Directories) > MaxImportDirectories {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "导入校验未通过",
			[]FieldError{{Field: "directories", Message: fmt.Sprintf("单次导入目录数不能超过 %d", MaxImportDirectories)}})
		return
	}

	var outbound *outboundhttp.Policy
	dirs := make([]Directory, 0, len(req.Directories))
	seenSlug := map[string]bool{}
	errs := []FieldError{}
	for i, item := range req.Directories {
		d := item.toDirectory(true)
		prefix := fmt.Sprintf("directories[%d]", i)
		for _, fe := range ValidateDirectory(&d) {
			errs = append(errs, FieldError{Field: prefix + "." + fe.Field, Message: fe.Message})
		}
		if d.Slug != "" {
			if seenSlug[d.Slug] {
				errs = append(errs, FieldError{Field: prefix + ".slug", Message: "导入包内存在重复 slug: " + d.Slug})
			}
			seenSlug[d.Slug] = true
		}
		if d.DirectoryURL != "" {
			if outbound == nil {
				var err error
				outbound, err = h.outboundPolicy(r.Context())
				if err != nil {
					response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "导入校验未通过",
						[]FieldError{{Field: "directory_url", Message: "允许清单配置非法: " + err.Error()}})
					return
				}
			}
			if fe := ValidateDirectoryURLSSRF(r.Context(), d.DirectoryURL, outbound); fe != nil {
				errs = append(errs, FieldError{Field: prefix + "." + fe.Field, Message: fe.Message})
			}
		}
		dirs = append(dirs, d)
	}
	if len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "导入校验未通过", errs)
		return
	}

	saved, err := h.store.UpsertDirectories(r.Context(), dirs)
	if err != nil {
		var ve *ValidationError
		if errors.As(err, &ve) {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "导入校验未通过", ve.Errors)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	afterSummary, _ := json.Marshal(map[string]interface{}{"imported": len(saved)})
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       &principal.UserID,
		Username:     principal.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "security",
		Action:       "import",
		ObjectType:   "ai_crawler_directory",
		ObjectID:     "batch",
		ObjectName:   fmt.Sprintf("import(%d)", len(saved)),
		AfterSummary: string(afterSummary),
		Result:       audits.ResultSuccess,
		RiskLevel:    audits.RiskMedium,
		RequestID:    response.RequestIDFrom(r),
	})
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"imported": len(saved),
		"items":    saved,
	})
}

// SyncDirectory POST /api/v1/ai-crawl/directories/{id}/sync
func (h *Handler) SyncDirectory(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的目录 ID")
		return
	}
	dir, err := h.store.GetDirectory(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "爬虫目录不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if strings.TrimSpace(dir.DirectoryURL) == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "该目录未配置远程 directory_url，请使用离线导入或手工维护公钥")
		return
	}
	outbound, err := h.outboundPolicy(r.Context())
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "允许清单配置非法: "+err.Error())
		return
	}
	fetch := h.dirFetch
	if fetch == nil {
		fetch = FetchDirectoryKeys
	}
	keys, err := fetch(r.Context(), dir.DirectoryURL, outbound)
	if err != nil {
		_ = h.store.UpdateDirectorySyncError(r.Context(), id, err.Error())
		h.recordDirectoryAudit(r, principal, "sync", dir, nil, audits.ResultFailure, err.Error())
		if errors.Is(err, outboundhttp.ErrDenied) || errors.Is(err, ErrDirectoryFetchInvalid) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "同步爬虫目录失败: "+err.Error())
			return
		}
		response.Error(w, r, http.StatusBadGateway, response.CodeServiceUnavailable, "同步远程爬虫目录失败: "+err.Error())
		return
	}
	updated, err := h.store.UpdateDirectorySyncSuccess(r.Context(), id, keys, time.Now().UTC())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordDirectoryAudit(r, principal, "sync", dir, updated, audits.ResultSuccess, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"directory":  updated,
		"keys_count": len(updated.Keys),
	})
}

// ---------- 应用级 AI 爬虫策略 ----------

// GetPolicy GET /api/v1/applications/{id}/ai-crawl-policy
func (h *Handler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	app, ok := h.resolveApp(w, r)
	if !ok {
		return
	}
	p, err := h.store.GetByApp(r.Context(), app.ID)
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

// PutPolicy PUT /api/v1/applications/{id}/ai-crawl-policy
func (h *Handler) PutPolicy(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	app, ok := h.resolveApp(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetByApp(r.Context(), app.ID)
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
	if p.LabyrinthEnabled && h.ensureLabyrinthKey != nil {
		if err := h.ensureLabyrinthKey(r.Context(), principal.UserID); err != nil {
			response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "初始化 AI 迷宫加密签名密钥失败: "+err.Error())
			return
		}
	}

	if err := h.store.SaveDraft(r.Context(), p, req.ExpectedVersion, req.Reason, principal.Username); err != nil {
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
	h.recordPolicyAudit(r, principal, "update", app, before, p, req.Reason, audits.ResultSuccess, "")

	final, err := h.store.GetByApp(r.Context(), app.ID)
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

func summarizeDirectory(d *Directory) map[string]interface{} {
	if d == nil {
		return nil
	}
	kids := make([]string, 0, len(d.Keys))
	for _, k := range d.Keys {
		kids = append(kids, k.KID)
	}
	return map[string]interface{}{
		"slug":            d.Slug,
		"name":            d.Name,
		"category":        d.Category,
		"signature_agent": d.SignatureAgent,
		"directory_url":   d.DirectoryURL,
		"enabled":         d.Enabled,
		"key_ids":         kids,
	}
}

func (h *Handler) recordDirectoryAudit(r *http.Request, p *authz.Principal, action string, before, after *Directory, result, failureReason string) {
	if p == nil {
		return
	}
	var beforeJSON, afterJSON []byte
	if before != nil {
		beforeJSON, _ = json.Marshal(summarizeDirectory(before))
	}
	if after != nil {
		afterJSON, _ = json.Marshal(summarizeDirectory(after))
	}
	objID, objName := "", ""
	if after != nil {
		objID, objName = after.ID.String(), after.Slug
	} else if before != nil {
		objID, objName = before.ID.String(), before.Slug
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "security",
		Action:        action,
		ObjectType:    "ai_crawler_directory",
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: string(beforeJSON),
		AfterSummary:  string(afterJSON),
		Result:        result,
		FailureReason: failureReason,
		RiskLevel:     audits.RiskMedium,
		RequestID:     response.RequestIDFrom(r),
	})
}

func summarizePolicy(p *Policy, reason string) map[string]interface{} {
	if p == nil {
		return nil
	}
	return map[string]interface{}{
		"mode":                      p.Mode,
		"version":                   p.Version,
		"default_ai_action":         p.DefaultAIAction,
		"content_signal":            p.ContentSignal,
		"verify_web_bot_auth":       p.VerifyWebBotAuth,
		"labyrinth_enabled":         p.LabyrinthEnabled,
		"labyrinth_inject_links":    p.LabyrinthInjectLinks,
		"labyrinth_max_depth":       p.LabyrinthMaxDepth,
		"labyrinth_max_concurrency": p.LabyrinthMaxConcurrency,
		"labyrinth_delay_ms":        p.LabyrinthDelayMs,
		"rules_count":               len(p.Rules),
		"reason":                    reason,
	}
}

func (h *Handler) recordPolicyAudit(r *http.Request, p *authz.Principal, action string, app *applications.Application, before, after *Policy, reason, result, failureReason string) {
	if p == nil {
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
	if (before == nil || before.Mode != ModeProtect) && after != nil && after.Mode == ModeProtect {
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
		Action:        action,
		ObjectType:    "ai_crawl_policy",
		ObjectID:      objID,
		ObjectName:    app.Code,
		BeforeSummary: string(beforeJSON),
		AfterSummary:  string(afterJSON),
		Result:        result,
		FailureReason: failureReason,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}
