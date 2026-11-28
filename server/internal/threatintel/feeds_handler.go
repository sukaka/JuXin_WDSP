// feeds_handler.go 威胁情报多源订阅管理、全局调度/熔断配置、在线拉取与同步历史 HTTP 接口。
//
// 路由（由 RegisterFeedRoutes 注册）：
//   - GET    /api/v1/threat-intel/feeds           查看全局设置、汇总、内置预置源与订阅源列表（threat_intel.read）
//   - PUT    /api/v1/threat-intel/settings        更新定时总开关与连续失败熔断阈值（threat_intel.manage）
//   - POST   /api/v1/threat-intel/feeds           新增自定义订阅源（threat_intel.manage）
//   - PUT    /api/v1/threat-intel/feeds/{id}      修改订阅源配置（threat_intel.manage）
//   - DELETE /api/v1/threat-intel/feeds/{id}      删除自定义订阅源（threat_intel.manage，拒绝预置源）
//   - POST   /api/v1/threat-intel/feeds/{id}/sync 手动触发单源拉取与对账（threat_intel.manage）
//   - GET    /api/v1/threat-intel/runs            分页查询同步与离线导入流水（threat_intel.read）
package threatintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/settings"
)

// 威胁情报订阅管理权限点（迁移 000256 种子；遵循 000232 三权边界）。
const (
	PermThreatIntelRead   = "threat_intel.read"
	PermThreatIntelManage = "threat_intel.manage"
)

const (
	maxFeedJSONBodyBytes = 32 << 10
	maxCustomURLLen      = 2048
	maxFeedNameRunes     = 128
	maxFeedDescRunes     = 1000
)

// FeedSettingsStore 读写 threat_intel 组系统设置（*settings.Service 直接满足）。
type FeedSettingsStore interface {
	GetBool(ctx context.Context, group, key string, def bool) bool
	GetInt(ctx context.Context, group, key string, def int) int
	UpsertBool(ctx context.Context, group, key string, value bool, description string, operatorID uuid.UUID) error
	List(ctx context.Context, group string) ([]settings.Setting, error)
	Update(ctx context.Context, group, key string, value json.RawMessage, expectedVersion int, operatorID uuid.UUID) (bool, error)
}

var _ FeedSettingsStore = (*settings.Service)(nil)

// ThreatIntelSettings 是威胁情报全局调度与熔断配置视图。
type ThreatIntelSettings struct {
	AutoUpdateEnabled bool `json:"auto_update_enabled"`
	CircuitThreshold  int  `json:"circuit_threshold"`
}

// FeedsSummary 是威胁情报订阅源总览统计。
type FeedsSummary struct {
	EnabledCount     int `json:"enabled_count"`
	TotalActiveRules int `json:"total_active_rules"`
	CircuitOpenCount int `json:"circuit_open_count"`
}

// FeedsListResponse 是 GET /api/v1/threat-intel/feeds 的响应载荷。
type FeedsListResponse struct {
	Settings ThreatIntelSettings `json:"settings"`
	Summary  FeedsSummary        `json:"summary"`
	Presets  []OfficialPreset    `json:"presets"`
	Feeds    []Feed              `json:"feeds"`
}

// FeedsHandler 处理威胁情报多源订阅管理与同步历史接口。
type FeedsHandler struct {
	repo         FeedRepository
	syncer       *Syncer
	settings     FeedSettingsStore
	urlValidator URLValidator
	audits       *audits.Service
}

// NewFeedsHandler 创建威胁情报订阅源管理处理器。
func NewFeedsHandler(
	repo FeedRepository,
	syncer *Syncer,
	settingsStore FeedSettingsStore,
	urlValidator URLValidator,
	auditSvc *audits.Service,
) *FeedsHandler {
	return &FeedsHandler{
		repo:         repo,
		syncer:       syncer,
		settings:     settingsStore,
		urlValidator: urlValidator,
		audits:       auditSvc,
	}
}

// RegisterFeedRoutes 注册威胁情报多源订阅、配置、同步与流水查询路由。
func RegisterFeedRoutes(mux *http.ServeMux, authzMw func(http.Handler) http.Handler, h *FeedsHandler) {
	mux.Handle("GET /api/v1/threat-intel/feeds",
		authzMw(middleware.RequirePermission(PermThreatIntelRead)(http.HandlerFunc(h.ListFeeds))))
	mux.Handle("PUT /api/v1/threat-intel/settings",
		authzMw(middleware.RequirePermission(PermThreatIntelManage)(http.HandlerFunc(h.UpdateSettings))))
	mux.Handle("POST /api/v1/threat-intel/feeds",
		authzMw(middleware.RequirePermission(PermThreatIntelManage)(http.HandlerFunc(h.CreateFeed))))
	mux.Handle("PUT /api/v1/threat-intel/feeds/{id}",
		authzMw(middleware.RequirePermission(PermThreatIntelManage)(http.HandlerFunc(h.UpdateFeed))))
	mux.Handle("DELETE /api/v1/threat-intel/feeds/{id}",
		authzMw(middleware.RequirePermission(PermThreatIntelManage)(http.HandlerFunc(h.DeleteFeed))))
	mux.Handle("POST /api/v1/threat-intel/feeds/{id}/sync",
		authzMw(middleware.RequirePermission(PermThreatIntelManage)(http.HandlerFunc(h.SyncFeed))))
	mux.Handle("GET /api/v1/threat-intel/runs",
		authzMw(middleware.RequirePermission(PermThreatIntelRead)(http.HandlerFunc(h.ListRuns))))
}

// ListFeeds GET /api/v1/threat-intel/feeds
func (h *FeedsHandler) ListFeeds(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.repo == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "威胁情报订阅服务未初始化")
		return
	}
	feeds, err := h.repo.ListFeeds(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if feeds == nil {
		feeds = []Feed{}
	}
	var summary FeedsSummary
	for i := range feeds {
		if feeds[i].Enabled {
			summary.EnabledCount++
		}
		summary.TotalActiveRules += feeds[i].ActiveRuleCount
		if feeds[i].CircuitOpen {
			summary.CircuitOpenCount++
		}
	}

	response.JSON(w, r, http.StatusOK, FeedsListResponse{
		Settings: h.readSettings(r.Context()),
		Summary:  summary,
		Presets:  OfficialPresets(),
		Feeds:    feeds,
	})
}

type updateSettingsRequest struct {
	AutoUpdateEnabled *bool `json:"auto_update_enabled"`
	CircuitThreshold  *int  `json:"circuit_threshold"`
}

// UpdateSettings PUT /api/v1/threat-intel/settings
func (h *FeedsHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.settings == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "威胁情报设置服务未初始化")
		return
	}
	p := authz.PrincipalFrom(r.Context())
	var req updateSettingsRequest
	if err := response.DecodeJSON(w, r, &req, maxFeedJSONBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体必须是合法 JSON")
		return
	}
	if req.AutoUpdateEnabled == nil && req.CircuitThreshold == nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请至少提供 auto_update_enabled 或 circuit_threshold 之一")
		return
	}
	if req.CircuitThreshold != nil && (*req.CircuitThreshold < MinCircuitThreshold || *req.CircuitThreshold > MaxCircuitThreshold) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("circuit_threshold 须在 %d–%d 之间", MinCircuitThreshold, MaxCircuitThreshold))
		return
	}

	opID := uuid.Nil
	if p != nil {
		opID = p.UserID
	}

	if req.AutoUpdateEnabled != nil {
		if err := h.settings.UpsertBool(r.Context(), SettingsGroup, KeyAutoUpdateEnabled, *req.AutoUpdateEnabled,
			"威胁情报 IP 黑名单库在线定时更新总开关", opID); err != nil {
			response.InternalError(w, r, err)
			return
		}
	}
	if req.CircuitThreshold != nil {
		if err := saveCircuitThreshold(r.Context(), h.settings, *req.CircuitThreshold, opID); err != nil {
			response.InternalError(w, r, err)
			return
		}
	}

	updated := h.readSettings(r.Context())
	h.writeAudit(r, p, "threat_intel_settings_update", "threat_intel_settings", SettingsGroup, "威胁情报全局调度设置", audits.ResultSuccess, map[string]any{
		"auto_update_enabled": updated.AutoUpdateEnabled,
		"circuit_threshold":   updated.CircuitThreshold,
	})
	response.JSON(w, r, http.StatusOK, updated)
}

type feedUpsertRequest struct {
	FeedKey         string   `json:"feed_key"`
	Name            string   `json:"name"`
	Description     *string  `json:"description,omitempty"`
	IsBuiltin       *bool    `json:"is_builtin,omitempty"`
	Enabled         *bool    `json:"enabled"`
	SourceMode      string   `json:"source_mode"`
	OfficialPreset  *string  `json:"official_preset,omitempty"`
	CustomURL       *string  `json:"custom_url,omitempty"`
	Format          string   `json:"format"`
	AllowCIDR       *bool    `json:"allow_cidr"`
	TTLDays         *int     `json:"ttl_days"`
	ScheduleCron    string   `json:"schedule_cron"`
	MinEntriesGuard *bool    `json:"min_entries_guard"`
	MaxDropRatio    *float64 `json:"max_drop_ratio"`
}

// CreateFeed POST /api/v1/threat-intel/feeds
func (h *FeedsHandler) CreateFeed(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.repo == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "威胁情报订阅服务未初始化")
		return
	}
	p := authz.PrincipalFrom(r.Context())
	var req feedUpsertRequest
	if err := response.DecodeJSON(w, r, &req, maxFeedJSONBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体必须是合法 JSON")
		return
	}

	feed := &Feed{
		FeedKey:         strings.ToLower(strings.TrimSpace(req.FeedKey)),
		Name:            strings.TrimSpace(req.Name),
		IsBuiltin:       false,
		Enabled:         false,
		SourceMode:      strings.ToUpper(strings.TrimSpace(req.SourceMode)),
		Format:          strings.ToLower(strings.TrimSpace(req.Format)),
		AllowCIDR:       false,
		TTLDays:         DefaultTTLDays,
		ScheduleCron:    strings.TrimSpace(req.ScheduleCron),
		MinEntriesGuard: true,
		MaxDropRatio:    DefaultMaxDropRatio,
		LastStatus:      RunStatusIdle,
	}
	if req.Description != nil {
		feed.Description = strings.TrimSpace(*req.Description)
	}
	if req.OfficialPreset != nil {
		feed.OfficialPreset = strings.ToLower(strings.TrimSpace(*req.OfficialPreset))
	}
	if req.CustomURL != nil {
		feed.CustomURL = strings.TrimSpace(*req.CustomURL)
	}
	if req.Enabled != nil {
		feed.Enabled = *req.Enabled
	}
	if req.AllowCIDR != nil {
		feed.AllowCIDR = *req.AllowCIDR
	}
	if req.TTLDays != nil {
		feed.TTLDays = *req.TTLDays
	}
	if req.MinEntriesGuard != nil {
		feed.MinEntriesGuard = *req.MinEntriesGuard
	}
	if req.MaxDropRatio != nil {
		feed.MaxDropRatio = *req.MaxDropRatio
	}
	if feed.SourceMode == "" {
		feed.SourceMode = SourceModeOfflineOnly
	}
	if feed.SourceMode == SourceModeOfficial {
		if preset, ok := LookupOfficialPreset(feed.OfficialPreset); ok {
			if feed.Format == "" {
				feed.Format = preset.Format
			}
			if req.AllowCIDR == nil {
				feed.AllowCIDR = preset.AllowCIDR
			}
			if req.TTLDays == nil {
				feed.TTLDays = preset.DefaultTTLDays
			}
			if feed.ScheduleCron == "" {
				feed.ScheduleCron = preset.DefaultCron
			}
		}
	}
	if feed.Format == "" {
		feed.Format = "text"
	}
	if feed.ScheduleCron == "" {
		feed.ScheduleCron = DefaultScheduleCron
	}

	if err := h.validateFeedFields(r.Context(), feed); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}

	if p != nil && p.UserID != uuid.Nil {
		id := p.UserID
		feed.CreatedBy = &id
		feed.UpdatedBy = &id
	}

	if err := h.repo.CreateFeed(r.Context(), feed); err != nil {
		if errors.Is(err, ErrFeedKeyConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
				fmt.Sprintf("订阅源标识 %q 已存在", feed.FeedKey))
			return
		}
		response.InternalError(w, r, err)
		return
	}

	h.writeAudit(r, p, "threat_intel_feed_create", "threat_intel_feed", feed.ID.String(), feed.FeedKey, audits.ResultSuccess, map[string]any{
		"feed_key":    feed.FeedKey,
		"name":        feed.Name,
		"source_mode": feed.SourceMode,
		"format":      feed.Format,
		"allow_cidr":  feed.AllowCIDR,
		"enabled":     feed.Enabled,
	})
	response.JSON(w, r, http.StatusCreated, feed)
}

// UpdateFeed PUT /api/v1/threat-intel/feeds/{id}
func (h *FeedsHandler) UpdateFeed(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.repo == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "威胁情报订阅服务未初始化")
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的订阅源 ID")
		return
	}
	existing, err := h.repo.GetFeed(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrFeedNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "威胁情报订阅源不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}

	p := authz.PrincipalFrom(r.Context())
	var req feedUpsertRequest
	if err := response.DecodeJSON(w, r, &req, maxFeedJSONBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体必须是合法 JSON")
		return
	}

	// 内置源（及既有源）不允许修改 feed_key 或 is_builtin（保护规则命名空间隔离与系统内置标识）
	if reqKey := strings.ToLower(strings.TrimSpace(req.FeedKey)); reqKey != "" && reqKey != existing.FeedKey {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "不允许修改已有订阅源的 feed_key")
		return
	}
	if req.IsBuiltin != nil && *req.IsBuiltin != existing.IsBuiltin {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "不允许修改订阅源的 is_builtin 属性")
		return
	}

	updated := *existing
	if name := strings.TrimSpace(req.Name); name != "" {
		updated.Name = name
	}
	if req.Description != nil {
		updated.Description = strings.TrimSpace(*req.Description)
	}
	if req.Enabled != nil {
		updated.Enabled = *req.Enabled
	}
	if mode := strings.ToUpper(strings.TrimSpace(req.SourceMode)); mode != "" {
		updated.SourceMode = mode
	}
	if req.OfficialPreset != nil {
		updated.OfficialPreset = strings.ToLower(strings.TrimSpace(*req.OfficialPreset))
	} else if updated.SourceMode != SourceModeOfficial {
		updated.OfficialPreset = ""
	}
	if updated.SourceMode == SourceModeCustomURL {
		if req.CustomURL != nil {
			updated.CustomURL = strings.TrimSpace(*req.CustomURL)
		}
	} else {
		updated.CustomURL = ""
	}
	if format := strings.ToLower(strings.TrimSpace(req.Format)); format != "" {
		updated.Format = format
	}
	if req.AllowCIDR != nil {
		updated.AllowCIDR = *req.AllowCIDR
	}
	if req.TTLDays != nil {
		updated.TTLDays = *req.TTLDays
	}
	if cron := strings.TrimSpace(req.ScheduleCron); cron != "" {
		updated.ScheduleCron = cron
	}
	if req.MinEntriesGuard != nil {
		updated.MinEntriesGuard = *req.MinEntriesGuard
	}
	if req.MaxDropRatio != nil {
		updated.MaxDropRatio = *req.MaxDropRatio
	}
	// 内置源切回 OFFICIAL 且未显式传 official_preset 时回填原始预置名（或 feed_key）
	if existing.IsBuiltin && updated.SourceMode == SourceModeOfficial && updated.OfficialPreset == "" {
		if existing.OfficialPreset != "" {
			updated.OfficialPreset = existing.OfficialPreset
		} else if _, ok := LookupOfficialPreset(existing.FeedKey); ok {
			updated.OfficialPreset = existing.FeedKey
		}
	}

	if err := h.validateFeedFields(r.Context(), &updated); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}

	// 来源、格式或 CIDR 策略变更时清空条件请求缓存头，确保下次拉取按新规则完整对账
	if updated.SourceMode != existing.SourceMode ||
		updated.OfficialPreset != existing.OfficialPreset ||
		updated.CustomURL != existing.CustomURL ||
		updated.Format != existing.Format ||
		updated.AllowCIDR != existing.AllowCIDR {
		updated.ETag = ""
		updated.LastModified = ""
		updated.LastContentSHA256 = ""
	}

	if p != nil && p.UserID != uuid.Nil {
		uid := p.UserID
		updated.UpdatedBy = &uid
	}

	if err := h.repo.UpdateFeed(r.Context(), &updated); err != nil {
		if errors.Is(err, ErrFeedNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "威胁情报订阅源不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}

	h.writeAudit(r, p, "threat_intel_feed_update", "threat_intel_feed", updated.ID.String(), updated.FeedKey, audits.ResultSuccess, map[string]any{
		"feed_key":          updated.FeedKey,
		"name":              updated.Name,
		"enabled":           updated.Enabled,
		"source_mode":       updated.SourceMode,
		"official_preset":   updated.OfficialPreset,
		"format":            updated.Format,
		"allow_cidr":        updated.AllowCIDR,
		"ttl_days":          updated.TTLDays,
		"schedule_cron":     updated.ScheduleCron,
		"min_entries_guard": updated.MinEntriesGuard,
		"max_drop_ratio":    updated.MaxDropRatio,
	})
	response.JSON(w, r, http.StatusOK, &updated)
}

// DeleteFeed DELETE /api/v1/threat-intel/feeds/{id}
func (h *FeedsHandler) DeleteFeed(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.repo == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "威胁情报订阅服务未初始化")
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的订阅源 ID")
		return
	}
	existing, err := h.repo.GetFeed(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrFeedNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "威胁情报订阅源不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if existing.IsBuiltin {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "系统预置官方情报源不允许删除，可停用或切换为纯离线模式")
		return
	}

	p := authz.PrincipalFrom(r.Context())
	if err := h.repo.DeleteFeed(r.Context(), id); err != nil {
		if errors.Is(err, ErrBuiltinProtected) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "系统预置官方情报源不允许删除")
			return
		}
		if errors.Is(err, ErrFeedNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "威胁情报订阅源不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}

	h.writeAudit(r, p, "threat_intel_feed_delete", "threat_intel_feed", id.String(), existing.FeedKey, audits.ResultSuccess, map[string]any{
		"id":       id.String(),
		"feed_key": existing.FeedKey,
		"name":     existing.Name,
	})
	response.JSON(w, r, http.StatusOK, map[string]any{
		"deleted":  true,
		"id":       id,
		"feed_key": existing.FeedKey,
	})
}

type syncFeedRequest struct {
	ForceIgnoreGuard bool `json:"force_ignore_guard"`
}

// SyncFeed POST /api/v1/threat-intel/feeds/{id}/sync
func (h *FeedsHandler) SyncFeed(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.syncer == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "威胁情报同步服务未初始化")
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的订阅源 ID")
		return
	}

	var req syncFeedRequest
	if r.Body != nil {
		decErr := response.DecodeJSON(w, r, &req, maxFeedJSONBodyBytes)
		if decErr != nil && !errors.Is(decErr, io.EOF) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体必须是合法 JSON")
			return
		}
	}

	p := authz.PrincipalFrom(r.Context())
	var opID *uuid.UUID
	if p != nil && p.UserID != uuid.Nil {
		uid := p.UserID
		opID = &uid
	}

	result, syncErr := h.syncer.SyncFeed(r.Context(), id, SyncOptions{
		TriggerType:      TriggerManual,
		ForceIgnoreGuard: req.ForceIgnoreGuard,
		OperatorID:       opID,
		RequestID:        response.RequestIDFrom(r),
	})
	if syncErr != nil {
		switch {
		case errors.Is(syncErr, ErrFeedNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "威胁情报订阅源不存在")
		case errors.Is(syncErr, ErrOfflineOnlyFeed):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "当前订阅源为纯离线模式（OFFLINE_ONLY），请改用离线快照导入")
		case errors.Is(syncErr, ErrSyncInProgress):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "该订阅源正在同步中，请稍后再试")
		default:
			response.InternalError(w, r, syncErr)
		}
		return
	}

	auditResult := audits.ResultSuccess
	if result.Run != nil && (result.Run.Status == RunStatusFailed || result.Run.Status == RunStatusGuardAborted) {
		auditResult = audits.ResultFailure
	}
	feedKey := id.String()
	if result.Feed != nil && result.Feed.FeedKey != "" {
		feedKey = result.Feed.FeedKey
	}
	summary := map[string]any{
		"feed_key":           feedKey,
		"force_ignore_guard": req.ForceIgnoreGuard,
		"guard_triggered":    result.GuardTriggered,
		"circuit_opened":     result.CircuitOpened,
	}
	if result.Run != nil {
		summary["status"] = result.Run.Status
		summary["batch_id"] = result.Run.BatchID
		summary["total_parsed"] = result.Run.TotalParsed
		summary["added"] = result.Run.Added
		summary["refreshed"] = result.Run.Refreshed
		summary["expired"] = result.Run.Expired
		summary["error"] = result.Run.ErrorMessage
	}
	h.writeAudit(r, p, "threat_intel_feed_sync", "threat_intel_feed", id.String(), feedKey, auditResult, summary)
	response.JSON(w, r, http.StatusOK, result)
}

// ListRuns GET /api/v1/threat-intel/runs
func (h *FeedsHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.repo == nil {
		response.Page(w, r, []SyncRun{}, 0, 1, 20)
		return
	}
	q := r.URL.Query()
	feedKey := strings.ToLower(strings.TrimSpace(q.Get("feed_key")))
	if feedKey != "" && !feedPattern.MatchString(feedKey) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 feed_key 过滤条件")
		return
	}
	triggerType := strings.ToUpper(strings.TrimSpace(q.Get("trigger_type")))
	if triggerType != "" {
		switch triggerType {
		case TriggerScheduled, TriggerManual, TriggerOfflineImport:
		default:
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 trigger_type 过滤条件")
			return
		}
	}
	status := strings.ToUpper(strings.TrimSpace(q.Get("status")))
	if status != "" {
		switch status {
		case RunStatusSuccess, RunStatusSkippedNotModified, RunStatusGuardAborted, RunStatusFailed:
		default:
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 status 过滤条件")
			return
		}
	}

	page := parseQueryInt(r, "page", 1)
	pageSize := parseQueryInt(r, "page_size", 20)
	if pageSize > 100 {
		pageSize = 100
	}
	items, total, err := h.repo.ListRuns(r.Context(), RunFilter{
		FeedKey:     feedKey,
		TriggerType: triggerType,
		Status:      status,
		Page:        page,
		PageSize:    pageSize,
	})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if items == nil {
		items = []SyncRun{}
	}
	response.Page(w, r, items, total, page, pageSize)
}

func (h *FeedsHandler) readSettings(ctx context.Context) ThreatIntelSettings {
	st := ThreatIntelSettings{
		AutoUpdateEnabled: false,
		CircuitThreshold:  DefaultCircuitThreshold,
	}
	if h.settings != nil {
		st.AutoUpdateEnabled = h.settings.GetBool(ctx, SettingsGroup, KeyAutoUpdateEnabled, false)
		n := h.settings.GetInt(ctx, SettingsGroup, KeyCircuitThreshold, DefaultCircuitThreshold)
		if n < MinCircuitThreshold {
			n = MinCircuitThreshold
		}
		if n > MaxCircuitThreshold {
			n = MaxCircuitThreshold
		}
		st.CircuitThreshold = n
	}
	return st
}

func (h *FeedsHandler) validateFeedFields(ctx context.Context, f *Feed) error {
	if !feedPattern.MatchString(f.FeedKey) {
		return fmt.Errorf("feed_key 仅允许小写字母/数字开头加 _ -（1–32 字符）: %q", f.FeedKey)
	}
	if n := utf8.RuneCountInString(f.Name); n == 0 || n > maxFeedNameRunes {
		return fmt.Errorf("订阅源名称必填且不超过 %d 字符", maxFeedNameRunes)
	}
	if utf8.RuneCountInString(f.Description) > maxFeedDescRunes {
		return fmt.Errorf("描述长度不超过 %d 字符", maxFeedDescRunes)
	}
	switch f.SourceMode {
	case SourceModeOfflineOnly:
		f.OfficialPreset = ""
		f.CustomURL = ""
	case SourceModeOfficial:
		if _, ok := LookupOfficialPreset(f.OfficialPreset); !ok {
			presets := OfficialPresets()
			keys := make([]string, 0, len(presets))
			for _, p := range presets {
				keys = append(keys, p.Key)
			}
			return fmt.Errorf("官方预置源无效（仅支持宽松许可预置源 %s）: %q", strings.Join(keys, " / "), f.OfficialPreset)
		}
		f.CustomURL = ""
	case SourceModeCustomURL:
		f.OfficialPreset = ""
		if f.CustomURL == "" {
			return errors.New("CUSTOM_URL 模式下 custom_url 不能为空")
		}
		if len(f.CustomURL) > maxCustomURLLen {
			return fmt.Errorf("custom_url 长度超过 %d 字符上限", maxCustomURLLen)
		}
		if err := basicValidateCustomURL(f.CustomURL); err != nil {
			return err
		}
		if h.urlValidator != nil {
			if err := h.urlValidator(ctx, SourceModeCustomURL, f.CustomURL); err != nil {
				return fmt.Errorf("custom_url 安全校验未通过: %v", err)
			}
		}
	default:
		return fmt.Errorf("无效的 source_mode（支持 OFFLINE_ONLY / OFFICIAL / CUSTOM_URL）: %q", f.SourceMode)
	}
	if f.Format != "text" && f.Format != "csv" {
		return fmt.Errorf("无效的 format（支持 text / csv）: %q", f.Format)
	}
	if f.TTLDays < 0 || f.TTLDays > MaxTTLDays {
		return fmt.Errorf("ttl_days 须在 0–%d 之间（0=永久）", MaxTTLDays)
	}
	if err := ValidateCron(f.ScheduleCron); err != nil {
		return fmt.Errorf("schedule_cron 非法: %v", err)
	}
	if math.IsNaN(f.MaxDropRatio) || math.IsInf(f.MaxDropRatio, 0) || f.MaxDropRatio < 0.0 || f.MaxDropRatio > 1.0 {
		return errors.New("max_drop_ratio 须在 0.0–1.0 之间")
	}
	return nil
}

func basicValidateCustomURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("无效的 custom_url: %v", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("custom_url 仅支持 http/https 协议")
	}
	if u.Host == "" {
		return errors.New("custom_url 缺少主机名")
	}
	if u.User != nil {
		return errors.New("custom_url 不允许内嵌认证凭据")
	}
	return nil
}

func saveCircuitThreshold(ctx context.Context, st FeedSettingsStore, threshold int, operatorID uuid.UUID) error {
	rawVal := json.RawMessage(strconv.Itoa(threshold))
	for attempt := 0; attempt < 3; attempt++ {
		items, err := st.List(ctx, SettingsGroup)
		if err != nil {
			return fmt.Errorf("list threat_intel settings: %w", err)
		}
		found := false
		version := 0
		for _, item := range items {
			if item.Key == KeyCircuitThreshold {
				found = true
				version = item.Version
				break
			}
		}
		if !found {
			return fmt.Errorf("setting %s:%s not initialized", SettingsGroup, KeyCircuitThreshold)
		}
		_, err = st.Update(ctx, SettingsGroup, KeyCircuitThreshold, rawVal, version, operatorID)
		if err == nil {
			return nil
		}
		if !strings.Contains(err.Error(), "version conflict") {
			return err
		}
	}
	return fmt.Errorf("update %s:%s failed after retries due to concurrent modification", SettingsGroup, KeyCircuitThreshold)
}

func (h *FeedsHandler) writeAudit(r *http.Request, p *authz.Principal, action, objType, objID, objName, result string, summary map[string]any) {
	if h.audits == nil {
		return
	}
	var uid *uuid.UUID
	username := ""
	if p != nil {
		if p.UserID != uuid.Nil {
			id := p.UserID
			uid = &id
		}
		username = p.Username
	}
	b, _ := json.Marshal(summary)
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       uid,
		Username:     username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "access_control",
		Action:       action,
		ObjectType:   objType,
		ObjectID:     objID,
		ObjectName:   objName,
		AfterSummary: string(b),
		Result:       result,
		RiskLevel:    audits.RiskMedium,
		RequestID:    response.RequestIDFrom(r),
	})
}

func parseQueryInt(r *http.Request, key string, def int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return def
	}
	return v
}
