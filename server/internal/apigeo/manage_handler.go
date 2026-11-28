// manage_handler.go GeoIP 归属地库状态查询、配置更新、在线同步、离线上传热加载、历史回滚、HA 重同步与流水查询 HTTP 接口。
//
// 路由（由 app.go 注册）：
//   - GET  /api/v1/geoip/status     查看引擎、5 个槽位、HA 节点一致性、官方预置源与调度摘要（geoip.read）
//   - PUT  /api/v1/geoip/settings   更新定时调度、HA 开关、MaxMind 凭据与槽位来源配置（geoip.manage）
//   - POST /api/v1/geoip/sync       立即在线同步单个或全部已启用槽位（geoip.manage）
//   - POST /api/v1/geoip/upload     离线上传 .xdb/.mmdb/.gz/.tar.gz 并零重启热重载（geoip.manage）
//   - POST /api/v1/geoip/rollback   按槽位与 backup_id 回滚历史版本并热重载（geoip.manage）
//   - POST /api/v1/geoip/ha-resync  将主节点运行期槽位重新同步至 HA 备节点（geoip.manage）
//   - GET  /api/v1/geoip/runs       分页查询更新/上传/回滚/HA 同步历史（geoip.read）
package apigeo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/iplibhttp"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/outboundhttp"
	"github.com/jiuzhang-waf/server/internal/response"
)

// GeoIP 管理权限点（迁移 000256 种子；遵循 000232 三权边界）。
const (
	PermGeoIPRead   = "geoip.read"
	PermGeoIPManage = "geoip.manage"
)

const (
	// maxGeoMultipartBytes 允许单次 multipart 上传的最大总请求体（最大槽位 256 MiB + 16 MiB 封装余量）。
	maxGeoMultipartBytes = (256 << 20) + (16 << 20)
	maxRollbackBodyBytes = 4 << 10
	maxSettingsBodyBytes = 32 << 10
	maxSyncBodyBytes     = 4 << 10
	maxCustomURLBytes    = 2048
	maxAccountIDLen      = 64
	maxLicenseKeyLen     = 256
)

// ManageSettingsReader 读取 GeoIP 调度与 MaxMind 配置元信息（*settings.Service 满足）。
type ManageSettingsReader interface {
	GetString(ctx context.Context, group, key, def string) string
	GetBool(ctx context.Context, group, key string, def bool) bool
}

// ManageSettingsWriter 写入 GeoIP 调度与 MaxMind 加密凭据（*settings.Service 满足）。
type ManageSettingsWriter interface {
	UpsertString(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) error
	UpsertSensitiveString(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) error
	UpsertBool(ctx context.Context, group, key string, value bool, description string, operatorID uuid.UUID) error
}

// URLValidatorFunc 是保存期自定义 URL 的 SSRF 校验函数签名。
type URLValidatorFunc func(ctx context.Context, sourceMode, rawURL string) error

// ManageHandler GeoIP 管理面 HTTP 处理器。
type ManageHandler struct {
	manager        *SlotManager
	store          ManageRepository
	settings       ManageSettingsReader
	settingsWriter ManageSettingsWriter
	audits         *audits.Service
	syncer         *GeoSyncer
	cipher         SecretCipher
	haPusher       HAGeoPusher
	urlValidator   URLValidatorFunc
}

// NewManageHandler 创建 GeoIP 管理处理器（保持向后兼容签名，附加依赖经 Set* 注入）。
func NewManageHandler(manager *SlotManager, store ManageRepository, settings ManageSettingsReader, auditSvc *audits.Service) *ManageHandler {
	h := &ManageHandler{
		manager:  manager,
		store:    store,
		settings: settings,
		audits:   auditSvc,
	}
	if w, ok := settings.(ManageSettingsWriter); ok {
		h.settingsWriter = w
	}
	return h
}

// SetSyncer 注入 GeoIP 在线同步器（同时复用其下载器校验与 HA 推送器）。
func (h *ManageHandler) SetSyncer(syncer *GeoSyncer) *ManageHandler {
	h.syncer = syncer
	return h
}

// SetCipher 注入主密钥加解密服务（用于加密写入 MaxMind License Key）。
func (h *ManageHandler) SetCipher(cipher SecretCipher) *ManageHandler {
	h.cipher = cipher
	return h
}

// SetSettingsWriter 显式注入设置写入接口（当 settings 已实现 ManageSettingsWriter 时自动识别，无需额外调用）。
func (h *ManageHandler) SetSettingsWriter(w ManageSettingsWriter) *ManageHandler {
	h.settingsWriter = w
	return h
}

// SetURLValidator 注入保存期 SSRF URL 校验器（未设置时优先复用 syncer 下载器，再退化为默认严格出站校验器）。
func (h *ManageHandler) SetURLValidator(fn URLValidatorFunc) *ManageHandler {
	h.urlValidator = fn
	return h
}

// SetHAPusher 注入 HA 节点推送与状态探测接口（未设置时自动复用 syncer 的 HAPusher）。
func (h *ManageHandler) SetHAPusher(p HAGeoPusher) *ManageHandler {
	h.haPusher = p
	return h
}

func (h *ManageHandler) effectiveSettingsWriter() ManageSettingsWriter {
	if h.settingsWriter != nil {
		return h.settingsWriter
	}
	if w, ok := h.settings.(ManageSettingsWriter); ok {
		return w
	}
	return nil
}

func (h *ManageHandler) effectiveCipher() SecretCipher {
	if h.cipher != nil {
		return h.cipher
	}
	if h.syncer != nil {
		return h.syncer.cipher
	}
	return nil
}

func (h *ManageHandler) effectiveHAPusher() HAGeoPusher {
	if h.haPusher != nil {
		return h.haPusher
	}
	if h.syncer != nil {
		return h.syncer.HAPusher()
	}
	return nil
}

func (h *ManageHandler) validateCustomURL(ctx context.Context, rawURL string) error {
	if h.urlValidator != nil {
		return h.urlValidator(ctx, SourceModeCustomURL, rawURL)
	}
	if h.syncer != nil && h.syncer.downloader != nil {
		return h.syncer.ValidateTargetURL(ctx, SourceModeCustomURL, rawURL)
	}
	var reader iplibhttp.SettingsReader
	if r, ok := h.settings.(iplibhttp.SettingsReader); ok {
		reader = r
	}
	return iplibhttp.NewDownloader(reader, h.effectiveCipher()).ValidateTargetURL(ctx, SourceModeCustomURL, rawURL)
}

// RegisterManageRoutes 注册 GeoIP 状态、配置、同步、上传、回滚、HA 重同步与历史路由。
func RegisterManageRoutes(mux *http.ServeMux, authzMw func(http.Handler) http.Handler, h *ManageHandler) {
	mux.Handle("GET /api/v1/geoip/status",
		authzMw(middleware.RequirePermission(PermGeoIPRead)(http.HandlerFunc(h.Status))))
	mux.Handle("PUT /api/v1/geoip/settings",
		authzMw(middleware.RequirePermission(PermGeoIPManage)(http.HandlerFunc(h.UpdateSettings))))
	mux.Handle("POST /api/v1/geoip/sync",
		authzMw(middleware.RequirePermission(PermGeoIPManage)(http.HandlerFunc(h.TriggerSync))))
	mux.Handle("POST /api/v1/geoip/upload",
		authzMw(middleware.RequirePermission(PermGeoIPManage)(http.HandlerFunc(h.Upload))))
	mux.Handle("POST /api/v1/geoip/rollback",
		authzMw(middleware.RequirePermission(PermGeoIPManage)(http.HandlerFunc(h.Rollback))))
	mux.Handle("POST /api/v1/geoip/ha-resync",
		authzMw(middleware.RequirePermission(PermGeoIPManage)(http.HandlerFunc(h.TriggerHAResync))))
	mux.Handle("GET /api/v1/geoip/runs",
		authzMw(middleware.RequirePermission(PermGeoIPRead)(http.HandlerFunc(h.ListRuns))))
}

// SlotStatusView 合并磁盘实态与数据库配置后的槽位视图。
type SlotStatusView struct {
	Slot             string        `json:"slot"`
	DisplayName      string        `json:"display_name"`
	CanonicalFile    string        `json:"canonical_file"`
	Format           string        `json:"format"`
	MaxBytes         int64         `json:"max_bytes"`
	Enabled          bool          `json:"enabled"`
	SourceMode       string        `json:"source_mode"`
	OfficialPreset   string        `json:"official_preset"`
	CustomURL        string        `json:"custom_url"`
	ActiveOrigin     string        `json:"active_origin"` // runtime | builtin | missing
	ActiveFilename   string        `json:"active_filename"`
	ActiveSourceType string        `json:"active_source_type"`
	SHA256           string        `json:"sha256"`
	SizeBytes        int64         `json:"size_bytes"`
	UpdatedAt        *time.Time    `json:"updated_at,omitempty"`
	LastStatus       string        `json:"last_status"`
	LastError        string        `json:"last_error"`
	Backups          []BackupEntry `json:"backups"`
}

// GeoIPScheduleSummary GeoIP 调度与凭据脱敏摘要（绝不回显 MaxMind License Key 原文）。
type GeoIPScheduleSummary struct {
	AutoUpdateEnabled    bool   `json:"auto_update_enabled"`
	ScheduleCron         string `json:"schedule_cron"`
	HASyncEnabled        bool   `json:"ha_sync_enabled"`
	MaxMindAccountID     string `json:"maxmind_account_id"`
	HasMaxMindLicenseKey bool   `json:"has_maxmind_license_key"`
}

// StatusResponse GET /api/v1/geoip/status 响应载荷。
type StatusResponse struct {
	GeoEnabled bool                 `json:"geo_enabled"`
	Sources    []string             `json:"sources"`
	LoadedAt   *time.Time           `json:"loaded_at,omitempty"`
	Revision   string               `json:"revision"`
	Schedule   GeoIPScheduleSummary `json:"schedule"`
	Slots      []SlotStatusView     `json:"slots"`
	HANodes    []HANodeGeoStatus    `json:"ha_nodes"`
	Presets    []GeoPreset          `json:"presets"`
}

// SlotSettingsPatch 单个 GeoIP 槽位配置变更载荷。
type SlotSettingsPatch struct {
	Slot           string `json:"slot"`
	Enabled        bool   `json:"enabled"`
	SourceMode     string `json:"source_mode"`
	OfficialPreset string `json:"official_preset"`
	CustomURL      string `json:"custom_url"`
}

// UpdateSettingsRequest PUT /api/v1/geoip/settings 请求体。
type UpdateSettingsRequest struct {
	AutoUpdateEnabled      *bool               `json:"auto_update_enabled,omitempty"`
	ScheduleCron           *string             `json:"schedule_cron,omitempty"`
	HASyncEnabled          *bool               `json:"ha_sync_enabled,omitempty"`
	MaxMindAccountID       *string             `json:"maxmind_account_id,omitempty"`
	MaxMindLicenseKey      string              `json:"maxmind_license_key,omitempty"`
	ClearMaxMindLicenseKey bool                `json:"clear_maxmind_license_key,omitempty"`
	Slots                  []SlotSettingsPatch `json:"slots,omitempty"`
}

type slotActionRequest struct {
	Slot string `json:"slot"`
}

// SyncActionResponse POST /api/v1/geoip/sync 与 POST /api/v1/geoip/ha-resync 统一响应体。
type SyncActionResponse struct {
	Runs            []SyncRun `json:"runs"`
	Succeeded       int       `json:"succeeded"`
	Skipped         int       `json:"skipped"`
	PartialHAFailed int       `json:"partial_ha_failed"`
	Failed          int       `json:"failed"`
}

// Status GET /api/v1/geoip/status
func (h *ManageHandler) Status(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.manager == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "GeoIP 管理服务未初始化")
		return
	}
	statusResp, err := h.buildStatusResponse(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, statusResp)
}

func (h *ManageHandler) buildStatusResponse(ctx context.Context) (*StatusResponse, error) {
	diskSlots, rev, err := h.manager.InspectSlots()
	if err != nil {
		return nil, err
	}

	cfgMap := map[string]SlotConfig{}
	if h.store != nil {
		cfgs, err := h.store.ListSlotConfigs(ctx)
		if err != nil {
			return nil, err
		}
		for _, c := range cfgs {
			cfgMap[c.Slot] = c
		}
	}

	views := make([]SlotStatusView, 0, len(diskSlots))
	primaryRuntimeHashes := map[string]string{}
	for _, ds := range diskSlots {
		v := SlotStatusView{
			Slot:             ds.Slot,
			DisplayName:      ds.DisplayName,
			CanonicalFile:    ds.CanonicalFile,
			Format:           ds.Format,
			MaxBytes:         ds.MaxBytes,
			SourceMode:       SourceModeOfflineOnly,
			ActiveOrigin:     ds.ActiveOrigin,
			ActiveFilename:   ds.ActiveFilename,
			ActiveSourceType: SourceTypeBuiltin,
			SHA256:           ds.SHA256,
			SizeBytes:        ds.SizeBytes,
			UpdatedAt:        ds.UpdatedAt,
			LastStatus:       RunStatusIdle,
			Backups:          ds.Backups,
		}
		if c, ok := cfgMap[ds.Slot]; ok {
			if c.DisplayName != "" {
				v.DisplayName = c.DisplayName
			}
			v.Enabled = c.Enabled
			v.SourceMode = c.SourceMode
			v.OfficialPreset = c.OfficialPreset
			v.CustomURL = c.CustomURL
			if c.ActiveSourceType != "" {
				v.ActiveSourceType = c.ActiveSourceType
			}
			if c.LastStatus != "" {
				v.LastStatus = c.LastStatus
			}
			v.LastError = c.LastError
			if v.UpdatedAt == nil && c.LastUpdatedAt != nil {
				v.UpdatedAt = c.LastUpdatedAt
			}
		}
		if ds.ActiveOrigin == "runtime" && rev != nil {
			if meta, ok := rev.Slots[ds.Slot]; ok && meta.SourceType != "" {
				v.ActiveSourceType = meta.SourceType
			}
		}
		if ds.ActiveOrigin == "runtime" && ds.SHA256 != "" {
			primaryRuntimeHashes[ds.Slot] = ds.SHA256
		}
		views = append(views, v)
	}

	sched := GeoIPScheduleSummary{
		ScheduleCron:  DefaultGeoIPScheduleCron,
		HASyncEnabled: true,
	}
	if h.settings != nil {
		sched.AutoUpdateEnabled = h.settings.GetBool(ctx, GeoIPSettingsGroup, KeyGeoIPAutoUpdateEnabled, false)
		if cron := strings.TrimSpace(h.settings.GetString(ctx, GeoIPSettingsGroup, KeyGeoIPScheduleCron, DefaultGeoIPScheduleCron)); cron != "" {
			sched.ScheduleCron = cron
		}
		sched.HASyncEnabled = h.settings.GetBool(ctx, GeoIPSettingsGroup, KeyGeoIPHASyncEnabled, true)
		sched.MaxMindAccountID = strings.TrimSpace(h.settings.GetString(ctx, GeoIPSettingsGroup, KeyMaxMindAccountID, ""))
		sched.HasMaxMindLicenseKey = strings.TrimSpace(h.settings.GetString(ctx, GeoIPSettingsGroup, KeyMaxMindLicenseKeyEnc, "")) != ""
	}

	var loadedAt *time.Time
	eng := h.manager.Engine()
	if eng != nil {
		if t := eng.LoadedAt(); !t.IsZero() {
			loadedAt = &t
		}
	}
	revID := ""
	if rev != nil {
		revID = rev.Revision
	}

	haNodes := []HANodeGeoStatus{}
	if pusher := h.effectiveHAPusher(); pusher != nil {
		peers, peerErr := pusher.ListPeerGeoIPStatus(ctx)
		if peerErr != nil {
			slog.Warn("list peer geoip status failed", "error", peerErr)
		} else {
			for _, peer := range peers {
				if peer.Slots == nil {
					peer.Slots = map[string]HANodeSlotDigest{}
				}
				peer.Consistent = evaluatePeerConsistency(primaryRuntimeHashes, peer)
				haNodes = append(haNodes, peer)
			}
		}
	}

	return &StatusResponse{
		GeoEnabled: eng != nil && eng.Enabled(),
		Sources:    eng.Sources(),
		LoadedAt:   loadedAt,
		Revision:   revID,
		Schedule:   sched,
		Slots:      views,
		HANodes:    haNodes,
		Presets:    OfficialPresets(),
	}, nil
}

func evaluatePeerConsistency(primaryRuntimeHashes map[string]string, peer HANodeGeoStatus) bool {
	if !peer.Reachable || !peer.GeoIPReady || strings.TrimSpace(peer.Error) != "" {
		return false
	}
	for slot, primarySHA := range primaryRuntimeHashes {
		peerMeta, ok := peer.Slots[slot]
		if !ok || !strings.EqualFold(strings.TrimSpace(peerMeta.SHA256), primarySHA) {
			return false
		}
	}
	return true
}

// UpdateSettings PUT /api/v1/geoip/settings
func (h *ManageHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.manager == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "GeoIP 管理服务未初始化")
		return
	}
	var req UpdateSettingsRequest
	if err := response.DecodeJSON(w, r, &req, maxSettingsBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体必须是合法 JSON")
		return
	}

	ctx := r.Context()
	p := authz.PrincipalFrom(ctx)
	var opID uuid.UUID
	var opPtr *uuid.UUID
	if p != nil && p.UserID != uuid.Nil {
		opID = p.UserID
		id := p.UserID
		opPtr = &id
	}

	hasGlobalChanges := req.AutoUpdateEnabled != nil ||
		req.ScheduleCron != nil ||
		req.HASyncEnabled != nil ||
		req.MaxMindAccountID != nil ||
		req.MaxMindLicenseKey != "" ||
		req.ClearMaxMindLicenseKey

	writer := h.effectiveSettingsWriter()
	if hasGlobalChanges && writer == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "系统设置写入服务未初始化")
		return
	}
	if len(req.Slots) > 0 && h.store == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "GeoIP 配置仓储未初始化")
		return
	}

	// 1. 校验 Cron 表达式
	var cleanedCron string
	if req.ScheduleCron != nil {
		cleanedCron = strings.TrimSpace(*req.ScheduleCron)
		spec, err := ParseCron(cleanedCron)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
		if _, err := spec.NextAfter(time.Now().UTC()); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
	}

	// 2. 校验 MaxMind Account ID 与只写 License Key
	var cleanedAccountID string
	if req.MaxMindAccountID != nil {
		cleanedAccountID = strings.TrimSpace(*req.MaxMindAccountID)
		if len(cleanedAccountID) > maxAccountIDLen || hasControlChars(cleanedAccountID) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "maxmind_account_id 格式非法")
			return
		}
	}
	if req.ClearMaxMindLicenseKey && req.MaxMindLicenseKey != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "不能同时设置 maxmind_license_key 与 clear_maxmind_license_key")
		return
	}
	var encryptedLicenseKey string
	licenseKeyUpdated := false
	if req.MaxMindLicenseKey != "" {
		trimmedKey := strings.TrimSpace(req.MaxMindLicenseKey)
		if trimmedKey == "" || len(trimmedKey) > maxLicenseKeyLen || hasControlChars(trimmedKey) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "maxmind_license_key 格式非法")
			return
		}
		cipher := h.effectiveCipher()
		if cipher == nil {
			response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "系统主密钥加密服务未初始化，无法保存 MaxMind License Key")
			return
		}
		enc, err := cipher.Encrypt(trimmedKey)
		if err != nil {
			response.InternalError(w, r, fmt.Errorf("encrypt maxmind license key: %w", err))
			return
		}
		encryptedLicenseKey = enc
		licenseKeyUpdated = true
	}

	// 计算本次更新生效后的 MaxMind 凭据可用状态（用于校验启用 MaxMind 预置源的前置条件）。
	effectiveAccountID := ""
	effectiveHasLicenseKey := false
	if h.settings != nil {
		effectiveAccountID = strings.TrimSpace(h.settings.GetString(ctx, GeoIPSettingsGroup, KeyMaxMindAccountID, ""))
		effectiveHasLicenseKey = strings.TrimSpace(h.settings.GetString(ctx, GeoIPSettingsGroup, KeyMaxMindLicenseKeyEnc, "")) != ""
	}
	if req.MaxMindAccountID != nil {
		effectiveAccountID = cleanedAccountID
	}
	if licenseKeyUpdated {
		effectiveHasLicenseKey = true
	} else if req.ClearMaxMindLicenseKey {
		effectiveHasLicenseKey = false
	}

	// 3. 逐项校验全部槽位变更（全通过后再统一落库，避免部分写入）
	seenSlots := map[string]bool{}
	validatedSlots := make([]SlotConfigUpdate, 0, len(req.Slots))
	for _, patch := range req.Slots {
		slot := strings.TrimSpace(patch.Slot)
		if _, ok := ValidSlot(slot); !ok {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				fmt.Sprintf("无效的 slot 参数（允许值: %s）", strings.Join(SlotOrder, "/")))
			return
		}
		if seenSlots[slot] {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				fmt.Sprintf("请求中包含重复槽位: %s", slot))
			return
		}
		seenSlots[slot] = true

		mode := strings.ToUpper(strings.TrimSpace(patch.SourceMode))
		presetID := strings.TrimSpace(patch.OfficialPreset)
		customURL := strings.TrimSpace(patch.CustomURL)

		switch mode {
		case SourceModeOfflineOnly:
			if len(customURL) > maxCustomURLBytes {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "custom_url 过长")
				return
			}
		case SourceModeOfficial:
			preset, ok := LookupPreset(presetID)
			if !ok || preset.Slot != slot {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
					fmt.Sprintf("槽位 %s 不支持官方预置源 %q", slot, presetID))
				return
			}
			if preset.RequiresMaxMindAuth && patch.Enabled && (effectiveAccountID == "" || !effectiveHasLicenseKey) {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, ErrMaxMindNotConfigured.Error())
				return
			}
		case SourceModeCustomURL:
			if customURL == "" || len(customURL) > maxCustomURLBytes {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
					fmt.Sprintf("槽位 %s 在 CUSTOM_URL 模式下必须提供合法的 custom_url", slot))
				return
			}
			if err := h.validateCustomURL(ctx, customURL); err != nil {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
					fmt.Sprintf("槽位 %s 的 custom_url 未通过出站安全校验: %v", slot, err))
				return
			}
		default:
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				fmt.Sprintf("槽位 %s 的 source_mode 无效（允许值: OFFLINE_ONLY/OFFICIAL/CUSTOM_URL）", slot))
			return
		}

		validatedSlots = append(validatedSlots, SlotConfigUpdate{
			Slot:           slot,
			Enabled:        patch.Enabled,
			SourceMode:     mode,
			OfficialPreset: presetID,
			CustomURL:      customURL,
			OperatorID:     opPtr,
			UpdatedAt:      time.Now().UTC(),
		})
	}

	// 4. 持久化全局设置与槽位配置
	if req.AutoUpdateEnabled != nil {
		if err := writer.UpsertBool(ctx, GeoIPSettingsGroup, KeyGeoIPAutoUpdateEnabled, *req.AutoUpdateEnabled,
			"GeoIP 归属地库在线定时更新总开关（默认关闭）", opID); err != nil {
			response.InternalError(w, r, err)
			return
		}
	}
	if req.ScheduleCron != nil {
		if err := writer.UpsertString(ctx, GeoIPSettingsGroup, KeyGeoIPScheduleCron, cleanedCron,
			"GeoIP 归属地库定时更新 Cron 表达式（默认每月 2 日 03:00）", opID); err != nil {
			response.InternalError(w, r, err)
			return
		}
	}
	if req.HASyncEnabled != nil {
		if err := writer.UpsertBool(ctx, GeoIPSettingsGroup, KeyGeoIPHASyncEnabled, *req.HASyncEnabled,
			"GeoIP 更新/上传/回滚后是否自动通过 hasyncd 同步至 HA 备节点", opID); err != nil {
			response.InternalError(w, r, err)
			return
		}
	}
	if req.MaxMindAccountID != nil {
		if err := writer.UpsertString(ctx, GeoIPSettingsGroup, KeyMaxMindAccountID, cleanedAccountID,
			"MaxMind GeoLite2 账号 ID（拉取官方 GeoLite2 时必填）", opID); err != nil {
			response.InternalError(w, r, err)
			return
		}
	}
	if licenseKeyUpdated {
		if err := writer.UpsertSensitiveString(ctx, GeoIPSettingsGroup, KeyMaxMindLicenseKeyEnc, encryptedLicenseKey,
			"MaxMind GeoLite2 License Key 密文（经系统主密钥加密存储，绝不明文回显）", opID); err != nil {
			response.InternalError(w, r, err)
			return
		}
	} else if req.ClearMaxMindLicenseKey {
		if err := writer.UpsertSensitiveString(ctx, GeoIPSettingsGroup, KeyMaxMindLicenseKeyEnc, "",
			"MaxMind GeoLite2 License Key 密文（经系统主密钥加密存储，绝不明文回显）", opID); err != nil {
			response.InternalError(w, r, err)
			return
		}
	}

	updatedSlotNames := make([]string, 0, len(validatedSlots))
	for _, su := range validatedSlots {
		if err := h.store.UpdateSlotConfig(ctx, su); err != nil {
			response.InternalError(w, r, err)
			return
		}
		updatedSlotNames = append(updatedSlotNames, su.Slot)
	}

	statusResp, err := h.buildStatusResponse(ctx)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}

	// 审计摘要严格脱敏：绝不记录 MaxMind License Key 明文或密文。
	h.writeAudit(r, p, "geoip_settings_update", "geoip", "settings", audits.ResultSuccess, map[string]any{
		"auto_update_enabled":        statusResp.Schedule.AutoUpdateEnabled,
		"schedule_cron":              statusResp.Schedule.ScheduleCron,
		"ha_sync_enabled":            statusResp.Schedule.HASyncEnabled,
		"maxmind_account_id":         statusResp.Schedule.MaxMindAccountID,
		"has_maxmind_license_key":    statusResp.Schedule.HasMaxMindLicenseKey,
		"maxmind_license_key_updated": licenseKeyUpdated,
		"maxmind_license_key_cleared": req.ClearMaxMindLicenseKey,
		"updated_slots":              updatedSlotNames,
	})

	response.JSON(w, r, http.StatusOK, statusResp)
}

// TriggerSync POST /api/v1/geoip/sync
func (h *ManageHandler) TriggerSync(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.syncer == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "GeoIP 在线同步服务未初始化")
		return
	}
	var req slotActionRequest
	if err := decodeOptionalJSON(w, r, &req, maxSyncBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体必须是合法 JSON")
		return
	}

	p := authz.PrincipalFrom(r.Context())
	var opID *uuid.UUID
	if p != nil && p.UserID != uuid.Nil {
		id := p.UserID
		opID = &id
	}

	slot := strings.TrimSpace(req.Slot)
	var runs []SyncRun
	if slot != "" {
		run, err := h.syncer.SyncSlot(r.Context(), slot, TriggerManual, opID)
		if run == nil && err != nil {
			h.writeAudit(r, p, "geoip_sync", slot, slot, audits.ResultFailure, map[string]any{
				"slot":  slot,
				"error": err.Error(),
			})
			writeGeoSyncError(w, r, err)
			return
		}
		if run != nil {
			runs = []SyncRun{*run}
		}
	} else {
		var err error
		runs, err = h.syncer.SyncAllEnabled(r.Context(), TriggerManual, opID)
		if err != nil {
			h.writeAudit(r, p, "geoip_sync", "all", "all", audits.ResultFailure, map[string]any{
				"error": err.Error(),
			})
			response.InternalError(w, r, err)
			return
		}
	}

	resp := summarizeSyncRuns(runs)
	auditResult := audits.ResultSuccess
	if resp.Failed > 0 {
		auditResult = audits.ResultFailure
	}
	target := slot
	if target == "" {
		target = "all"
	}
	h.writeAudit(r, p, "geoip_sync", target, target, auditResult, map[string]any{
		"slot":              target,
		"total_runs":        len(resp.Runs),
		"succeeded":         resp.Succeeded,
		"skipped":           resp.Skipped,
		"partial_ha_failed": resp.PartialHAFailed,
		"failed":            resp.Failed,
	})

	response.JSON(w, r, http.StatusOK, resp)
}

// TriggerHAResync POST /api/v1/geoip/ha-resync
func (h *ManageHandler) TriggerHAResync(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.syncer == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "GeoIP HA 重同步服务未初始化")
		return
	}
	var req slotActionRequest
	if err := decodeOptionalJSON(w, r, &req, maxSyncBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体必须是合法 JSON")
		return
	}

	p := authz.PrincipalFrom(r.Context())
	var opID *uuid.UUID
	if p != nil && p.UserID != uuid.Nil {
		id := p.UserID
		opID = &id
	}

	slot := strings.TrimSpace(req.Slot)
	runs, err := h.syncer.HAResync(r.Context(), slot, opID)
	if err != nil {
		target := slot
		if target == "" {
			target = "all"
		}
		h.writeAudit(r, p, "geoip_ha_resync", target, target, audits.ResultFailure, map[string]any{
			"slot":  target,
			"error": err.Error(),
		})
		writeGeoSyncError(w, r, err)
		return
	}

	resp := summarizeSyncRuns(runs)
	auditResult := audits.ResultSuccess
	if resp.Failed > 0 || resp.PartialHAFailed > 0 {
		auditResult = audits.ResultFailure
	}
	target := slot
	if target == "" {
		target = "all"
	}
	h.writeAudit(r, p, "geoip_ha_resync", target, target, auditResult, map[string]any{
		"slot":              target,
		"total_runs":        len(resp.Runs),
		"succeeded":         resp.Succeeded,
		"partial_ha_failed": resp.PartialHAFailed,
		"failed":            resp.Failed,
	})

	response.JSON(w, r, http.StatusOK, resp)
}

// Upload POST /api/v1/geoip/upload
// multipart/form-data 字段：
//   - slot（必填，支持同时从 query 兜底）：ip2region_v4 | ip2region_v6 | dbip_city | city_ipv6 | country
//   - file（必填）：.xdb / .mmdb / .xdb.gz / .mmdb.gz / .tar.gz（MaxMind GeoLite2）
//   - expected_sha256（可选）：64 位十六进制 SHA-256 摘要（原始文件或解压后库文件任一匹配即通过）
func (h *ManageHandler) Upload(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.manager == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "GeoIP 管理服务未初始化")
		return
	}
	startedAt := time.Now().UTC()
	p := authz.PrincipalFrom(r.Context())

	r.Body = http.MaxBytesReader(w, r.Body, maxGeoMultipartBytes)
	mr, err := r.MultipartReader()
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求必须为 multipart/form-data 格式")
		return
	}

	slot := strings.TrimSpace(r.URL.Query().Get("slot"))
	expectedSHA := strings.TrimSpace(r.URL.Query().Get("expected_sha256"))
	var uploadedFilename string
	var tempUploadPath string
	defer func() {
		if tempUploadPath != "" {
			_ = os.Remove(tempUploadPath)
		}
	}()

	// 流式读取全部 multipart 段：大文件直接落临时文件（避免 256 MiB 进入内存），兼容任意字段顺序
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				response.Error(w, r, http.StatusRequestEntityTooLarge, response.CodeInvalidArgument, "上传文件超过大小上限")
				return
			}
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "解析上传表单失败")
			return
		}
		name := part.FormName()
		switch name {
		case "slot":
			b, readErr := io.ReadAll(io.LimitReader(part, 128))
			_ = part.Close()
			if readErr != nil {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "读取 slot 参数失败")
				return
			}
			slot = strings.TrimSpace(string(b))
		case "expected_sha256":
			b, readErr := io.ReadAll(io.LimitReader(part, 256))
			_ = part.Close()
			if readErr != nil {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "读取 expected_sha256 参数失败")
				return
			}
			expectedSHA = strings.TrimSpace(string(b))
		case "file":
			if tempUploadPath != "" {
				_ = part.Close()
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "单次仅支持上传一个 GeoIP 文件")
				return
			}
			uploadedFilename = filepath.Base(strings.TrimSpace(part.FileName()))
			if err := os.MkdirAll(h.manager.stagingDir(), 0o750); err != nil {
				_ = part.Close()
				response.InternalError(w, r, err)
				return
			}
			tmpFile, err := os.CreateTemp(h.manager.stagingDir(), "upload-*.tmp")
			if err != nil {
				_ = part.Close()
				response.InternalError(w, r, err)
				return
			}
			tempUploadPath = tmpFile.Name()
			n, copyErr := io.Copy(tmpFile, io.LimitReader(part, maxGeoMultipartBytes+1))
			closeErr := tmpFile.Close()
			_ = part.Close()
			if copyErr != nil {
				var maxErr *http.MaxBytesError
				if errors.As(copyErr, &maxErr) {
					response.Error(w, r, http.StatusRequestEntityTooLarge, response.CodeInvalidArgument, "上传文件超过大小上限")
					return
				}
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "读取上传文件流失败")
				return
			}
			if closeErr != nil {
				response.InternalError(w, r, closeErr)
				return
			}
			if n == 0 {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "上传文件不能为空")
				return
			}
			if n > maxGeoMultipartBytes {
				response.Error(w, r, http.StatusRequestEntityTooLarge, response.CodeInvalidArgument, "上传文件超过大小上限")
				return
			}
		default:
			_, _ = io.Copy(io.Discard, io.LimitReader(part, 64<<10))
			_ = part.Close()
		}
	}

	if _, ok := ValidSlot(slot); !ok {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("无效的 slot 参数（允许值: %s）", strings.Join(SlotOrder, "/")))
		return
	}
	if tempUploadPath == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请通过 file 字段上传 GeoIP 数据文件")
		return
	}

	f, err := os.Open(tempUploadPath)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	result, installErr := h.manager.InstallSlotFromReader(slot, uploadedFilename, f, expectedSHA, SourceTypeOffline)
	_ = f.Close()

	var opID *uuid.UUID
	if p != nil && p.UserID != uuid.Nil {
		id := p.UserID
		opID = &id
	}

	if installErr != nil {
		finishedAt := time.Now().UTC()
		h.recordRunAndSlot(r.Context(), slot, TriggerOfflineUpload, RunStatusFailed, uploadedFilename,
			"", "", 0, SourceTypeOffline, nil, installErr.Error(), opID, startedAt, finishedAt, false)
		h.writeAudit(r, p, "geoip_upload", slot, uploadedFilename, audits.ResultFailure, map[string]any{
			"slot":  slot,
			"file":  uploadedFilename,
			"error": installErr.Error(),
		})
		writeGeoSlotError(w, r, installErr)
		return
	}

	status := RunStatusSuccess
	errMsg := ""
	var haResults []HANodeSyncResult
	if result.Unchanged {
		status = RunStatusSkippedUnchange
	} else if h.syncer != nil {
		var haErr error
		haResults, haErr = h.syncer.PushInstalledSlotIfEnabled(r.Context(), slot, result.Revision)
		result.HAResults = haResults
		if haErr != nil {
			status = RunStatusPartialHAFailed
			errMsg = haErr.Error()
		}
	}

	finishedAt := time.Now().UTC()
	h.recordRunAndSlot(r.Context(), slot, TriggerOfflineUpload, status, uploadedFilename,
		result.PreviousSHA256, result.NewSHA256, result.SizeBytes, SourceTypeOffline, haResults, errMsg,
		opID, startedAt, finishedAt, !result.Unchanged)

	h.writeAudit(r, p, "geoip_upload", slot, result.Filename, audits.ResultSuccess, map[string]any{
		"slot":            slot,
		"filename":        result.Filename,
		"uploaded_file":   uploadedFilename,
		"previous_sha256": result.PreviousSHA256,
		"new_sha256":      result.NewSHA256,
		"size_bytes":      result.SizeBytes,
		"revision":        result.Revision,
		"unchanged":       result.Unchanged,
		"status":          status,
	})

	response.JSON(w, r, http.StatusOK, result)
}

type rollbackRequest struct {
	Slot     string `json:"slot"`
	BackupID string `json:"backup_id"`
}

// Rollback POST /api/v1/geoip/rollback
func (h *ManageHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.manager == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "GeoIP 管理服务未初始化")
		return
	}
	startedAt := time.Now().UTC()
	p := authz.PrincipalFrom(r.Context())

	var req rollbackRequest
	if err := response.DecodeJSON(w, r, &req, maxRollbackBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体必须是合法 JSON")
		return
	}
	slot := strings.TrimSpace(req.Slot)
	backupID := strings.TrimSpace(req.BackupID)
	if _, ok := ValidSlot(slot); !ok {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("无效的 slot 参数（允许值: %s）", strings.Join(SlotOrder, "/")))
		return
	}
	if backupID == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "backup_id 不能为空")
		return
	}

	result, err := h.manager.RollbackSlot(slot, backupID)
	var opID *uuid.UUID
	if p != nil && p.UserID != uuid.Nil {
		id := p.UserID
		opID = &id
	}

	if err != nil {
		finishedAt := time.Now().UTC()
		h.recordRunAndSlot(r.Context(), slot, TriggerRollback, RunStatusFailed, backupID,
			"", "", 0, SourceTypeRollback, nil, err.Error(), opID, startedAt, finishedAt, false)
		h.writeAudit(r, p, "geoip_rollback", slot, backupID, audits.ResultFailure, map[string]any{
			"slot":      slot,
			"backup_id": backupID,
			"error":     err.Error(),
		})
		writeGeoSlotError(w, r, err)
		return
	}

	status := RunStatusSuccess
	errMsg := ""
	var haResults []HANodeSyncResult
	if result.Unchanged {
		status = RunStatusSkippedUnchange
	} else if h.syncer != nil {
		var haErr error
		haResults, haErr = h.syncer.PushInstalledSlotIfEnabled(r.Context(), slot, result.Revision)
		result.HAResults = haResults
		if haErr != nil {
			status = RunStatusPartialHAFailed
			errMsg = haErr.Error()
		}
	}

	finishedAt := time.Now().UTC()
	h.recordRunAndSlot(r.Context(), slot, TriggerRollback, status, backupID,
		result.PreviousSHA256, result.NewSHA256, result.SizeBytes, SourceTypeRollback, haResults, errMsg,
		opID, startedAt, finishedAt, !result.Unchanged)

	h.writeAudit(r, p, "geoip_rollback", slot, result.Filename, audits.ResultSuccess, map[string]any{
		"slot":            slot,
		"backup_id":       backupID,
		"previous_sha256": result.PreviousSHA256,
		"new_sha256":      result.NewSHA256,
		"revision":        result.Revision,
		"unchanged":       result.Unchanged,
		"status":          status,
	})

	response.JSON(w, r, http.StatusOK, result)
}

// ListRuns GET /api/v1/geoip/runs
func (h *ManageHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		response.JSON(w, r, http.StatusOK, response.PageData{
			Items:    []SyncRun{},
			Page:     1,
			PageSize: 20,
			Total:    0,
		})
		return
	}
	q := r.URL.Query()
	slot := strings.TrimSpace(q.Get("slot"))
	if slot != "" {
		if _, ok := ValidSlot(slot); !ok {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 slot 过滤条件")
			return
		}
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	if pageSize > 100 {
		pageSize = 100
	}
	items, total, err := h.store.ListSyncRuns(r.Context(), RunFilter{
		Slot:        slot,
		TriggerType: strings.TrimSpace(q.Get("trigger_type")),
		Status:      strings.TrimSpace(q.Get("status")),
		Page:        page,
		PageSize:    pageSize,
	})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, response.PageData{
		Items:    items,
		Page:     page,
		PageSize: pageSize,
		Total:    total,
	})
}

func (h *ManageHandler) recordRunAndSlot(
	ctx context.Context,
	slot, triggerType, status, sourceLabel string,
	prevSHA, newSHA string,
	sizeBytes int64,
	sourceType string,
	haResults []HANodeSyncResult,
	errMsg string,
	operatorID *uuid.UUID,
	startedAt, finishedAt time.Time,
	updateActive bool,
) {
	if h.store == nil {
		return
	}
	if haResults == nil {
		haResults = []HANodeSyncResult{}
	}
	spec, _ := ValidSlot(slot)
	if err := h.store.InsertSyncRun(ctx, &SyncRun{
		Slot:           slot,
		TriggerType:    triggerType,
		Status:         status,
		SourceLabel:    sourceLabel,
		PreviousSHA256: prevSHA,
		NewSHA256:      newSHA,
		FileSizeBytes:  sizeBytes,
		HAResults:      haResults,
		ErrorMessage:   errMsg,
		OperatorID:     operatorID,
		StartedAt:      startedAt,
		FinishedAt:     finishedAt,
	}); err != nil {
		slog.Warn("record geoip sync run failed", "slot", slot, "error", err)
	}
	if err := h.store.UpdateSlotStatus(ctx, SlotActivationUpdate{
		Slot:             slot,
		ActiveFilename:   spec.CanonicalFile,
		ActiveSHA256:     newSHA,
		ActiveSizeBytes:  sizeBytes,
		ActiveSourceType: sourceType,
		Status:           status,
		ErrorMessage:     errMsg,
		OperatorID:       operatorID,
		UpdatedAt:        finishedAt,
		UpdateActiveFile: updateActive,
	}); err != nil {
		slog.Warn("update geoip slot config status failed", "slot", slot, "error", err)
	}
}

func (h *ManageHandler) writeAudit(r *http.Request, p *authz.Principal, action, slot, objName, result string, summary map[string]any) {
	if h.audits == nil {
		return
	}
	var uid *uuid.UUID
	username := ""
	if p != nil {
		id := p.UserID
		uid = &id
		username = p.Username
	}
	summaryBytes, _ := json.Marshal(summary)
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       uid,
		Username:     username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "access_control",
		Action:       action,
		ObjectType:   "geoip_database",
		ObjectID:     slot,
		ObjectName:   objName,
		AfterSummary: string(summaryBytes),
		Result:       result,
		RiskLevel:    audits.RiskMedium,
		RequestID:    response.RequestIDFrom(r),
	})
}

func summarizeSyncRuns(runs []SyncRun) SyncActionResponse {
	if runs == nil {
		runs = []SyncRun{}
	}
	out := SyncActionResponse{Runs: runs}
	for _, run := range runs {
		switch run.Status {
		case RunStatusSuccess:
			out.Succeeded++
		case RunStatusSkippedUnchange:
			out.Skipped++
		case RunStatusPartialHAFailed:
			out.PartialHAFailed++
		case RunStatusFailed:
			out.Failed++
		}
	}
	return out
}

func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	if r.Body == nil {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(http.MaxBytesReader(w, r.Body, maxBytes), maxBytes+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > maxBytes {
		return errors.New("request body too large")
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

func hasControlChars(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func writeGeoSlotError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrInvalidSlot),
		errors.Is(err, ErrInvalidBackupID),
		errors.Is(err, ErrGeoFileInvalid),
		errors.Is(err, ErrSHA256Mismatch):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
	case errors.Is(err, ErrBackupNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, err.Error())
	case errors.Is(err, ErrGeoFileTooLarge):
		response.Error(w, r, http.StatusRequestEntityTooLarge, response.CodeInvalidArgument, err.Error())
	default:
		response.InternalError(w, r, err)
	}
}

func writeGeoSyncError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrInvalidSlot),
		errors.Is(err, ErrSlotOfflineOnly),
		errors.Is(err, ErrInvalidSlotConfig),
		errors.Is(err, ErrMaxMindNotConfigured),
		errors.Is(err, ErrSlotRuntimeMissing),
		errors.Is(err, outboundhttp.ErrDenied),
		errors.Is(err, iplibhttp.ErrOfflineOnly):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
	case errors.Is(err, ErrHAPusherUnavailable):
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, err.Error())
	default:
		response.InternalError(w, r, err)
	}
}
