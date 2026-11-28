// syncer.go GeoIP 归属地库在线同步器、官方预置源注册表、HA 协同接口与后台分钟级定时调度器。
package apigeo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/iplibhttp"
)

// GeoIP 系统告警类型常量（与 server/internal/systemalerts/rules.go 一致）。
const (
	AlertTypeGeoIPSyncFailed = "GEOIP_SYNC_FAILED"
	AlertTypeGeoIPNodeDrift  = "GEOIP_NODE_DRIFT"
)

// 官方预置 GeoIP 源标识。
const (
	PresetIP2RegionV4           = "ip2region_v4"
	PresetIP2RegionV6           = "ip2region_v6"
	PresetDBIPCityLite          = "dbip_city_lite"
	PresetDBIPCountryLite       = "dbip_country_lite"
	PresetGeoCountryMMDB        = "geo_country_mmdb"
	PresetMaxMindGeoLite2City   = "maxmind_geolite2_city"
	PresetMaxMindGeoLite2Country = "maxmind_geolite2_country"
)

// 同步器哨兵错误。
var (
	ErrSlotOfflineOnly      = errors.New("该槽位当前为纯离线模式（OFFLINE_ONLY），请先配置官方源或内网镜像地址")
	ErrInvalidSlotConfig    = errors.New("GeoIP 槽位配置不完整或无效")
	ErrMaxMindNotConfigured = errors.New("使用 MaxMind GeoLite2 官方源前请先配置 MaxMind Account ID 与 License Key")
	ErrHAPusherUnavailable  = errors.New("HA 节点协同服务未启用")
	ErrSlotRuntimeMissing   = errors.New("该槽位当前无运行期 GeoIP 文件可供同步")
)

// GeoPreset 描述一个硬编码官方 GeoIP 预置源元数据。
type GeoPreset struct {
	ID                  string `json:"id"`
	Slot                string `json:"slot"`
	Name                string `json:"name"`
	License             string `json:"license"`
	URLTemplate         string `json:"url_template"`
	RequiresMaxMindAuth bool   `json:"requires_maxmind_auth"`
	MonthlyFallback     bool   `json:"monthly_fallback"`
}

var officialPresetsOrder = []GeoPreset{
	{
		ID:          PresetIP2RegionV4,
		Slot:        SlotIP2RegionV4,
		Name:        "ip2region IPv4 官方 XDB",
		License:     "Apache-2.0 OR MIT",
		URLTemplate: "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb",
	},
	{
		ID:          PresetIP2RegionV6,
		Slot:        SlotIP2RegionV6,
		Name:        "ip2region IPv6 官方 XDB",
		License:     "Apache-2.0 OR MIT",
		URLTemplate: "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb",
	},
	{
		ID:              PresetDBIPCityLite,
		Slot:            SlotDBIPCity,
		Name:            "DB-IP City Lite（月度免费版）",
		License:         "CC BY 4.0",
		URLTemplate:     "https://download.db-ip.com/free/dbip-city-lite-{YYYY-MM}.mmdb.gz",
		MonthlyFallback: true,
	},
	{
		ID:              PresetDBIPCountryLite,
		Slot:            SlotCountry,
		Name:            "DB-IP Country Lite（月度免费版）",
		License:         "CC BY 4.0",
		URLTemplate:     "https://download.db-ip.com/free/dbip-country-lite-{YYYY-MM}.mmdb.gz",
		MonthlyFallback: true,
	},
	{
		ID:          PresetGeoCountryMMDB,
		Slot:        SlotCountry,
		Name:        "geo-whois-asn-country MMDB（GitHub 开源版）",
		License:     "CC0-1.0",
		URLTemplate: "https://raw.githubusercontent.com/sapics/ip-location-db/main/geo-whois-asn-country-mmdb/geo-whois-asn-country.mmdb",
	},
	{
		ID:                  PresetMaxMindGeoLite2City,
		Slot:                SlotDBIPCity,
		Name:                "MaxMind GeoLite2 City",
		License:             "MaxMind GeoLite2 EULA",
		URLTemplate:         "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz",
		RequiresMaxMindAuth: true,
	},
	{
		ID:                  PresetMaxMindGeoLite2Country,
		Slot:                SlotCountry,
		Name:                "MaxMind GeoLite2 Country",
		License:             "MaxMind GeoLite2 EULA",
		URLTemplate:         "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz",
		RequiresMaxMindAuth: true,
	},
}

var officialPresetsByID = func() map[string]GeoPreset {
	m := make(map[string]GeoPreset, len(officialPresetsOrder))
	for _, p := range officialPresetsOrder {
		m[p.ID] = p
	}
	return m
}()

// OfficialPresets 返回所有官方预置 GeoIP 源列表副本（固定顺序）。
func OfficialPresets() []GeoPreset {
	out := make([]GeoPreset, len(officialPresetsOrder))
	copy(out, officialPresetsOrder)
	return out
}

// LookupPreset 按 preset ID 查找官方预置源。
func LookupPreset(id string) (GeoPreset, bool) {
	p, ok := officialPresetsByID[strings.TrimSpace(id)]
	return p, ok
}

// HANodeSlotDigest 单个 HA 备节点上某槽位的文件摘要。
type HANodeSlotDigest struct {
	Filename  string `json:"filename"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// HANodeGeoStatus 单个 HA 备节点的 GeoIP 状态与主备一致性摘要。
type HANodeGeoStatus struct {
	NodeID     string                      `json:"node_id,omitempty"`
	NodeName   string                      `json:"node_name"`
	Reachable  bool                        `json:"reachable"`
	GeoIPReady bool                        `json:"geoip_ready"`
	Consistent bool                        `json:"consistent"`
	Revision   string                      `json:"revision"`
	UpdatedAt  *time.Time                  `json:"updated_at,omitempty"`
	Slots      map[string]HANodeSlotDigest `json:"slots"`
	Error      string                      `json:"error,omitempty"`
}

// HAGeoPusher 定义 HA 备节点 GeoIP 推送与状态探测窄接口（由 app.go 适配 nodesync.Manager 注入）。
type HAGeoPusher interface {
	PushGeoIPSlot(ctx context.Context, slot, filePath, sha256Hex, revision string) ([]HANodeSyncResult, error)
	ListPeerGeoIPStatus(ctx context.Context) ([]HANodeGeoStatus, error)
}

// SlotDownloader 是 GeoSyncer 依赖的受控下载器窄接口（*iplibhttp.Downloader 满足）。
type SlotDownloader interface {
	Fetch(ctx context.Context, req iplibhttp.FetchRequest) (*iplibhttp.FetchResult, error)
	ValidateTargetURL(ctx context.Context, sourceMode, rawURL string) error
}

// SecretCipher 是凭据加解密窄接口（*encryption.Service 满足）。
type SecretCipher interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(encoded string) (string, error)
}

// AlertFunc 是系统告警事件通知回调（app.go 可直接适配 systemalerts.Engine.NotifyFailure）。
type AlertFunc func(ctx context.Context, alertType, component, title, message string)

// GeoSyncer 负责 GeoIP 槽位在线拉取、安装热加载、HA 推送与定时调度。
type GeoSyncer struct {
	manager    *SlotManager
	store      ManageRepository
	settings   ManageSettingsReader
	downloader SlotDownloader
	cipher     SecretCipher
	haPusher   HAGeoPusher
	alertFn    AlertFunc
	now        func() time.Time
	tickEvery  time.Duration

	mu           sync.Mutex
	lastSchedMin int64
}

// NewGeoSyncer 创建 GeoIP 在线同步与定时调度器。
func NewGeoSyncer(
	manager *SlotManager,
	store ManageRepository,
	settings ManageSettingsReader,
	downloader SlotDownloader,
	cipher SecretCipher,
) *GeoSyncer {
	return &GeoSyncer{
		manager:    manager,
		store:      store,
		settings:   settings,
		downloader: downloader,
		cipher:     cipher,
		now:        func() time.Time { return time.Now().UTC() },
		tickEvery:  time.Minute,
	}
}

// SetHAPusher 注入 HA 备节点 GeoIP 推送器（可选）。
func (s *GeoSyncer) SetHAPusher(p HAGeoPusher) *GeoSyncer {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.haPusher = p
	return s
}

// HAPusher 返回当前注入的 HA 推送器（未注入返回 nil）。
func (s *GeoSyncer) HAPusher() HAGeoPusher {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.haPusher
}

// SetAlertFunc 注入系统告警通知回调（GEOIP_SYNC_FAILED / GEOIP_NODE_DRIFT）。
func (s *GeoSyncer) SetAlertFunc(fn AlertFunc) *GeoSyncer {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertFn = fn
	return s
}

// ValidateTargetURL 代理调用底层下载器的保存期 SSRF 校验。
func (s *GeoSyncer) ValidateTargetURL(ctx context.Context, sourceMode, rawURL string) error {
	if s == nil || s.downloader == nil {
		return errors.New("下载器未初始化，无法校验出站 URL")
	}
	return s.downloader.ValidateTargetURL(ctx, sourceMode, rawURL)
}

func (s *GeoSyncer) notifyAlert(ctx context.Context, alertType, component, title, message string) {
	s.mu.Lock()
	fn := s.alertFn
	s.mu.Unlock()
	if fn != nil {
		fn(ctx, alertType, component, title, message)
	}
}

// SyncSlot 对单个槽位执行在线拉取、验真、原子切换热加载、HA 同步及流水落库。
func (s *GeoSyncer) SyncSlot(ctx context.Context, slot, triggerType string, operatorID *uuid.UUID) (*SyncRun, error) {
	if s == nil || s.manager == nil || s.store == nil || s.downloader == nil {
		return nil, errors.New("GeoIP 同步服务未完整初始化")
	}
	spec, ok := ValidSlot(slot)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrInvalidSlot, slot)
	}
	if triggerType == "" {
		triggerType = TriggerManual
	}
	cfg, err := s.store.GetSlotConfig(ctx, slot)
	if err != nil {
		return nil, err
	}

	switch cfg.SourceMode {
	case SourceModeOfflineOnly:
		return nil, ErrSlotOfflineOnly
	case SourceModeOfficial, SourceModeCustomURL:
	default:
		return nil, fmt.Errorf("%w: 未知 source_mode %q", ErrInvalidSlotConfig, cfg.SourceMode)
	}

	candidates, basicUser, basicPass, sourceLabel, err := s.resolveSyncTargets(ctx, cfg)
	if err != nil {
		return nil, err
	}

	startedAt := s.now()
	maxDownloadBytes := spec.MaxBytes + maxArchiveOverhead

	var (
		fetchRes      *iplibhttp.FetchResult
		fetchErr      error
		usedLabel     = sourceLabel
		lastStatusErr *iplibhttp.HTTPStatusError
	)

	for i, cand := range candidates {
		res, err := s.downloader.Fetch(ctx, iplibhttp.FetchRequest{
			SourceMode:   cfg.SourceMode,
			URL:          cand.url,
			ETag:         cfg.ETag,
			LastModified: cfg.LastModified,
			BasicUser:    basicUser,
			BasicPass:    basicPass,
			MaxBytes:     maxDownloadBytes,
		})
		if err == nil {
			fetchRes = res
			if cand.label != "" {
				usedLabel = cand.label
			}
			fetchErr = nil
			break
		}
		fetchErr = err
		// DB-IP Lite 月度 URL 404 自动回退到上月版本（月初 1-3 日上游尚未发布当月包）。
		if errors.As(err, &lastStatusErr) && lastStatusErr.StatusCode == http.StatusNotFound && i+1 < len(candidates) {
			slog.Info("geoip monthly preset 404, falling back to previous month",
				"slot", slot, "preset", cfg.OfficialPreset, "attempt", i+1)
			continue
		}
		break
	}

	if fetchErr != nil {
		errMsg := scrubSecret(fetchErr.Error(), basicPass)
		finishedAt := s.now()
		run := &SyncRun{
			ID:             uuid.New(),
			Slot:           slot,
			TriggerType:    triggerType,
			Status:         RunStatusFailed,
			SourceLabel:    usedLabel,
			PreviousSHA256: cfg.ActiveSHA256,
			HAResults:      []HANodeSyncResult{},
			ErrorMessage:   errMsg,
			OperatorID:     operatorID,
			StartedAt:      startedAt,
			FinishedAt:     finishedAt,
		}
		s.persistRunAndSlot(ctx, run, SlotActivationUpdate{
			Slot:             slot,
			Status:           RunStatusFailed,
			ErrorMessage:     errMsg,
			OperatorID:       operatorID,
			UpdatedAt:        finishedAt,
			UpdateActiveFile: false,
		})
		s.notifyAlert(ctx, AlertTypeGeoIPSyncFailed, "geoip:"+slot,
			fmt.Sprintf("GeoIP 归属地库更新失败（%s）", slot),
			fmt.Sprintf("槽位 %s（来源 %s）在线拉取失败：%s", slot, usedLabel, errMsg))
		return run, fetchErr
	}

	if fetchRes.NotModified {
		finishedAt := s.now()
		run := &SyncRun{
			ID:             uuid.New(),
			Slot:           slot,
			TriggerType:    triggerType,
			Status:         RunStatusSkippedUnchange,
			SourceLabel:    usedLabel,
			PreviousSHA256: cfg.ActiveSHA256,
			NewSHA256:      cfg.ActiveSHA256,
			FileSizeBytes:  cfg.ActiveSizeBytes,
			HAResults:      []HANodeSyncResult{},
			OperatorID:     operatorID,
			StartedAt:      startedAt,
			FinishedAt:     finishedAt,
		}
		s.persistRunAndSlot(ctx, run, SlotActivationUpdate{
			Slot:             slot,
			ETag:             fetchRes.ETag,
			LastModified:     fetchRes.LastModified,
			Status:           RunStatusSkippedUnchange,
			ErrorMessage:     "",
			OperatorID:       operatorID,
			UpdatedAt:        finishedAt,
			UpdateActiveFile: false,
		})
		return run, nil
	}

	defer fetchRes.Body.Close()

	filename := strings.TrimSpace(fetchRes.Filename)
	if filename == "" {
		filename = spec.CanonicalFile
	}
	installRes, installErr := s.manager.InstallSlotFromReader(slot, filename, fetchRes.Body, "", SourceTypeOnline)
	if installErr != nil {
		errMsg := scrubSecret(installErr.Error(), basicPass)
		finishedAt := s.now()
		run := &SyncRun{
			ID:             uuid.New(),
			Slot:           slot,
			TriggerType:    triggerType,
			Status:         RunStatusFailed,
			SourceLabel:    usedLabel,
			PreviousSHA256: cfg.ActiveSHA256,
			HAResults:      []HANodeSyncResult{},
			ErrorMessage:   errMsg,
			OperatorID:     operatorID,
			StartedAt:      startedAt,
			FinishedAt:     finishedAt,
		}
		s.persistRunAndSlot(ctx, run, SlotActivationUpdate{
			Slot:             slot,
			Status:           RunStatusFailed,
			ErrorMessage:     errMsg,
			OperatorID:       operatorID,
			UpdatedAt:        finishedAt,
			UpdateActiveFile: false,
		})
		s.notifyAlert(ctx, AlertTypeGeoIPSyncFailed, "geoip:"+slot,
			fmt.Sprintf("GeoIP 归属地库校验安装失败（%s）", slot),
			fmt.Sprintf("槽位 %s（来源 %s）文件验真或切换失败：%s", slot, usedLabel, errMsg))
		return run, installErr
	}

	if installRes.Unchanged {
		finishedAt := s.now()
		run := &SyncRun{
			ID:             uuid.New(),
			Slot:           slot,
			TriggerType:    triggerType,
			Status:         RunStatusSkippedUnchange,
			SourceLabel:    usedLabel,
			PreviousSHA256: installRes.PreviousSHA256,
			NewSHA256:      installRes.NewSHA256,
			FileSizeBytes:  installRes.SizeBytes,
			HAResults:      []HANodeSyncResult{},
			OperatorID:     operatorID,
			StartedAt:      startedAt,
			FinishedAt:     finishedAt,
		}
		s.persistRunAndSlot(ctx, run, SlotActivationUpdate{
			Slot:             slot,
			ETag:             fetchRes.ETag,
			LastModified:     fetchRes.LastModified,
			Status:           RunStatusSkippedUnchange,
			ErrorMessage:     "",
			OperatorID:       operatorID,
			UpdatedAt:        finishedAt,
			UpdateActiveFile: false,
		})
		return run, nil
	}

	// 本地新文件已生效；若启用了 HA 同步则推送到所有备节点（备节点失败不回滚主节点，触发漂移告警）。
	status := RunStatusSuccess
	errMsg := ""
	haResults, haErr := s.PushInstalledSlotIfEnabled(ctx, slot, installRes.Revision)
	if haResults == nil {
		haResults = []HANodeSyncResult{}
	}
	if haErr != nil {
		status = RunStatusPartialHAFailed
		errMsg = haErr.Error()
	}

	finishedAt := s.now()
	run := &SyncRun{
		ID:             uuid.New(),
		Slot:           slot,
		TriggerType:    triggerType,
		Status:         status,
		SourceLabel:    usedLabel,
		PreviousSHA256: installRes.PreviousSHA256,
		NewSHA256:      installRes.NewSHA256,
		FileSizeBytes:  installRes.SizeBytes,
		HAResults:      haResults,
		ErrorMessage:   errMsg,
		OperatorID:     operatorID,
		StartedAt:      startedAt,
		FinishedAt:     finishedAt,
	}
	s.persistRunAndSlot(ctx, run, SlotActivationUpdate{
		Slot:             slot,
		ActiveFilename:   installRes.Filename,
		ActiveSHA256:     installRes.NewSHA256,
		ActiveSizeBytes:  installRes.SizeBytes,
		ActiveSourceType: SourceTypeOnline,
		ETag:             fetchRes.ETag,
		LastModified:     fetchRes.LastModified,
		Status:           status,
		ErrorMessage:     errMsg,
		OperatorID:       operatorID,
		UpdatedAt:        finishedAt,
		UpdateActiveFile: true,
	})
	return run, nil
}

// PushInstalledSlotIfEnabled 当已注入 HAGeoPusher 且 geoip.ha_sync_enabled=true 时，
// 将本地已激活的槽位推送至所有 HA 备节点；若任一备节点失败，触发 GEOIP_NODE_DRIFT 告警并返回错误摘要。
func (s *GeoSyncer) PushInstalledSlotIfEnabled(ctx context.Context, slot, revision string) ([]HANodeSyncResult, error) {
	if s == nil || s.manager == nil {
		return nil, nil
	}
	pusher := s.HAPusher()
	if pusher == nil {
		return nil, nil
	}
	haEnabled := true
	if s.settings != nil {
		haEnabled = s.settings.GetBool(ctx, GeoIPSettingsGroup, KeyGeoIPHASyncEnabled, true)
	}
	if !haEnabled {
		return nil, nil
	}

	filePath, sha, _, err := s.manager.ActiveSlotFilePath(slot)
	if err != nil {
		driftErr := fmt.Errorf("读取待推送槽位 %s 文件失败: %w", slot, err)
		s.notifyAlert(ctx, AlertTypeGeoIPNodeDrift, "geoip:"+slot,
			fmt.Sprintf("HA 备节点 GeoIP 同步失败（%s）", slot), driftErr.Error())
		return nil, driftErr
	}
	if strings.TrimSpace(revision) == "" {
		revision = newRevisionID(s.now())
	}

	results, pushErr := pusher.PushGeoIPSlot(ctx, slot, filePath, sha, revision)
	failedDesc := summarizeHAFailures(results, pushErr)
	if failedDesc != "" {
		driftErr := errors.New(failedDesc)
		s.notifyAlert(ctx, AlertTypeGeoIPNodeDrift, "geoip:"+slot,
			fmt.Sprintf("HA 备节点 GeoIP 版本漂移（%s）", slot),
			fmt.Sprintf("槽位 %s（revision=%s）主节点已生效，但备节点同步异常：%s", slot, revision, failedDesc))
		return results, driftErr
	}
	return results, nil
}

// SyncAllEnabled 同步所有已启用且非纯离线（OFFLINE_ONLY）的槽位。
// 单槽位失败记录流水并告警，但绝不中断其余槽位更新。
func (s *GeoSyncer) SyncAllEnabled(ctx context.Context, triggerType string, operatorID *uuid.UUID) ([]SyncRun, error) {
	if s == nil || s.store == nil {
		return nil, errors.New("GeoIP 同步服务未初始化")
	}
	if triggerType == "" {
		triggerType = TriggerManual
	}
	cfgs, err := s.store.ListSlotConfigs(ctx)
	if err != nil {
		return nil, err
	}
	runs := []SyncRun{}
	for _, cfg := range cfgs {
		if !cfg.Enabled || cfg.SourceMode == SourceModeOfflineOnly {
			continue
		}
		run, syncErr := s.SyncSlot(ctx, cfg.Slot, triggerType, operatorID)
		if run != nil {
			runs = append(runs, *run)
		} else if syncErr != nil {
			slog.Warn("geoip batch sync skipped slot due to config error",
				"slot", cfg.Slot, "error", syncErr)
		}
	}
	return runs, nil
}

// HAResync 将主节点运行期目录中当前生效的一个或全部槽位重新推送至 HA 备节点。
func (s *GeoSyncer) HAResync(ctx context.Context, slot string, operatorID *uuid.UUID) ([]SyncRun, error) {
	if s == nil || s.manager == nil {
		return nil, errors.New("GeoIP 同步服务未初始化")
	}
	pusher := s.HAPusher()
	if pusher == nil {
		return nil, ErrHAPusherUnavailable
	}

	slot = strings.TrimSpace(slot)
	var targetSlots []string
	if slot != "" {
		if _, ok := ValidSlot(slot); !ok {
			return nil, fmt.Errorf("%w: %q", ErrInvalidSlot, slot)
		}
		if _, _, _, err := s.manager.ActiveSlotFilePath(slot); err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("%w: %s", ErrSlotRuntimeMissing, slot)
			}
			return nil, err
		}
		targetSlots = []string{slot}
	} else {
		for _, candidate := range SlotOrder {
			if _, _, _, err := s.manager.ActiveSlotFilePath(candidate); err == nil {
				targetSlots = append(targetSlots, candidate)
			}
		}
	}

	_, rev, _ := s.manager.InspectSlots()
	revision := ""
	if rev != nil {
		revision = rev.Revision
	}
	if revision == "" {
		revision = newRevisionID(s.now())
	}

	runs := make([]SyncRun, 0, len(targetSlots))
	for _, target := range targetSlots {
		startedAt := s.now()
		filePath, sha, size, err := s.manager.ActiveSlotFilePath(target)
		if err != nil {
			continue
		}
		haResults, pushErr := pusher.PushGeoIPSlot(ctx, target, filePath, sha, revision)
		if haResults == nil {
			haResults = []HANodeSyncResult{}
		}
		finishedAt := s.now()

		failedDesc := summarizeHAFailures(haResults, pushErr)
		status := RunStatusSuccess
		if failedDesc != "" {
			if hasAnyHASuccess(haResults) {
				status = RunStatusPartialHAFailed
			} else {
				status = RunStatusFailed
			}
			s.notifyAlert(ctx, AlertTypeGeoIPNodeDrift, "geoip:"+target,
				fmt.Sprintf("HA 备节点 GeoIP 重同步失败（%s）", target),
				fmt.Sprintf("槽位 %s 手动 HA 重同步失败：%s", target, failedDesc))
		}

		run := SyncRun{
			ID:             uuid.New(),
			Slot:           target,
			TriggerType:    TriggerHAResync,
			Status:         status,
			SourceLabel:    "ha_resync",
			PreviousSHA256: sha,
			NewSHA256:      sha,
			FileSizeBytes:  size,
			HAResults:      haResults,
			ErrorMessage:   failedDesc,
			OperatorID:     operatorID,
			StartedAt:      startedAt,
			FinishedAt:     finishedAt,
		}
		if s.store != nil {
			if err := s.store.InsertSyncRun(ctx, &run); err != nil {
				slog.Warn("record geoip ha resync run failed", "slot", target, "error", err)
			}
		}
		runs = append(runs, run)
	}
	return runs, nil
}

// Run 启动后台 1 分钟定时调度循环（读取 geoip.auto_update_enabled 与 geoip.schedule_cron），ctx 取消即退出。
func (s *GeoSyncer) Run(ctx context.Context) {
	if s == nil {
		return
	}
	interval := s.tickEvery
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _, _ = s.Tick(ctx, s.now())
		}
	}
}

// Tick 执行单次分钟级调度判定（便于单测确定性验证 Cron 触发、开关门控与同分钟去重）。
func (s *GeoSyncer) Tick(ctx context.Context, now time.Time) ([]SyncRun, bool, error) {
	if s == nil || s.settings == nil || s.store == nil {
		return nil, false, nil
	}
	if !s.settings.GetBool(ctx, GeoIPSettingsGroup, KeyGeoIPAutoUpdateEnabled, false) {
		return nil, false, nil
	}
	cronExpr := strings.TrimSpace(s.settings.GetString(ctx, GeoIPSettingsGroup, KeyGeoIPScheduleCron, DefaultGeoIPScheduleCron))
	if cronExpr == "" {
		cronExpr = DefaultGeoIPScheduleCron
	}
	spec, err := ParseCron(cronExpr)
	if err != nil {
		slog.Warn("invalid geoip schedule_cron, skipping tick", "cron", cronExpr, "error", err)
		return nil, false, err
	}
	tUTC := now.UTC().Truncate(time.Minute)
	if !spec.Match(tUTC) {
		return nil, false, nil
	}
	minuteKey := tUTC.Unix()
	s.mu.Lock()
	if s.lastSchedMin == minuteKey {
		s.mu.Unlock()
		return nil, false, nil
	}
	s.lastSchedMin = minuteKey
	s.mu.Unlock()

	runs, err := s.SyncAllEnabled(ctx, TriggerScheduled, nil)
	return runs, true, err
}

type syncCandidate struct {
	url   string
	label string
}

func (s *GeoSyncer) resolveSyncTargets(ctx context.Context, cfg *SlotConfig) ([]syncCandidate, string, string, string, error) {
	if cfg.SourceMode == SourceModeCustomURL {
		rawURL := strings.TrimSpace(cfg.CustomURL)
		if rawURL == "" {
			return nil, "", "", "", fmt.Errorf("%w: CUSTOM_URL 模式下 custom_url 不能为空", ErrInvalidSlotConfig)
		}
		label := "custom:" + sanitizeURLForLabel(rawURL)
		return []syncCandidate{{url: rawURL, label: label}}, "", "", label, nil
	}

	preset, ok := LookupPreset(cfg.OfficialPreset)
	if !ok || preset.Slot != cfg.Slot {
		return nil, "", "", "", fmt.Errorf("%w: 槽位 %s 的官方预置源 %q 无效", ErrInvalidSlotConfig, cfg.Slot, cfg.OfficialPreset)
	}

	var basicUser, basicPass string
	if preset.RequiresMaxMindAuth {
		if s.settings == nil || s.cipher == nil {
			return nil, "", "", "", ErrMaxMindNotConfigured
		}
		accountID := strings.TrimSpace(s.settings.GetString(ctx, GeoIPSettingsGroup, KeyMaxMindAccountID, ""))
		encKey := strings.TrimSpace(s.settings.GetString(ctx, GeoIPSettingsGroup, KeyMaxMindLicenseKeyEnc, ""))
		if accountID == "" || encKey == "" {
			return nil, "", "", "", ErrMaxMindNotConfigured
		}
		plainKey, err := s.cipher.Decrypt(encKey)
		if err != nil || strings.TrimSpace(plainKey) == "" {
			return nil, "", "", "", fmt.Errorf("%w: 解密 MaxMind License Key 失败", ErrMaxMindNotConfigured)
		}
		basicUser = accountID
		basicPass = strings.TrimSpace(plainKey)
	}

	baseLabel := "official:" + preset.ID
	if !preset.MonthlyFallback {
		return []syncCandidate{{url: preset.URLTemplate, label: baseLabel}}, basicUser, basicPass, baseLabel, nil
	}

	nowUTC := s.now().UTC()
	curMonth := nowUTC.Format("2006-01")
	prevMonth := time.Date(nowUTC.Year(), nowUTC.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -1, 0).Format("2006-01")

	cands := []syncCandidate{
		{
			url:   strings.ReplaceAll(preset.URLTemplate, "{YYYY-MM}", curMonth),
			label: fmt.Sprintf("%s (%s)", baseLabel, curMonth),
		},
		{
			url:   strings.ReplaceAll(preset.URLTemplate, "{YYYY-MM}", prevMonth),
			label: fmt.Sprintf("%s (%s)", baseLabel, prevMonth),
		},
	}
	return cands, basicUser, basicPass, cands[0].label, nil
}

func (s *GeoSyncer) persistRunAndSlot(ctx context.Context, run *SyncRun, slotUpd SlotActivationUpdate) {
	if s.store == nil {
		return
	}
	if err := s.store.InsertSyncRun(ctx, run); err != nil {
		slog.Warn("record geoip sync run failed", "slot", run.Slot, "error", err)
	}
	if err := s.store.UpdateSlotStatus(ctx, slotUpd); err != nil {
		slog.Warn("update geoip slot status failed", "slot", slotUpd.Slot, "error", err)
	}
}

func summarizeHAFailures(results []HANodeSyncResult, pushErr error) string {
	var parts []string
	if pushErr != nil {
		parts = append(parts, pushErr.Error())
	}
	for _, r := range results {
		if strings.EqualFold(r.Status, "FAILED") {
			name := r.NodeName
			if name == "" {
				name = r.NodeID
			}
			if r.Error != "" {
				parts = append(parts, fmt.Sprintf("%s: %s", name, r.Error))
			} else {
				parts = append(parts, fmt.Sprintf("%s: 同步失败", name))
			}
		}
	}
	return strings.Join(parts, "; ")
}

func hasAnyHASuccess(results []HANodeSyncResult) bool {
	for _, r := range results {
		if strings.EqualFold(r.Status, "SUCCESS") {
			return true
		}
	}
	return false
}

func sanitizeURLForLabel(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil {
		return truncateGeoError(raw, 128)
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return truncateGeoError(u.String(), 200)
}

func scrubSecret(msg, secret string) string {
	if secret == "" || !strings.Contains(msg, secret) {
		return msg
	}
	return strings.ReplaceAll(msg, secret, "********")
}
