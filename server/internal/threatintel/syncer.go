// syncer.go 威胁情报在线拉取、条件请求短路、空集/骤降护栏、连续失败熔断与后台定时调度器。
// 仅内建 CC0 许可官方源（abuse.ch Feodo / SSLBL），严守 AGENTS.md 宽松许可证底线，
// 明确排除 GPL-2.0 FireHOL；零编译依赖 iplibhttp，通过窄接口 FeedDownloader 与 URLValidator 注入。
package threatintel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// 系统告警类型常量（与 server/internal/systemalerts/rules.go 保持一致）。
const (
	AlertTypeSyncFailed  = "THREAT_INTEL_SYNC_FAILED"
	AlertTypeCircuitOpen = "THREAT_INTEL_CIRCUIT_OPEN"
)

// OfficialPreset 是系统内置 CC0 官方威胁情报订阅源定义。
type OfficialPreset struct {
	Key            string `json:"key"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	URL            string `json:"url"`
	Format         string `json:"format"`
	License        string `json:"license"`
	DefaultTTLDays int    `json:"default_ttl_days"`
	DefaultCron    string `json:"default_cron"`
	AllowCIDR      bool   `json:"allow_cidr"`
}

// builtinOfficialPresets 仅包含 CC0 许可的官方源（绝不包含 GPL/AGPL 源）。
var builtinOfficialPresets = []OfficialPreset{
	{
		Key:            "feodo",
		Name:           "abuse.ch Feodo C2 IP 清单",
		Description:    "僵尸网络控制端（C2）推荐封禁 IPv4 列表",
		URL:            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
		Format:         "text",
		License:        "CC0-1.0",
		DefaultTTLDays: DefaultTTLDays,
		DefaultCron:    DefaultScheduleCron,
		AllowCIDR:      false,
	},
	{
		Key:            "sslbl",
		Name:           "abuse.ch SSLBL 恶意 C2 IP 清单",
		Description:    "恶意 SSL 证书关联僵尸网络 C2 IPv4 列表",
		URL:            "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
		Format:         "text",
		License:        "CC0-1.0",
		DefaultTTLDays: DefaultTTLDays,
		DefaultCron:    DefaultScheduleCron,
		AllowCIDR:      false,
	},
}

// OfficialPresets 返回内置 CC0 官方威胁情报源副本列表。
func OfficialPresets() []OfficialPreset {
	out := make([]OfficialPreset, len(builtinOfficialPresets))
	copy(out, builtinOfficialPresets)
	return out
}

// LookupOfficialPreset 按 preset key 查询内置官方源。
func LookupOfficialPreset(key string) (OfficialPreset, bool) {
	k := strings.ToLower(strings.TrimSpace(key))
	for _, p := range builtinOfficialPresets {
		if p.Key == k {
			return p, true
		}
	}
	return OfficialPreset{}, false
}

// FeedFetchRequest 是在线拉取威胁情报源的请求参数（零依赖 iplibhttp）。
type FeedFetchRequest struct {
	SourceMode   string // OFFICIAL | CUSTOM_URL
	URL          string
	ETag         string
	LastModified string
	MaxBytes     int64 // 缺省 MaxOnlineContentBytes (2 MiB)
}

// FeedFetchResponse 是在线拉取威胁情报源的响应。
type FeedFetchResponse struct {
	NotModified  bool
	Body         []byte
	ETag         string
	LastModified string
	StatusCode   int
}

// FeedDownloader 是威胁情报在线下载器窄接口（app.go 装配时桥接 iplibhttp.Downloader）。
type FeedDownloader interface {
	Fetch(ctx context.Context, req FeedFetchRequest) (*FeedFetchResponse, error)
}

// URLValidator 是保存订阅源时的 URL/SSRF 校验回调（app.go 装配时桥接 iplibhttp.Downloader.ValidateTargetURL）。
type URLValidator func(ctx context.Context, sourceMode, rawURL string) error

// AlertFunc 是系统告警回调（app.go 装配时桥接 systemalerts.Engine.NotifyFailure）。
type AlertFunc func(ctx context.Context, alertType, component, title, message string)

// SettingsReader 是威胁情报调度/熔断配置只读接口（*settings.Service 满足）。
type SettingsReader interface {
	GetBool(ctx context.Context, group, key string, def bool) bool
	GetInt(ctx context.Context, group, key string, def int) int
}

// SyncOptions 控制单次订阅源同步行为。
type SyncOptions struct {
	TriggerType      string     // MANUAL | SCHEDULED（缺省 MANUAL）
	ForceIgnoreGuard bool       // true 时忽略空集与骤降保护，强制执行对账
	OperatorID       *uuid.UUID // 手动操作人
	RequestID        string     // 关联请求 ID（透传给网关发布）
	BatchPublish     bool       // true 时跳过单源直接发布，由批量调度器统一发布一次
}

// SyncFeedResult 是单次订阅源同步的完整结果（供 HTTP 接口与定时调度器消费）。
type SyncFeedResult struct {
	Run            *SyncRun `json:"run"`
	Feed           *Feed    `json:"feed"`
	GuardTriggered bool     `json:"guard_triggered"`
	GuardReason    string   `json:"guard_reason,omitempty"`
	CircuitOpened  bool     `json:"circuit_opened"`
	ChangedRules   int      `json:"changed_rules"`
}

// SweepStats 是一轮后台定时调度的执行统计。
type SweepStats struct {
	Checked       int
	Due           int
	Succeeded     int
	Skipped       int
	GuardAborted  int
	Failed        int
	TotalChanged  int
	PublishedOnce bool
}

// Syncer 负责威胁情报在线拉取、护栏校验、熔断保护与 1 分钟周期定时调度。
type Syncer struct {
	repo       FeedRepository
	reconciler Reconciler
	downloader FeedDownloader
	settings   SettingsReader
	publish    PublishFunc
	alertFn    AlertFunc
	now        func() time.Time
	interval   time.Duration

	mu       sync.Mutex
	inflight map[uuid.UUID]bool
}

// NewSyncer 创建威胁情报在线同步与调度器。
func NewSyncer(repo FeedRepository, reconciler Reconciler, downloader FeedDownloader, settings SettingsReader) *Syncer {
	return &Syncer{
		repo:       repo,
		reconciler: reconciler,
		downloader: downloader,
		settings:   settings,
		now:        time.Now,
		interval:   time.Minute,
		inflight:   map[uuid.UUID]bool{},
	}
}

// SetPublishFunc 注入网关配置发布回调。
func (s *Syncer) SetPublishFunc(fn PublishFunc) *Syncer {
	s.publish = fn
	return s
}

// SetAlertFunc 注入系统告警回调（THREAT_INTEL_SYNC_FAILED / THREAT_INTEL_CIRCUIT_OPEN）。
func (s *Syncer) SetAlertFunc(fn AlertFunc) *Syncer {
	s.alertFn = fn
	return s
}

// SetClock 注入时钟（测试用）。
func (s *Syncer) SetClock(fn func() time.Time) *Syncer {
	if fn != nil {
		s.now = fn
	}
	return s
}

// AutoUpdateEnabled 读取威胁情报全局在线定时更新开关（默认 false，纯离线零外连）。
func (s *Syncer) AutoUpdateEnabled(ctx context.Context) bool {
	if s == nil || s.settings == nil {
		return false
	}
	return s.settings.GetBool(ctx, SettingsGroup, KeyAutoUpdateEnabled, false)
}

// CircuitThreshold 读取连续失败自动熔断阈值（默认 5，夹取 [1, 20]）。
func (s *Syncer) CircuitThreshold(ctx context.Context) int {
	n := DefaultCircuitThreshold
	if s != nil && s.settings != nil {
		n = s.settings.GetInt(ctx, SettingsGroup, KeyCircuitThreshold, DefaultCircuitThreshold)
	}
	if n < MinCircuitThreshold {
		return MinCircuitThreshold
	}
	if n > MaxCircuitThreshold {
		return MaxCircuitThreshold
	}
	return n
}

// Run 启动 1 分钟周期定时调度器，直到 ctx 取消。
func (s *Syncer) Run(ctx context.Context) {
	interval := s.interval
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	slog.Info("threat intel sync scheduler started", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("threat intel sync scheduler stopped")
			return
		case <-ticker.C:
			stats, err := s.SweepOnce(ctx)
			if err != nil {
				slog.Error("threat intel scheduled sweep failed", "error", err)
				continue
			}
			if stats.Due > 0 {
				slog.Info("threat intel scheduled sweep completed",
					"due", stats.Due,
					"succeeded", stats.Succeeded,
					"skipped", stats.Skipped,
					"guard_aborted", stats.GuardAborted,
					"failed", stats.Failed,
					"changed_rules", stats.TotalChanged,
					"published", stats.PublishedOnce,
				)
			}
		}
	}
}

// SweepOnce 执行单轮定时调度检查：
// 1. 若全局 auto_update_enabled=false 则立即空转返回（纯离线环境零外连）；
// 2. 遍历全部 enabled=true、非 OFFLINE_ONLY、非 circuit_open 且命中当前分钟 cron 的订阅源；
// 3. 同一分钟内已同步过的订阅源跳过防重复；
// 4. 全部到期源处理完毕后，若累计 added+refreshed+expired > 0，仅触发一次合并网关发布。
func (s *Syncer) SweepOnce(ctx context.Context) (SweepStats, error) {
	var stats SweepStats
	if s == nil || s.repo == nil {
		return stats, nil
	}
	if !s.AutoUpdateEnabled(ctx) {
		return stats, nil
	}
	feeds, err := s.repo.ListFeeds(ctx)
	if err != nil {
		return stats, fmt.Errorf("list threat intel feeds: %w", err)
	}

	now := s.now()
	nowMin := now.Truncate(time.Minute)

	for i := range feeds {
		feed := feeds[i]
		stats.Checked++
		if !feed.Enabled || feed.SourceMode == SourceModeOfflineOnly || feed.CircuitOpen {
			continue
		}
		if feed.LastSyncAt != nil && !feed.LastSyncAt.In(now.Location()).Truncate(time.Minute).Before(nowMin) {
			continue
		}
		spec, perr := ParseCron(feed.ScheduleCron)
		if perr != nil {
			slog.Warn("threat intel feed has invalid cron expression, skipping",
				"feed_key", feed.FeedKey, "cron", feed.ScheduleCron, "error", perr)
			continue
		}
		if !spec.Match(nowMin) {
			continue
		}

		stats.Due++
		res, serr := s.SyncFeed(ctx, feed.ID, SyncOptions{
			TriggerType:  TriggerScheduled,
			BatchPublish: true,
		})
		if serr != nil {
			if errors.Is(serr, ErrSyncInProgress) || errors.Is(serr, ErrOfflineOnlyFeed) {
				stats.Skipped++
				continue
			}
			stats.Failed++
			slog.Warn("threat intel scheduled sync error", "feed_key", feed.FeedKey, "error", serr)
			continue
		}
		if res == nil || res.Run == nil {
			continue
		}
		switch res.Run.Status {
		case RunStatusSuccess:
			stats.Succeeded++
			stats.TotalChanged += res.ChangedRules
		case RunStatusSkippedNotModified:
			stats.Skipped++
		case RunStatusGuardAborted:
			stats.GuardAborted++
		default:
			stats.Failed++
		}
	}

	if stats.TotalChanged > 0 && s.publish != nil {
		s.publish(ctx, uuid.Nil, "")
		stats.PublishedOnce = true
	}
	return stats, nil
}

// SyncFeed 同步指定 ID 的订阅源（单源并发防重入）。
func (s *Syncer) SyncFeed(ctx context.Context, feedID uuid.UUID, opts SyncOptions) (*SyncFeedResult, error) {
	if s == nil || s.repo == nil {
		return nil, errors.New("threat intel syncer not initialized")
	}
	if opts.TriggerType == "" {
		opts.TriggerType = TriggerManual
	}
	if !s.acquireInflight(feedID) {
		return nil, ErrSyncInProgress
	}
	defer s.releaseInflight(feedID)

	feed, err := s.repo.GetFeed(ctx, feedID)
	if err != nil {
		return nil, err
	}
	if feed.SourceMode == SourceModeOfflineOnly {
		return nil, ErrOfflineOnlyFeed
	}

	startedAt := s.now().UTC()
	targetURL, urlErr := resolveFeedURL(feed)
	if urlErr != nil {
		return s.recordFailure(ctx, feed, opts, startedAt, RunStatusFailed, 0, 0, urlErr.Error())
	}
	if s.downloader == nil {
		return s.recordFailure(ctx, feed, opts, startedAt, RunStatusFailed, 0, 0, "在线下载器未初始化")
	}

	req := FeedFetchRequest{
		SourceMode: feed.SourceMode,
		URL:        targetURL,
		MaxBytes:   MaxOnlineContentBytes,
	}
	if !opts.ForceIgnoreGuard {
		req.ETag = feed.ETag
		req.LastModified = feed.LastModified
	}

	resp, fetchErr := s.downloader.Fetch(ctx, req)
	if fetchErr != nil {
		return s.recordFailure(ctx, feed, opts, startedAt, RunStatusFailed, 0, 0,
			fmt.Sprintf("拉取订阅源失败: %v", fetchErr))
	}
	if resp == nil {
		return s.recordFailure(ctx, feed, opts, startedAt, RunStatusFailed, 0, 0, "下载器返回空响应")
	}

	// 条件请求 304 Not Modified 短路：不写规则库、不触发网关发布；手动/在线成功恢复熔断状态
	if resp.NotModified {
		return s.recordNotModified(ctx, feed, opts, startedAt, resp.ETag, resp.LastModified)
	}

	if len(resp.Body) > MaxOnlineContentBytes {
		return s.recordFailure(ctx, feed, opts, startedAt, RunStatusFailed, 0, 0,
			fmt.Sprintf("订阅源内容超过 %d MiB 上限", MaxOnlineContentBytes/(1<<20)))
	}

	sum := sha256.Sum256(resp.Body)
	contentSHA := hex.EncodeToString(sum[:])

	// 内容 SHA-256 未变短路：不写规则库、不触发网关发布
	if !opts.ForceIgnoreGuard && feed.LastContentSHA256 != "" && contentSHA == feed.LastContentSHA256 {
		return s.recordNotModified(ctx, feed, opts, startedAt, resp.ETag, resp.LastModified)
	}

	// 解析内容
	parseOpts := ParseOptions{AllowCIDR: feed.AllowCIDR}
	var parsed *ParseResult
	var parseErr error
	if feed.Format == "csv" {
		parsed, parseErr = ParseCSVWithOptions(string(resp.Body), parseOpts)
	} else {
		parsed = ParseTextWithOptions(string(resp.Body), parseOpts)
	}
	if parseErr != nil {
		return s.recordFailure(ctx, feed, opts, startedAt, RunStatusFailed, 0, 0,
			fmt.Sprintf("解析 CSV 失败: %v", parseErr))
	}

	// 安全护栏检查（forceIgnoreGuard=true 时跳过）
	if !opts.ForceIgnoreGuard {
		// 护栏 1：空集保护（min_entries_guard）
		if feed.MinEntriesGuard && len(parsed.Entries) == 0 {
			reason := fmt.Sprintf("解析出 0 条有效 IP（无效行 %d），触发空集防误清空保护，未变更在册黑名单；确认上游无误后可手动忽略保护强制同步",
				parsed.ErrorTotal)
			return s.recordFailure(ctx, feed, opts, startedAt, RunStatusGuardAborted, 0, parsed.ErrorTotal, reason)
		}

		// 护栏 2：骤降比例保护（max_drop_ratio，当活跃规则 >= 20 且缩水比例 > max_drop_ratio 时中止）
		activeCount := feed.ActiveRuleCount
		if cnt, cerr := s.repo.CountActiveFeedRules(ctx, feed.FeedKey); cerr == nil {
			activeCount = cnt
		}
		if activeCount >= DropGuardMinActiveRules && feed.MaxDropRatio < 1.0 && len(parsed.Entries) < activeCount {
			dropRatio := float64(activeCount-len(parsed.Entries)) / float64(activeCount)
			if dropRatio > feed.MaxDropRatio {
				reason := fmt.Sprintf(
					"新批次有效条目 %d 较当前在册活跃规则 %d 骤降 %.1f%%（超过阈值 %.1f%%），已中止对账防止误清空；确认上游无误后可手动忽略保护强制同步",
					len(parsed.Entries), activeCount, dropRatio*100, feed.MaxDropRatio*100)
				return s.recordFailure(ctx, feed, opts, startedAt, RunStatusGuardAborted, len(parsed.Entries), parsed.ErrorTotal, reason)
			}
		}
	}

	if s.reconciler == nil {
		return s.recordFailure(ctx, feed, opts, startedAt, RunStatusFailed, len(parsed.Entries), parsed.ErrorTotal, "对账服务未初始化")
	}

	op := uuid.Nil
	if opts.OperatorID != nil {
		op = *opts.OperatorID
	}
	importRes, impErr := s.reconciler.Import(ctx, ImportInput{
		Feed:     feed.FeedKey,
		TTLDays:  feed.TTLDays,
		Entries:  parsed.Entries,
		Operator: op,
	})
	if impErr != nil {
		return s.recordFailure(ctx, feed, opts, startedAt, RunStatusFailed, len(parsed.Entries), parsed.ErrorTotal,
			fmt.Sprintf("集合对账写入失败: %v", impErr))
	}

	changed := importRes.Added + importRes.Refreshed + importRes.Expired
	published := false
	if changed > 0 && s.publish != nil {
		if opts.BatchPublish {
			// 批量调度由 SweepOnce 在所有到期源完成后统一发布一次
			published = true
		} else {
			s.publish(ctx, op, opts.RequestID)
			published = true
		}
	}

	finishedAt := s.now().UTC()
	activeCount, cntErr := s.repo.CountActiveFeedRules(ctx, feed.FeedKey)
	if cntErr != nil {
		activeCount = maxInt(0, feed.ActiveRuleCount+importRes.Added-importRes.Expired)
	}

	run := &SyncRun{
		FeedKey:         feed.FeedKey,
		TriggerType:     opts.TriggerType,
		BatchID:         importRes.BatchID,
		Status:          RunStatusSuccess,
		TotalParsed:     len(parsed.Entries),
		Added:           importRes.Added,
		Refreshed:       importRes.Refreshed,
		Expired:         importRes.Expired,
		SkippedConflict: importRes.SkippedConflict,
		InvalidCount:    parsed.ErrorTotal,
		Published:       published,
		OperatorID:      opts.OperatorID,
		StartedAt:       startedAt,
		FinishedAt:      finishedAt,
	}
	if err := s.repo.InsertRun(ctx, run); err != nil {
		slog.Warn("insert threat intel sync run failed", "feed_key", feed.FeedKey, "error", err)
	}

	upd := FeedSyncUpdate{
		ID:                  feed.ID,
		ETag:                resp.ETag,
		LastModified:        resp.LastModified,
		LastContentSHA256:   contentSHA,
		UpdateCacheHeaders:  true,
		ActiveRuleCount:     activeCount,
		UpdateActiveCount:   true,
		ConsecutiveFailures: 0,
		CircuitOpen:         false,
		UpdateCircuit:       true,
		LastSyncAt:          finishedAt,
		LastStatus:          RunStatusSuccess,
		LastError:           "",
		UpdatedBy:           opts.OperatorID,
	}
	if err := s.repo.UpdateFeedSyncResult(ctx, upd); err != nil {
		slog.Warn("update threat intel feed sync status failed", "feed_key", feed.FeedKey, "error", err)
	}

	updatedFeed := applySyncUpdateCopy(feed, upd)
	return &SyncFeedResult{
		Run:          run,
		Feed:         updatedFeed,
		ChangedRules: changed,
	}, nil
}

func (s *Syncer) recordNotModified(
	ctx context.Context,
	feed *Feed,
	opts SyncOptions,
	startedAt time.Time,
	respETag, respLastModified string,
) (*SyncFeedResult, error) {
	finishedAt := s.now().UTC()
	run := &SyncRun{
		FeedKey:     feed.FeedKey,
		TriggerType: opts.TriggerType,
		Status:      RunStatusSkippedNotModified,
		Published:   false,
		OperatorID:  opts.OperatorID,
		StartedAt:   startedAt,
		FinishedAt:  finishedAt,
	}
	if err := s.repo.InsertRun(ctx, run); err != nil {
		slog.Warn("insert threat intel not-modified run failed", "feed_key", feed.FeedKey, "error", err)
	}

	etag := feed.ETag
	if respETag != "" {
		etag = respETag
	}
	lastMod := feed.LastModified
	if respLastModified != "" {
		lastMod = respLastModified
	}

	upd := FeedSyncUpdate{
		ID:                  feed.ID,
		ETag:                etag,
		LastModified:        lastMod,
		LastContentSHA256:   feed.LastContentSHA256,
		UpdateCacheHeaders:  true,
		UpdateActiveCount:   false,
		ConsecutiveFailures: 0,
		CircuitOpen:         false,
		UpdateCircuit:       true,
		LastSyncAt:          finishedAt,
		LastStatus:          RunStatusSkippedNotModified,
		LastError:           "",
		UpdatedBy:           opts.OperatorID,
	}
	if err := s.repo.UpdateFeedSyncResult(ctx, upd); err != nil {
		slog.Warn("update threat intel feed not-modified status failed", "feed_key", feed.FeedKey, "error", err)
	}

	return &SyncFeedResult{
		Run:          run,
		Feed:         applySyncUpdateCopy(feed, upd),
		ChangedRules: 0,
	}, nil
}

func (s *Syncer) recordFailure(
	ctx context.Context,
	feed *Feed,
	opts SyncOptions,
	startedAt time.Time,
	status string,
	totalParsed, invalidCount int,
	errMsg string,
) (*SyncFeedResult, error) {
	finishedAt := s.now().UTC()
	threshold := s.CircuitThreshold(ctx)
	newFailures := feed.ConsecutiveFailures + 1
	wasOpen := feed.CircuitOpen
	nowOpen := wasOpen || newFailures >= threshold

	run := &SyncRun{
		FeedKey:      feed.FeedKey,
		TriggerType:  opts.TriggerType,
		Status:       status,
		TotalParsed:  totalParsed,
		InvalidCount: invalidCount,
		Published:    false,
		ErrorMessage: errMsg,
		OperatorID:   opts.OperatorID,
		StartedAt:    startedAt,
		FinishedAt:   finishedAt,
	}
	if err := s.repo.InsertRun(ctx, run); err != nil {
		slog.Warn("insert threat intel failure run failed", "feed_key", feed.FeedKey, "error", err)
	}

	upd := FeedSyncUpdate{
		ID:                  feed.ID,
		UpdateCacheHeaders:  false, // 保留上次成功的缓存头与摘要
		UpdateActiveCount:   false, // 保留现有在册规则数
		ConsecutiveFailures: newFailures,
		CircuitOpen:         nowOpen,
		UpdateCircuit:       true,
		LastSyncAt:          finishedAt,
		LastStatus:          status,
		LastError:           errMsg,
		UpdatedBy:           opts.OperatorID,
	}
	if err := s.repo.UpdateFeedSyncResult(ctx, upd); err != nil {
		slog.Warn("update threat intel feed failure status failed", "feed_key", feed.FeedKey, "error", err)
	}

	if s.alertFn != nil {
		comp := "threat_intel:" + feed.FeedKey
		title := fmt.Sprintf("威胁情报订阅源同步失败（%s）", feed.FeedKey)
		if status == RunStatusGuardAborted {
			title = fmt.Sprintf("威胁情报订阅源触发保护护栏（%s）", feed.FeedKey)
		}
		s.alertFn(ctx, AlertTypeSyncFailed, comp, title, errMsg)

		if !wasOpen && nowOpen {
			cbTitle := fmt.Sprintf("威胁情报订阅源连续失败触发熔断（%s）", feed.FeedKey)
			cbMsg := fmt.Sprintf("订阅源 %s（%s）连续失败 %d 次，达到熔断阈值 %d，已暂停自动拉取。最近错误：%s",
				feed.Name, feed.FeedKey, newFailures, threshold, errMsg)
			s.alertFn(ctx, AlertTypeCircuitOpen, comp, cbTitle, cbMsg)
		}
	}

	res := &SyncFeedResult{
		Run:            run,
		Feed:           applySyncUpdateCopy(feed, upd),
		GuardTriggered: status == RunStatusGuardAborted,
		CircuitOpened:  !wasOpen && nowOpen,
		ChangedRules:   0,
	}
	if status == RunStatusGuardAborted {
		res.GuardReason = errMsg
	}
	return res, nil
}

func resolveFeedURL(feed *Feed) (string, error) {
	switch feed.SourceMode {
	case SourceModeOfficial:
		preset, ok := LookupOfficialPreset(feed.OfficialPreset)
		if !ok {
			return "", fmt.Errorf("未知的官方预置情报源: %q", feed.OfficialPreset)
		}
		return preset.URL, nil
	case SourceModeCustomURL:
		u := strings.TrimSpace(feed.CustomURL)
		if u == "" {
			return "", errors.New("CUSTOM_URL 模式下 custom_url 不能为空")
		}
		return u, nil
	default:
		return "", fmt.Errorf("不支持在线拉取的源模式: %s", feed.SourceMode)
	}
}

func applySyncUpdateCopy(feed *Feed, u FeedSyncUpdate) *Feed {
	cp := *feed
	if u.UpdateCacheHeaders {
		cp.ETag = u.ETag
		cp.LastModified = u.LastModified
		cp.LastContentSHA256 = u.LastContentSHA256
	}
	if u.UpdateActiveCount {
		cp.ActiveRuleCount = u.ActiveRuleCount
	}
	if u.UpdateCircuit {
		cp.ConsecutiveFailures = u.ConsecutiveFailures
		cp.CircuitOpen = u.CircuitOpen
	}
	t := u.LastSyncAt
	cp.LastSyncAt = &t
	cp.LastStatus = u.LastStatus
	cp.LastError = u.LastError
	cp.UpdatedAt = t
	if u.UpdatedBy != nil {
		cp.UpdatedBy = u.UpdatedBy
	}
	return &cp
}

func (s *Syncer) acquireInflight(id uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight[id] {
		return false
	}
	s.inflight[id] = true
	return true
}

func (s *Syncer) releaseInflight(id uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inflight, id)
}
