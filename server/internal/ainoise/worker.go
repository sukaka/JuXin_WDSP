// worker.go 降噪后台工人：周期扫描事件窗口聚类（结构照搬 guardjanitor：
// Run(ctx) ticker + SweepOnce(ctx) 可由调度与测试直接调用）。
// 设置读 system_settings（组 ai_noise）；enabled=false 时 worker 空转。
package ainoise

import (
	"context"
	"log/slog"
	"strconv"
	"time"
)

// SettingsReader 系统设置读取契约（*settings.Service 满足）。
// 降噪设置统一按字符串存取（UpsertString 写入，读取方自行解析）。
type SettingsReader interface {
	GetString(ctx context.Context, group, key, def string) string
}

// SettingsGroup 降噪设置组。
const SettingsGroup = "ai_noise"

// 设置默认值与取值范围。
const (
	DefaultIntervalSeconds    = 300
	DefaultSweepWindowMinutes = 15
	DefaultMinEventsThreshold = 10
	MinIntervalSeconds        = 30
	MaxIntervalSeconds        = 86400
	MinSweepWindowMinutes     = 1
	MaxSweepWindowMinutes     = 1440
	MinEventsThresholdFloor   = 1
	MinEventsThresholdCeil    = 100000
	defaultLLMVerdictBatch    = 20 // 单次扫描最多评分簇数（成本兜底）
	defaultRecommendBatch     = 20
)

// SweepStatus 扫描运行状态。
const (
	SweepSuccess = "SUCCESS"
	SweepFailed  = "FAILED"
	SweepPartial = "PARTIAL"
)

// Config 降噪运行配置（每次 tick 重新读取，支持热更新）。
type Config struct {
	Enabled            bool
	Interval           time.Duration
	Window             time.Duration
	MinEventsThreshold int
	LLMVerdictEnabled  bool
}

// DefaultConfig 默认配置。
func DefaultConfig() Config {
	return Config{
		Enabled:            false,
		Interval:           DefaultIntervalSeconds * time.Second,
		Window:             DefaultSweepWindowMinutes * time.Minute,
		MinEventsThreshold: DefaultMinEventsThreshold,
		LLMVerdictEnabled:  false,
	}
}

// LoadConfig 从系统设置读取配置（非法值回退默认，不静默沿用旧值）。
func LoadConfig(ctx context.Context, s SettingsReader) Config {
	cfg := DefaultConfig()
	if s == nil {
		return cfg
	}
	cfg.Enabled = parseBoolSetting(s.GetString(ctx, SettingsGroup, "enabled", ""), cfg.Enabled)
	cfg.Interval = time.Duration(parseIntSetting(s.GetString(ctx, SettingsGroup, "interval_seconds", ""),
		DefaultIntervalSeconds, MinIntervalSeconds, MaxIntervalSeconds)) * time.Second
	cfg.Window = time.Duration(parseIntSetting(s.GetString(ctx, SettingsGroup, "sweep_window_minutes", ""),
		DefaultSweepWindowMinutes, MinSweepWindowMinutes, MaxSweepWindowMinutes)) * time.Minute
	cfg.MinEventsThreshold = parseIntSetting(s.GetString(ctx, SettingsGroup, "min_events_threshold", ""),
		DefaultMinEventsThreshold, MinEventsThresholdFloor, MinEventsThresholdCeil)
	cfg.LLMVerdictEnabled = parseBoolSetting(s.GetString(ctx, SettingsGroup, "llm_verdict_enabled", ""), cfg.LLMVerdictEnabled)
	return cfg
}

func parseBoolSetting(v string, def bool) bool {
	switch v {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return def
	}
}

func parseIntSetting(v string, def, min, max int) int {
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return def
	}
	return n
}

// SweepStats 一次扫描统计（同步落 ai_noise_sweep_runs 并返回给手动触发方）。
type SweepStats struct {
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
	ScannedEvents   int       `json:"scanned_events"`
	NewClusters     int       `json:"new_clusters"`
	UpdatedClusters int       `json:"updated_clusters"`
	LLMCalls        int       `json:"llm_calls"`
	TokensUsed      int       `json:"tokens_used"`
	Recommendations int       `json:"recommendations"`
	Status          string    `json:"status"` // SUCCESS / FAILED / PARTIAL
	Error           string    `json:"error,omitempty"`
}

// Worker 降噪后台工人。
type Worker struct {
	store       Store
	source      EventSource
	settings    SettingsReader
	evaluator   *VerdictEvaluator
	recommender *Recommender
}

// NewWorker 创建降噪工人（任一依赖为 nil 时对应环节降级跳过，不致命）。
func NewWorker(store Store, source EventSource, settings SettingsReader, gw LLMGateway, rec RecommendationRecorder) *Worker {
	return &Worker{
		store:       store,
		source:      source,
		settings:    settings,
		evaluator:   NewVerdictEvaluator(gw),
		recommender: NewRecommender(rec),
	}
}

// Run 周期调度（直到 ctx 取消；每次 tick 重读设置，enabled=false 时空转，interval 变更即时生效）。
func (w *Worker) Run(ctx context.Context) {
	cfg := LoadConfig(ctx, w.settings)
	t := time.NewTicker(cfg.Interval)
	defer t.Stop()
	slog.Info("ai noise worker started", "interval", cfg.Interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cfg = LoadConfig(ctx, w.settings)
			t.Reset(cfg.Interval)
			if !cfg.Enabled {
				continue
			}
			stats := w.SweepOnce(ctx)
			if stats.Status == SweepFailed {
				slog.Error("ai noise sweep failed", "error", stats.Error)
				continue
			}
			if stats.ScannedEvents > 0 {
				slog.Info("ai noise sweep done", "scanned", stats.ScannedEvents,
					"new_clusters", stats.NewClusters, "updated_clusters", stats.UpdatedClusters,
					"llm_calls", stats.LLMCalls, "status", stats.Status)
			}
		}
	}
}

// SweepOnce 执行一次降噪扫描（手动触发与定时调度共用；手动触发不受 enabled 限制）。
// 错误不中断已完成的聚类结果：单源失败记 PARTIAL，全部失败记 FAILED。
func (w *Worker) SweepOnce(ctx context.Context) SweepStats {
	stats := SweepStats{StartedAt: time.Now().UTC(), Status: SweepSuccess}
	finish := func() SweepStats {
		now := time.Now().UTC()
		stats.FinishedAt = now
		if w.store != nil {
			run := &SweepRun{
				StartedAt: stats.StartedAt, FinishedAt: &now,
				ScannedEvents: stats.ScannedEvents, NewClusters: stats.NewClusters,
				UpdatedClusters: stats.UpdatedClusters, LLMCalls: stats.LLMCalls,
				TokensUsed: stats.TokensUsed, Status: stats.Status, Error: stats.Error,
			}
			if err := w.store.RecordSweepRun(ctx, run); err != nil {
				slog.Error("record ai noise sweep run failed", "error", err)
			}
		}
		return stats
	}
	if w.store == nil || w.source == nil {
		stats.Status = SweepFailed
		stats.Error = "noise worker not fully initialized"
		return finish()
	}
	cfg := LoadConfig(ctx, w.settings)
	end := stats.StartedAt
	start := end.Add(-cfg.Window)

	// 1) 拉取事件（WAF 恒读；API 源非 WDSP 时返回空）
	wafEvents, wafErr := w.source.FetchWAF(ctx, start, end, sweepFetchLimit)
	apiEvents, apiErr := w.source.FetchAPI(ctx, start, end, sweepFetchLimit)
	if wafErr != nil && apiErr != nil {
		stats.Status = SweepFailed
		stats.Error = "fetch events failed: " + wafErr.Error() + "; " + apiErr.Error()
		return finish()
	}
	if wafErr != nil || apiErr != nil {
		stats.Status = SweepPartial
		if wafErr != nil {
			stats.Error = "fetch waf events failed: " + wafErr.Error()
		} else {
			stats.Error = "fetch api events failed: " + apiErr.Error()
		}
		slog.Warn("ai noise sweep partial", "error", stats.Error)
	}

	// 2) 指纹聚类（单事件失败记日志并记 PARTIAL，不中断本批）
	events := make([]EventInput, 0, len(wafEvents)+len(apiEvents))
	events = append(events, wafEvents...)
	events = append(events, apiEvents...)
	for _, ev := range events {
		created, _, err := w.store.UpsertEvent(ctx, ev)
		if err != nil {
			stats.Status = SweepPartial
			stats.Error = "upsert event failed: " + err.Error()
			slog.Warn("ai noise upsert event failed", "event_id", ev.EventID, "source", ev.Source, "error", err)
			continue
		}
		stats.ScannedEvents++
		if created {
			stats.NewClusters++
		} else {
			stats.UpdatedClusters++
		}
	}

	// 3) 可选 LLM 误报评分（超阈值且未判定簇；失败降级 UNKNOWN，不致命）
	if cfg.LLMVerdictEnabled {
		stats.LLMCalls, stats.TokensUsed = w.scoreClusters(ctx, cfg.MinEventsThreshold, &stats)
	}

	// 4) 疑似误报簇生成 DRAFT 降噪推荐（人工审核；同簇去重）
	stats.Recommendations = w.recommend(ctx, cfg.MinEventsThreshold, &stats)

	return finish()
}

// scoreClusters 对待判定簇逐个 LLM 评分并写回。
func (w *Worker) scoreClusters(ctx context.Context, minEvents int, stats *SweepStats) (calls, tokens int) {
	candidates, err := w.store.VerdictCandidates(ctx, minEvents, defaultLLMVerdictBatch)
	if err != nil {
		stats.Status = SweepPartial
		stats.Error = "list verdict candidates failed: " + err.Error()
		slog.Warn("ai noise list verdict candidates failed", "error", err)
		return 0, 0
	}
	for _, c := range candidates {
		ev, err := w.store.Evidence(ctx, c.ID)
		if err != nil {
			slog.Warn("ai noise load evidence failed", "cluster_id", c.ID, "error", err)
			continue
		}
		result, used := w.evaluator.Evaluate(ctx, ev)
		calls++
		tokens += used
		var conf *float64
		if result.Verdict != VerdictUnknown {
			v := result.Confidence
			conf = &v
		}
		if err := w.store.UpdateVerdict(ctx, c.ID, result.Verdict, conf, result.Reason); err != nil {
			stats.Status = SweepPartial
			stats.Error = "update verdict failed: " + err.Error()
			slog.Warn("ai noise update verdict failed", "cluster_id", c.ID, "error", err)
		}
	}
	return calls, tokens
}

// recommend 为疑似误报簇生成 DRAFT 推荐。
func (w *Worker) recommend(ctx context.Context, minEvents int, stats *SweepStats) int {
	candidates, err := w.store.FalsePositiveCandidates(ctx, minEvents, defaultRecommendBatch)
	if err != nil {
		stats.Status = SweepPartial
		stats.Error = "list recommendation candidates failed: " + err.Error()
		slog.Warn("ai noise list recommendation candidates failed", "error", err)
		return 0
	}
	n := 0
	for i := range candidates {
		ok, err := w.recommender.MaybeRecommend(ctx, w.store, &candidates[i])
		if err != nil {
			stats.Status = SweepPartial
			stats.Error = "record recommendation failed: " + err.Error()
			slog.Warn("ai noise recommend failed", "cluster_id", candidates[i].ID, "error", err)
			continue
		}
		if ok {
			n++
		}
	}
	return n
}
