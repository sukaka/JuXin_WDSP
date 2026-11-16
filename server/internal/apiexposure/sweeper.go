// sweeper.go 暴露面周期评估（仿 learningjobs/janitor.go：SweepOnce 可独立测试 +
// Run ticker 周期调度）：
//   - 候选：观察窗内有流量 或 从未评估 或 最近评估超 24h 的端点（单轮限量，余量下轮继续）；
//   - 评估：装配证据（来源聚合窗 + 端点归属 + 公网 DNS 视角）→ Evaluate 纯函数 →
//     写评估明细（结论未变化且 24h 内已评估时跳过明细写，防评估表膨胀）→
//     条件 upsert EXPOSURE 维度（人工/锁定不覆盖）；
//   - 收尾：留存清理（30 天前的 bucket/seen/assessment 行）。
//
// 单端点评估失败记日志并计数，不中断批次；DNS 证据按域名在本轮内缓存。
package apiexposure

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// 调度与留存常量。
const (
	// DefaultSweepInterval 默认周期（10 分钟；SetInterval 可覆盖，测试注入小时钟）。
	DefaultSweepInterval = 10 * time.Minute
	// sweepBatchLimit 单轮评估端点上限（防长事务/长轮次；余量下轮继续）。
	sweepBatchLimit = 500
	// retentionDays 聚合与评估明细留存天数（迁移 000190 表留存纪律）。
	retentionDays = 30
	// assessmentRefreshAfter 结论未变化时距上次评估超过该时长仍重写明细
	// （证据数字保鲜：来源计数随窗口漂移，每日至少落一次最新证据）。
	assessmentRefreshAfter = 24 * time.Hour
)

// Sweeper 暴露面周期评估器（无内部可变状态外的时间源；并发安全由仓储保证）。
type Sweeper struct {
	store    Repository
	settings SettingsReader
	resolver *PublicResolver // nil 时跳过 DNS 证据（CONFIG 级判定退化，不伪造）
	interval time.Duration
	now      func() time.Time
}

// NewSweeper 创建评估器（settings 为 nil 时全用默认配置）。
func NewSweeper(store Repository, settings SettingsReader) *Sweeper {
	return &Sweeper{
		store:    store,
		settings: settings,
		interval: DefaultSweepInterval,
		now:      time.Now,
	}
}

// SetResolver 注入公网 DNS 判定器（装配层用；nil 时评估不产 DNS 证据）。
func (s *Sweeper) SetResolver(r *PublicResolver) *Sweeper { s.resolver = r; return s }

// SetInterval 覆盖调度周期（<=0 保持默认；应用装配/测试用）。
func (s *Sweeper) SetInterval(d time.Duration) *Sweeper {
	if d > 0 {
		s.interval = d
	}
	return s
}

// SetClock 注入时钟（测试用；默认 time.Now）。
func (s *Sweeper) SetClock(now func() time.Time) *Sweeper {
	if now != nil {
		s.now = now
	}
	return s
}

// SweepStats 一轮评估结果。
type SweepStats struct {
	Candidates int   // 本轮候选端点数
	Assessed   int   // 评估成功数
	Failed     int   // 单端点评估失败数（失败隔离不中断批次）
	Pruned     int64 // 留存清理删除行数
}

// Run 周期调度（直到 ctx 取消）。
func (s *Sweeper) Run(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	slog.Info("api exposure sweeper started", "interval", s.interval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("api exposure sweeper stopped")
			return
		case <-t.C:
			stats, err := s.SweepOnce(ctx)
			if err != nil {
				slog.Error("api exposure sweep failed", "error", err)
				continue
			}
			if stats.Assessed > 0 || stats.Failed > 0 || stats.Pruned > 0 {
				slog.Info("api exposure swept",
					"candidates", stats.Candidates, "assessed", stats.Assessed,
					"failed", stats.Failed, "pruned", stats.Pruned)
			}
		}
	}
}

// SweepOnce 执行一轮批量评估 + 留存清理（可由调度与测试直接调用）。
func (s *Sweeper) SweepOnce(ctx context.Context) (SweepStats, error) {
	var stats SweepStats
	cfg := LoadConfig(ctx, s.settings)
	now := s.now()
	candidates, err := s.store.ListCandidates(ctx, sinceDay(now, cfg.ObservationDays),
		now.Add(-assessmentRefreshAfter), sweepBatchLimit)
	if err != nil {
		return stats, err
	}
	stats.Candidates = len(candidates)
	dnsCache := map[string]string{} // 本轮域名级缓存（同域名多端点只查一次）
	for _, id := range candidates {
		if _, _, err := s.assessOne(ctx, id, cfg, now, dnsCache, false); err != nil {
			stats.Failed++
			slog.Error("assess endpoint exposure failed", "endpoint_id", id, "error", err)
			continue
		}
		stats.Assessed++
	}
	pruned, err := s.store.Prune(ctx, retentionDays)
	if err != nil {
		return stats, fmt.Errorf("prune exposure tables: %w", err)
	}
	stats.Pruned = pruned
	return stats, nil
}

// AssessEndpoint 人工即时重评（重评接口用；每次写评估明细，返回结论与维度是否生效）。
func (s *Sweeper) AssessEndpoint(ctx context.Context, endpointID uuid.UUID) (Assessment, bool, error) {
	cfg := LoadConfig(ctx, s.settings)
	return s.assessOne(ctx, endpointID, cfg, s.now(), map[string]string{}, true)
}

// assessOne 评估单个端点：装配证据 → Evaluate → 写明细 → 条件 upsert 维度。
// alwaysWrite=false（周期清扫）时结论三元组未变化且 24h 内已评估则跳过明细写入；
// alwaysWrite=true（人工重评）恒写明细。MANUAL 结论只写明细不动维度。
func (s *Sweeper) assessOne(ctx context.Context, id uuid.UUID, cfg Config, now time.Time,
	dnsCache map[string]string, alwaysWrite bool) (Assessment, bool, error) {
	ectx, err := s.store.EndpointContext(ctx, id)
	if err != nil {
		return Assessment{}, false, err
	}
	buckets, err := s.store.WindowStats(ctx, id, sinceDay(now, cfg.ObservationDays))
	if err != nil {
		return Assessment{}, false, err
	}
	dnsResult := ""
	// 人工确认的端点不耗 DNS 查询（结论已被人工接管）；其余有域名才解析
	if s.resolver != nil && ectx.Hostname != "" && !ectx.Locked && ectx.ExistingSource != SourceManual {
		if v, ok := dnsCache[ectx.Hostname]; ok {
			dnsResult = v
		} else {
			dnsResult = s.resolver.ResolvePublicView(ctx, ectx.Hostname, cfg.PublicDNSServers)
			dnsCache[ectx.Hostname] = dnsResult
		}
	}
	a := Evaluate(EvidenceInput{
		WindowDays:     cfg.ObservationDays,
		Buckets:        buckets,
		ExistingValue:  ectx.ExistingValue,
		ExistingSource: ectx.ExistingSource,
		Locked:         ectx.Locked,
		Hostname:       ectx.Hostname,
		HTTPPort:       ectx.HTTPPort,
		HTTPSPort:      ectx.HTTPSPort,
		DeploymentMode: ectx.DeploymentMode,
		DNSResult:      dnsResult,
		MinRequests:    cfg.MinRequests,
		MinDays:        cfg.MinDays,
	})
	latest, err := s.store.LatestAssessment(ctx, id)
	if err != nil {
		return Assessment{}, false, err
	}
	if alwaysWrite || latest == nil ||
		latest.Verdict != a.Verdict || latest.Source != a.Source || latest.Confidence != a.Confidence ||
		latest.AssessedAt.Before(now.Add(-assessmentRefreshAfter)) {
		if _, err := s.store.WriteAssessment(ctx, id, a, now); err != nil {
			return Assessment{}, false, err
		}
	}
	if a.Source == SourceManual {
		return a, false, nil
	}
	applied, err := s.store.ApplyVerdict(ctx, id, a)
	if err != nil {
		return Assessment{}, false, err
	}
	return a, applied, nil
}

// sinceDay 观察窗起始自然日（UTC；含今天共 days 天）。
func sinceDay(now time.Time, days int) time.Time {
	if days <= 0 {
		days = DefaultObservationDays
	}
	return now.UTC().Truncate(24 * time.Hour).Add(-time.Duration(days-1) * 24 * time.Hour)
}
