// sweeper.go 节点版本校验周期清扫：聚合事件表 → upsert 节点视图 → 状态重算 →
// 版本一致性判定 → 不一致告警（结构对齐 apiops.Sweeper：SweepOnce 可独立单测 +
// ticker Run 周期驱动）。
package apinodes

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/systemalerts"
)

// DefaultSweepInterval 默认清扫间隔（节点状态窗口为 5min/1h，1 分钟粒度足够）。
const DefaultSweepInterval = time.Minute

// AlertComponent 版本不一致告警组件名。告警类型复用 CONFIG_HASH_MISMATCH
// （systemalerts 规则矩阵为固定词表，本包不改既有文件；「多节点策略版本不一致」
// 与「配置哈希不一致」语义同属配置漂移，默认等级 MEDIUM）。
const AlertComponent = "API_GATEWAY_NODES"

// Alerter 版本不一致告警出口（*systemalerts.Engine 天然实现，装配时直接注入；
// nil 时不一致事实仅 slog.Warn 记录——不静默吞错，也不因告警未接线阻断聚合）。
type Alerter interface {
	NotifyFailure(ctx context.Context, alertType, component, title, message string) (*systemalerts.Alert, error)
	AutoRecover(ctx context.Context, component string, alertTypes ...string) (int, error)
}

// Stats 一轮清扫结果。
type Stats struct {
	Nodes         int  // 本轮聚合 upsert 的节点数
	StatusChanges int  // 本轮状态发生变化的节点数
	Consistent    bool // 本轮一致性判定结果（口径见 EvaluateConsistency）
	Inconsistent  bool // 本轮检测到不一致（告警已触发/记录）
}

// Sweeper 节点版本校验清扫器。
type Sweeper struct {
	store    Repository
	alerter  Alerter          // nil 时不一致仅记录日志
	now      func() time.Time // 测试注入固定时钟
	interval time.Duration    // 0 时取 DefaultSweepInterval
}

// NewSweeper 创建清扫器。
func NewSweeper(store Repository) *Sweeper {
	return &Sweeper{store: store, now: func() time.Time { return time.Now().UTC() }}
}

// SetAlerter 设置告警出口（应用装配时注入 *systemalerts.Engine；可为 nil）。
func (s *Sweeper) SetAlerter(a Alerter) *Sweeper { s.alerter = a; return s }

// SetClock 注入时钟（测试使用）。
func (s *Sweeper) SetClock(now func() time.Time) *Sweeper { s.now = now; return s }

// SetInterval 设置清扫间隔（应用装配时使用；非正数取默认）。
func (s *Sweeper) SetInterval(d time.Duration) *Sweeper { s.interval = d; return s }

// SweepOnce 执行一轮校验（可由调度与测试直接调用）：
// 聚合 → 取现存视图（心跳活性参与合并）→ upsert（状态随写入刷新）→ 全量状态
// 重算（覆盖非聚合来源行，如纯心跳节点）→ 一致性判定 → 不一致告警/恢复。
// 任一步失败如实返回错误（不静默吞错）。
func (s *Sweeper) SweepOnce(ctx context.Context) (Stats, error) {
	var stats Stats
	now := s.now()
	aggs, err := s.store.AggregateEvents(ctx)
	if err != nil {
		return stats, fmt.Errorf("aggregate runtime events: %w", err)
	}
	// 现存视图先取：心跳（W17-HB）可能已把节点活性推进到事件表聚合值之后，
	// upsert 写入的状态须按「聚合活性与现存活性取新」判定——否则每分钟都会先把
	// 纯心跳节点写回旧状态、再由下方重算纠正（行振荡，StatusChanges 每轮虚增）。
	before, err := s.store.ListNodes(ctx)
	if err != nil {
		return stats, fmt.Errorf("list nodes: %w", err)
	}
	known := make(map[string]time.Time, len(before))
	for i := range before {
		known[before[i].NodeName] = before[i].LastSeenAt
	}
	for i := range aggs {
		effective := aggs[i].LastSeenAt
		if prev, ok := known[aggs[i].NodeName]; ok && prev.After(aggs[i].LastSeenAt) {
			effective = prev
		}
		if err := s.store.UpsertNode(ctx, aggs[i], StatusFor(now, effective), now); err != nil {
			return stats, fmt.Errorf("upsert node %q: %w", aggs[i].NodeName, err)
		}
	}
	stats.Nodes = len(aggs)

	// upsert 后重取（含新插入行与合并后活性），全量状态重算
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return stats, fmt.Errorf("list nodes: %w", err)
	}
	for i := range nodes {
		want := StatusFor(now, nodes[i].LastSeenAt)
		if nodes[i].Status == want {
			continue
		}
		if err := s.store.UpdateNodeStatus(ctx, nodes[i].NodeName, want, now); err != nil {
			return stats, fmt.Errorf("update node %q status: %w", nodes[i].NodeName, err)
		}
		nodes[i].Status = want
		stats.StatusChanges++
	}

	report := EvaluateConsistency(nodes, now)
	stats.Consistent = report.Consistent
	if report.Consistent {
		// 恢复一致：自动解决未关闭的不一致告警（RECOVERED；无未关闭时为空转）
		if s.alerter != nil {
			if _, err := s.alerter.AutoRecover(ctx, AlertComponent, systemalerts.TypeConfigHashMismatch); err != nil {
				return stats, fmt.Errorf("recover consistency alert: %w", err)
			}
		}
		return stats, nil
	}
	stats.Inconsistent = true
	msg := inconsistencyMessage(report)
	if s.alerter == nil {
		slog.Warn("api gateway node policy version inconsistent (alerter not wired, recorded only)",
			"component", AlertComponent, "message", msg)
		return stats, nil
	}
	if _, err := s.alerter.NotifyFailure(ctx, systemalerts.TypeConfigHashMismatch, AlertComponent,
		"多节点策略版本不一致", msg); err != nil {
		return stats, fmt.Errorf("raise consistency alert: %w", err)
	}
	return stats, nil
}

// inconsistencyMessage 组组装不一致告警内容（版本:节点清单；长度由告警存储截断兜底）。
func inconsistencyMessage(report ConsistencyReport) string {
	parts := make([]string, 0, len(report.Groups))
	for _, g := range report.Groups {
		version := g.PolicyVersion
		if version == "" {
			version = "未上报"
		}
		parts = append(parts, fmt.Sprintf("%s:[%s]", version, strings.Join(g.Nodes, ",")))
	}
	return fmt.Sprintf("活跃网关节点策略版本不一致（%d 个节点参与判定）：%s",
		report.EvaluatedNodes, strings.Join(parts, "; "))
}

// Run 周期清扫（直到 ctx 取消；单轮失败记日志不退出，下一轮继续）。
func (s *Sweeper) Run(ctx context.Context) {
	interval := s.interval
	if interval <= 0 {
		interval = DefaultSweepInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	slog.Info("api gateway nodes sweeper started", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("api gateway nodes sweeper stopped")
			return
		case <-t.C:
			stats, err := s.SweepOnce(ctx)
			if err != nil {
				slog.Error("api gateway nodes sweep failed", "error", err)
				continue
			}
			if stats.Nodes > 0 {
				slog.Debug("api gateway nodes swept",
					"nodes", stats.Nodes, "status_changes", stats.StatusChanges,
					"consistent", stats.Consistent)
			}
		}
	}
}
