// aggregator.go 攻击活动会话聚合器（WDSP AI 自动化渗透防护增强 阶段4；设计 #16 / #31.3 异步）。
// 60s 一轮从四类事件源增量拉取已归属事件，按「30 分钟不活跃间隔滑动窗」聚成 Attack Session：
//
//   - 新事件落在同身份 OPEN 会话 last_event_at+30min 内 → 并入；否则关闭旧会话并新建；
//   - 每轮收口 last_event_at < now()-30min 的 OPEN → CLOSED；
//   - 会话字段增量维护：event_count/request_count 累加（request_count 按 request_id 去重）、
//     risk_score=成员事件分求和截断 [0,100]、risk_level 20/40/70 档（与 client_identity 同口径）、
//     attack_stage=成员事件阶段最高值（stage.go 秩表）；
//   - WDSP 双落去重：Coraza SQLi 同落 security_events 与 api_runtime_events（waf 明细），
//     同会话内 request_id 已挂则后者整体跳过（事件级去重，不重复计 event_count）；
//   - 幂等：attack_session_event UNIQUE(source_table, source_id) + ON CONFLICT DO NOTHING，
//     水位线派生自该表（失败不前移、重放幂等），与采集器同一断点纪律；
//   - fail-open 降级：单源查询失败记日志跳过该源（容忍某源长期无数据），不阻断其他源；
//   - 未归属事件（三套指纹域不可 join 的降级链穷尽：主锚 identity_id / identity_key 精确 join /
//     request_id 关联 / IP 反查唯一归属）本期跳过并计数——identity_id NULL 的会话不做。
//
// 结构对齐 learningjobs：SweepOnce 可独立测试 + Run(ticker) 周期调度。
package attacksessions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
)

// 调度与窗口常量。
const (
	// DefaultInterval 聚合周期（设计 #31.3：Attack Session 汇总异步处理）。
	DefaultInterval = 60 * time.Second
	// InactivityWindow 30 分钟不活跃间隔（滑动语义，非固定对齐窗；设计 #16.3）。
	InactivityWindow = 30 * time.Minute
	// lookback 首跑/长空闲回看上限（恒为查询提供 occurred_at 常量下界保分区裁剪）。
	lookback = 24 * time.Hour
	// watermarkOverlap 水位线回看重叠窗：同 occurred_at 批次迟到行靠重叠重扫兜住，
	// 重复行由 UNIQUE(source_table, source_id) 幂等吸收。
	watermarkOverlap = 2 * time.Second
	// fetchLimit 单源单轮拉取上限（深 backlog 多轮消化）。
	fetchLimit = 5000
)

// Repository 聚合器持久化接口（*Store 实现；单测用内存假实现）。
type Repository interface {
	Watermark(ctx context.Context, source string) (time.Time, bool, error)
	FetchBehaviorEvents(ctx context.Context, since time.Time, limit int) ([]Event, error)
	FetchAccessControlEvents(ctx context.Context, since time.Time, limit int) ([]Event, error)
	FetchSecurityEvents(ctx context.Context, since time.Time, limit int) ([]Event, error)
	FetchAPIRuntimeEvents(ctx context.Context, since time.Time, limit int) ([]Event, error)
	FindOpenSession(ctx context.Context, identityID uuid.UUID) (*Session, error)
	// CreateSession 返回（会话， 是否本轮新插入， 错误）；键冲突回读既有行时
	// created=false，调用方须检查返回行 Status（可能是 CLOSED 的桶碰撞旧会话）。
	CreateSession(ctx context.Context, sess *Session) (*Session, bool, error)
	CloseOtherOpenSessions(ctx context.Context, identityID, excludeID uuid.UUID) error
	// AlreadyLinked 事件判重（建会话前调用，重放不进入合并/新建流程）。
	AlreadyLinked(ctx context.Context, sourceTable, sourceID string) (uuid.UUID, bool, error)
	LinkEvent(ctx context.Context, sessionID uuid.UUID, ev Event) (bool, error)
	HasRequest(ctx context.Context, sessionID uuid.UUID, requestID string) (bool, error)
	// HasRequestFrom 仅统计 source_table 属于 sources 的命中（WDSP 双落去重口径）。
	HasRequestFrom(ctx context.Context, sessionID uuid.UUID, requestID string, sources ...string) (bool, error)
	UpdateSession(ctx context.Context, sess *Session) error
	CloseStaleSessions(ctx context.Context, before time.Time) (int64, error)
}

// 编译期断言：*Store 实现 Repository。
var _ Repository = (*Store)(nil)

// Stats 一轮聚合结果。
type Stats struct {
	Fetched             int   // 四源合计拉取事件数
	Linked              int   // 新挂会话的事件数
	Deduped             int   // WDSP 双落 request_id 去重跳过数
	Replayed            int   // 幂等重放跳过数（事件已挂，不重复累计）
	SkippedUnattributed int   // 未归属跳过数（identity 解析失败，本期不做 NULL 会话）
	SessionsCreated     int   // 新建会话数
	SessionsClosed      int64 // 收口 CLOSED 会话数
	BizEventsEmitted    int   // Business 滥用检测产出的行为事件数
	SourceErrors        int   // 单源失败数（fail-open：跳过该源不阻断本轮）
}

// Aggregator 攻击活动会话聚合器。
type Aggregator struct {
	repo     Repository
	biz      *BusinessDetector // nil 时跳过 Business 滥用检测
	interval time.Duration
	now      func() time.Time
}

// NewAggregator 创建聚合器。
func NewAggregator(repo Repository) *Aggregator {
	return &Aggregator{repo: repo, interval: DefaultInterval, now: time.Now}
}

// SetBusinessDetector 注入 Business 滥用检测器（装配时使用；未注入时跳过）。
func (a *Aggregator) SetBusinessDetector(b *BusinessDetector) { a.biz = b }

// SetInterval 覆盖聚合周期（测试用；非正值保持默认）。
func (a *Aggregator) SetInterval(d time.Duration) *Aggregator {
	if d > 0 {
		a.interval = d
	}
	return a
}

// Run 周期调度（直到 ctx 取消）。
func (a *Aggregator) Run(ctx context.Context) {
	t := time.NewTicker(a.interval)
	defer t.Stop()
	slog.Info("attack session aggregator started", "interval", a.interval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("attack session aggregator stopped")
			return
		case <-t.C:
			stats, err := a.SweepOnce(ctx)
			if err != nil {
				slog.Error("attack session sweep failed", "error", err)
				continue
			}
			if stats.Linked > 0 || stats.SessionsCreated > 0 || stats.SessionsClosed > 0 ||
				stats.BizEventsEmitted > 0 || stats.SourceErrors > 0 {
				slog.Info("attack session swept",
					"fetched", stats.Fetched, "linked", stats.Linked, "deduped", stats.Deduped,
					"replayed", stats.Replayed, "unattributed", stats.SkippedUnattributed,
					"created", stats.SessionsCreated, "closed", stats.SessionsClosed,
					"biz_emitted", stats.BizEventsEmitted, "source_errors", stats.SourceErrors)
			}
		}
	}
}

// 事件源拉取函数表（fail-open 逐源降级）。
type sourceFetcher struct {
	name  string
	fetch func(ctx context.Context, since time.Time, limit int) ([]Event, error)
}

// SweepOnce 执行一轮聚合（可由调度与测试直接调用）。
func (a *Aggregator) SweepOnce(ctx context.Context) (Stats, error) {
	var stats Stats
	now := a.now().UTC()

	fetchers := []sourceFetcher{
		{SourceBehaviorEvents, a.repo.FetchBehaviorEvents},
		{SourceAccessControlEvents, a.repo.FetchAccessControlEvents},
		{SourceSecurityEvents, a.repo.FetchSecurityEvents},
		{SourceAPIRuntimeEvents, a.repo.FetchAPIRuntimeEvents},
	}
	var all []Event
	for _, f := range fetchers {
		since, err := a.sourceSince(ctx, f.name, now)
		if err != nil {
			stats.SourceErrors++
			slog.Error("attack session watermark failed", "source", f.name, "error", err)
			continue
		}
		events, err := f.fetch(ctx, since, fetchLimit)
		if err != nil {
			// fail-open：单源失败跳过该源（容忍长期无数据/分区缺失），水位线不前移
			stats.SourceErrors++
			slog.Error("attack session fetch failed", "source", f.name, "error", err)
			continue
		}
		stats.Fetched += len(events)
		all = append(all, events...)
	}
	// 全局时间序处理（滑动窗判定依赖事件按时间到达；同刻保持稳定源序）
	sort.SliceStable(all, func(i, j int) bool { return all[i].OccurredAt.Before(all[j].OccurredAt) })

	openByIdentity := map[uuid.UUID]*Session{}
	for i := range all {
		ev := all[i]
		if ev.IdentityID == nil || *ev.IdentityID == uuid.Nil {
			// 未归属事件本期跳过（三套指纹域不可 join；NAT 歧义标存疑不强挂）
			stats.SkippedUnattributed++
			continue
		}
		if err := a.aggregateOne(ctx, openByIdentity, ev, &stats); err != nil {
			// 单事件失败不阻断本轮其余事件（下轮重放由幂等键兜底）
			slog.Error("attack session aggregate event failed",
				"source", ev.SourceTable, "source_id", ev.SourceID, "error", err)
		}
	}

	closed, err := a.repo.CloseStaleSessions(ctx, now.Add(-InactivityWindow))
	if err != nil {
		return stats, err
	}
	stats.SessionsClosed = closed

	// Business 滥用检测（默认 OBSERVE，不接处置；产出行为事件天然汇入下轮聚合）
	if a.biz != nil {
		n, err := a.biz.DetectOnce(ctx, now)
		if err != nil {
			slog.Error("business abuse detect failed", "error", err)
		}
		stats.BizEventsEmitted = n
	}
	return stats, nil
}

// sourceSince 计算源拉取下界：水位线-重叠窗；无水位线回看 lookback；
// 下界恒不早于 now-lookback（常量谓词保分区裁剪）。
func (a *Aggregator) sourceSince(ctx context.Context, source string, now time.Time) (time.Time, error) {
	floor := now.Add(-lookback)
	wm, ok, err := a.repo.Watermark(ctx, source)
	if err != nil {
		return time.Time{}, err
	}
	if !ok {
		return floor, nil
	}
	since := wm.Add(-watermarkOverlap)
	if since.Before(floor) {
		since = floor
	}
	return since, nil
}

// aggregateOne 单事件归属：先判重（重放不建会话）→ 滑动窗并入/新建 → 双落去重 →
// 幂等挂载 → 会话字段回写。不变式：会话成员事件数 == event_count（去重/重放均不挂不计）。
func (a *Aggregator) aggregateOne(ctx context.Context, open map[uuid.UUID]*Session, ev Event, stats *Stats) error {
	// 幂等判重优先于会话创建：重放事件（水位线重叠窗/崩溃重扫）直接跳过，
	// 不进入合并/新建流程——否则重放会产生零事件空会话。
	if _, linked, err := a.repo.AlreadyLinked(ctx, ev.SourceTable, ev.SourceID); err != nil {
		return err
	} else if linked {
		stats.Replayed++
		return nil
	}

	identityID := *ev.IdentityID
	sess, cached := open[identityID]
	if !cached {
		var err error
		sess, err = a.repo.FindOpenSession(ctx, identityID)
		if err != nil {
			return err
		}
	}
	if sess == nil || ev.OccurredAt.After(sess.EndTime.Add(InactivityWindow)) {
		// 新建会话：先关闭该身份其余 OPEN（维持至多一个 OPEN 不变式），稳定键幂等
		if err := a.repo.CloseOtherOpenSessions(ctx, identityID, uuid.Nil); err != nil {
			return err
		}
		created, inserted, err := a.createSession(ctx, identityID, ev, SessionKeyOf(identityID, ev.OccurredAt))
		if err != nil {
			return err
		}
		if !inserted && created.Status != "OPEN" {
			// 桶键撞上已 CLOSED 的旧会话（迟到事件落在旧会话同 30min 桶内）：
			// 不复活 CLOSED 会话，改用精确到首事件时刻的盐键新建（重放同键幂等；
			// 已被 AlreadyLinked 拦截的重放到不了这里）。
			created, inserted, err = a.createSession(ctx, identityID, ev,
				SessionKeyPreciseOf(identityID, ev.OccurredAt))
			if err != nil {
				return err
			}
		}
		if inserted {
			stats.SessionsCreated++
		}
		sess = created
	}
	open[identityID] = sess

	// WDSP 双落去重：security_events / api_runtime_events 同 request_id 只计一次。
	// 去重行不挂载（保「成员事件数 == event_count」不变式）：该源水位线暂不越过此行，
	// 后续轮次重叠窗会重复判定去重（开销有界，随新事件挂载自愈），注释说明。
	reqSeen := false
	if ev.RequestID != "" {
		seen, err := a.repo.HasRequest(ctx, sess.ID, ev.RequestID)
		if err != nil {
			return err
		}
		reqSeen = seen
		if ev.SourceTable == SourceSecurityEvents || ev.SourceTable == SourceAPIRuntimeEvents {
			// 仅对内判重：同请求的行为信号（RECON 等）与安全/WAF 明细语义不同，都计入。
			dup, derr := a.repo.HasRequestFrom(ctx, sess.ID, ev.RequestID, SourceSecurityEvents, SourceAPIRuntimeEvents)
			if derr != nil {
				return derr
			}
			if dup {
				stats.Deduped++
				return nil
			}
		}
	}

	linked, err := a.repo.LinkEvent(ctx, sess.ID, ev)
	if err != nil {
		return err
	}
	if !linked {
		// AlreadyLinked 后的并发兜底（单工人正常路径到不了；不静默，按重放计）
		stats.Replayed++
		return nil
	}

	// 会话字段增量维护（内存状态累加后绝对值回写；聚合器单工人无并发竞争）
	if ev.OccurredAt.Before(sess.StartTime) {
		sess.StartTime = ev.OccurredAt
	}
	if ev.OccurredAt.After(sess.EndTime) {
		sess.EndTime = ev.OccurredAt
	}
	sess.EventCount++
	if ev.RequestID == "" || !reqSeen {
		sess.RequestCount++
	}
	sess.RiskScore = clampRiskScore(sess.RiskScore + ev.Score)
	sess.RiskLevel = RiskLevelForScore(sess.RiskScore)
	sess.AttackStage = MaxStage(sess.AttackStage, ev.Stage)
	// 疑似自动化攻击标注（automation.go：有效阶段≥3 且命中指示信号；单调 false→true，
	// 命中后冻结 basis 于判定时刻——证据已足够，继续追加浪费每事件一次回写）
	if !sess.AutomationSuspected {
		st := parseAutomationBasis(sess.AutomationBasis)
		st.observe(ev.Stage, ev.Signal)
		suspected, basis := st.eval()
		sess.AutomationSuspected = suspected
		sess.AutomationBasis = basis
	}
	if err := a.repo.UpdateSession(ctx, sess); err != nil {
		return err
	}
	stats.Linked++
	return nil
}

// createSession 以给定键创建会话（返回行可能是键冲突回读的既有行）。
func (a *Aggregator) createSession(ctx context.Context, identityID uuid.UUID, ev Event, key string) (*Session, bool, error) {
	fresh := &Session{
		SessionKey:  key,
		IdentityID:  &identityID,
		IdentityKey: ev.IdentityKey,
		StartTime:   ev.OccurredAt,
		EndTime:     ev.OccurredAt,
	}
	return a.repo.CreateSession(ctx, fresh)
}

// SessionKeyOf 稳定会话键：sha256(identity_id | 首事件 30min 桶起点) hex。
// 重放/崩溃重建同键冲突回读既有行（CreateSession ON CONFLICT DO NOTHING），保证幂等。
func SessionKeyOf(identityID uuid.UUID, firstEventAt time.Time) string {
	bucket := firstEventAt.UTC().Truncate(InactivityWindow)
	sum := sha256.Sum256([]byte(identityID.String() + "|" + bucket.Format(time.RFC3339)))
	return hex.EncodeToString(sum[:])
}

// SessionKeyPreciseOf 精确盐键：sha256(identity_id | 30min 桶起点 | 首事件精确时刻)。
// 仅用于桶键撞上 CLOSED 旧会话的迟到事件（见 aggregateOne 碰撞回退注释）。
func SessionKeyPreciseOf(identityID uuid.UUID, firstEventAt time.Time) string {
	at := firstEventAt.UTC()
	sum := sha256.Sum256([]byte(identityID.String() + "|" +
		at.Truncate(InactivityWindow).Format(time.RFC3339) + "|" + at.Format(time.RFC3339Nano)))
	return hex.EncodeToString(sum[:])
}

// clampRiskScore 风险分截断 [0,100]（与 client_identity 口径一致）。
func clampRiskScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

// RiskLevelForScore 风险等级 20/40/70 档（与 identityevents.RiskLevelForScore 同口径，
// 本地实现避免聚合器依赖采集包）。
func RiskLevelForScore(score int) string {
	switch {
	case score >= 70:
		return "CRITICAL"
	case score >= 40:
		return "HIGH"
	case score >= 20:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
