// suppressor.go 通知层风暴抑制（引擎层去重/冷却/抖动之外的四道闸）：
//  1. 每渠道令牌桶速率限制（notify_rate_limit_per_minute），超出不丢、进聚合；
//  2. 同告警指纹（alert_type+component）静默期免打扰（notify_mute_minutes）；
//  3. 聚合窗口（notify_group_window_seconds）内被限流的告警合并为一条中文摘要；
//  4. 恢复通知（RESOLVED）单独开关（notify_resolved，dispatcher 入口判定）。
package notify

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Params 是通知层抑制参数（来自 system_settings notify 组，每批热读）。
type Params struct {
	RatePerMinute  int  // 每渠道每分钟最大直接发送条数（默认 10；0 = 全部进聚合）
	MuteMinutes    int  // 同指纹静默期（默认 30；0 = 不静默）
	WindowSeconds  int  // 聚合窗口（默认 60）
	ResolvedNotify bool // 恢复通知开关（默认 false）
}

// Decision 是抑制判定结果。
type Decision int

const (
	// DecisionSend 直接发送。
	DecisionSend Decision = iota
	// DecisionMuted 同指纹静默期内，丢弃（引擎层仍在落库合并，仅不重复通知）。
	DecisionMuted
	// DecisionAggregated 超出速率限制，进入聚合摘要。
	DecisionAggregated
)

// aggregation 是单渠道待汇总事件集。
type aggregation struct {
	first       time.Time
	total       int
	counts      map[string]int // alert_type → 条数
	maxSeverity string         // 摘要渲染取最高级别
}

// Suppressor 是通知层抑制器（仅 dispatcher 单协程调用，内部仍加锁保证测试/并发安全）。
type Suppressor struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets map[uuid.UUID]*tokenBucket
	muted   map[string]time.Time // 指纹 → 静默截止
	pending map[uuid.UUID]*aggregation
}

// NewSuppressor 创建抑制器；now 可注入（测试用可控时钟），nil 用真实时间。
func NewSuppressor(now func() time.Time) *Suppressor {
	if now == nil {
		now = time.Now
	}
	return &Suppressor{
		now:     now,
		buckets: map[uuid.UUID]*tokenBucket{},
		muted:   map[string]time.Time{},
		pending: map[uuid.UUID]*aggregation{},
	}
}

// tokenBucket 是每渠道令牌桶（容量=速率，按速率线性补充）。
type tokenBucket struct {
	tokens float64
	last   time.Time
	init   bool
}

// take 尝试取一个令牌；rate 为每分钟补充/容量。
func (b *tokenBucket) take(now time.Time, rate int) bool {
	if rate <= 0 {
		return false
	}
	limit := float64(rate)
	if !b.init {
		b.tokens, b.last, b.init = limit, now, true
	}
	elapsed := now.Sub(b.last).Minutes() * float64(rate)
	b.tokens += elapsed
	if b.tokens > limit {
		b.tokens = limit
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Process 判定事件对指定渠道的处理方式；DecisionSend 时按指纹写入静默期
// （RESOLVED 恢复事件不参与同指纹静默：恢复是一次性收尾，不制造后续静默）。
func (s *Suppressor) Process(channelID uuid.UUID, ev Event, p Params) Decision {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()

	if ev.Status != StatusResolved && p.MuteMinutes > 0 {
		if until, ok := s.muted[ev.fingerprint()]; ok {
			if now.Before(until) {
				return DecisionMuted
			}
			delete(s.muted, ev.fingerprint())
		}
	}

	b := s.buckets[channelID]
	if b == nil {
		b = &tokenBucket{}
		s.buckets[channelID] = b
	}
	if !b.take(now, p.RatePerMinute) {
		agg := s.pending[channelID]
		if agg == nil {
			agg = &aggregation{first: now, counts: map[string]int{}}
			s.pending[channelID] = agg
		}
		agg.total++
		agg.counts[ev.AlertType]++
		if severityRank(ev.Severity) > severityRank(agg.maxSeverity) {
			agg.maxSeverity = ev.Severity
		}
		return DecisionAggregated
	}

	if ev.Status != StatusResolved && p.MuteMinutes > 0 {
		s.muted[ev.fingerprint()] = now.Add(time.Duration(p.MuteMinutes) * time.Minute)
	}
	return DecisionSend
}

// HasPending 判断是否有待汇总渠道（dispatcher tick 快速路径用）。
func (s *Suppressor) HasPending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending) > 0
}

// FlushDue 返回聚合窗口已到期的渠道 ID 列表。
func (s *Suppressor) FlushDue(windowSeconds int) []uuid.UUID {
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out []uuid.UUID
	for id, agg := range s.pending {
		if now.Sub(agg.first) >= time.Duration(windowSeconds)*time.Second {
			out = append(out, id)
		}
	}
	return out
}

// TakeSummary 取出并清空指定渠道的聚合，渲染为中文摘要事件
// （「过去 N 分钟共 X 条告警：网关离线×3、…」）；无聚合时 ok=false。
func (s *Suppressor) TakeSummary(channelID uuid.UUID) (Event, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	agg, ok := s.pending[channelID]
	if !ok || agg.total == 0 {
		return Event{}, false
	}
	delete(s.pending, channelID)

	minutes := int(s.now().Sub(agg.first).Minutes()) + 1
	type part struct {
		name  string
		count int
	}
	parts := make([]part, 0, len(agg.counts))
	for t, n := range agg.counts {
		parts = append(parts, part{name: AlertTypeName(t), count: n})
	}
	// 确定性输出：按条数降序，条数相同按中文名字典序
	sort.Slice(parts, func(i, j int) bool {
		if parts[i].count != parts[j].count {
			return parts[i].count > parts[j].count
		}
		return parts[i].name < parts[j].name
	})
	var sb strings.Builder
	for i, p := range parts {
		if i > 0 {
			sb.WriteString("、")
		}
		fmt.Fprintf(&sb, "%s×%d", p.name, p.count)
	}
	title := fmt.Sprintf("过去 %d 分钟共 %d 条告警", minutes, agg.total)
	return Event{
		Severity:   agg.maxSeverity,
		Component:  "NOTIFY",
		Title:      title,
		Message:    fmt.Sprintf("%s：%s（因速率限制合并发送）", title, sb.String()),
		Status:     StatusOpen,
		OccurredAt: s.now(),
		Summary:    true,
	}, true
}
