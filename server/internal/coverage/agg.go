// Package coverage 执行覆盖聚合（NG-COV-02 server 侧）：把网关发射的
// coverage.Observation 按「应用 × 端点模板 × 检测器 × 方向 × 策略版本 × 节点 × 分钟窗」
// 聚合为五态计数，并提供 E 口径指标与明细采样。
//
// 口径（NG-BASE-02 §2.2 / RD_PLAN §5.2，唯一事实源，不得偏离）：
//   - E = FULL + PARTIAL + SKIPPED + ERROR；NOT_APPLICABLE 另计，不进 E；
//   - 完整检查率 FULL/E、有效执行率 (FULL+PARTIAL)/E 分别给出，不可混用；
//   - E=0 表示「无适用流量」，绝不显示为 100%；
//   - 维度组合超上限归 other 桶并计丢弃；非法记录丢弃计数；
//   - 用户 ID、对象 ID、原始 URL 永不进入维度标签。
package coverage

import (
	"fmt"
	"sort"
	"sync"
	"time"

	gwcov "github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
)

// DimKey 聚合维度键（分钟窗）。
type DimKey struct {
	ApplicationID string    `json:"application_id"`
	EndpointKey   string    `json:"endpoint_key"`
	Detector      string    `json:"detector"`
	Phase         string    `json:"phase"`
	PolicyVersion string    `json:"policy_version"`
	NodeID        string    `json:"node_id"`
	Minute        time.Time `json:"minute"` // UTC 截断到分
}

// Bucket 单维度计数桶。
type Bucket struct {
	Full          uint64 `json:"full"`
	Partial       uint64 `json:"partial"`
	Skipped       uint64 `json:"skipped"`
	Error         uint64 `json:"error"`
	NotApplicable uint64 `json:"not_applicable"`
}

// E 有效集合（FULL+PARTIAL+SKIPPED+ERROR）。
func (b Bucket) E() uint64 { return b.Full + b.Partial + b.Skipped + b.Error }

// Metrics 指标输出：两个比率分别给出；E=0 时 NoApplicableTraffic=true（绝不显示 100%）。
type Metrics struct {
	DimKey
	Bucket
	E                   uint64  `json:"e"`
	FullRate            float64 `json:"full_rate"`
	EffectiveRate       float64 `json:"effective_rate"`
	NoApplicableTraffic bool    `json:"no_applicable_traffic"`
}

// Aggregator 有界维度聚合器。
// maxKeys 为单窗口维度键上限（>0）；超限时新维度归拢到 otherKey 并累计 Overflow 丢弃数。
type Aggregator struct {
	maxKeys  int
	mu       sync.Mutex
	buckets  map[DimKey]*Bucket
	overflow uint64
	invalid  uint64
}

// NewAggregator 创建聚合器（maxKeys<=0 时取默认 10000）。
func NewAggregator(maxKeys int) *Aggregator {
	if maxKeys <= 0 {
		maxKeys = 10000
	}
	return &Aggregator{maxKeys: maxKeys, buckets: map[DimKey]*Bucket{}}
}

// otherKey 维度超限时的归拢键。
func otherKey(k DimKey) DimKey {
	return DimKey{
		ApplicationID: k.ApplicationID,
		EndpointKey:   "other",
		Detector:      "other",
		Phase:         k.Phase,
		PolicyVersion: k.PolicyVersion,
		NodeID:        k.NodeID,
		Minute:        k.Minute,
	}
}

// Add 记账一条观测。非法记录（契约校验失败）丢弃并计 invalid；
// 维度键数达上限时新维度归拢 other 并计 overflow。
func (a *Aggregator) Add(o gwcov.Observation) {
	if msg := o.Validate(); msg != "" {
		a.mu.Lock()
		a.invalid++
		a.mu.Unlock()
		return
	}
	k := DimKey{
		ApplicationID: o.ApplicationID,
		EndpointKey:   o.EndpointKey,
		Detector:      o.Detector,
		Phase:         string(o.Phase),
		PolicyVersion: o.PolicyVersion,
		NodeID:        o.NodeID,
		Minute:        o.OccurredAt.UTC().Truncate(time.Minute),
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	b, ok := a.buckets[k]
	if !ok {
		if len(a.buckets) >= a.maxKeys {
			k = otherKey(k)
			a.overflow++
			b, ok = a.buckets[k]
			if !ok {
				b = &Bucket{}
				a.buckets[k] = b
			}
		} else {
			b = &Bucket{}
			a.buckets[k] = b
		}
	}
	switch o.Status {
	case gwcov.StatusFull:
		b.Full++
	case gwcov.StatusPartial:
		b.Partial++
	case gwcov.StatusSkipped:
		b.Skipped++
	case gwcov.StatusError:
		b.Error++
	case gwcov.StatusNotApplicable:
		b.NotApplicable++
	}
}

// Overflow 维度超限归拢丢弃计数。
func (a *Aggregator) Overflow() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.overflow
}

// Invalid 非法记录丢弃计数。
func (a *Aggregator) Invalid() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.invalid
}

// Metrics 输出指定维度键的指标；键不存在时返回零值 + NoApplicableTraffic。
func (a *Aggregator) Metrics(k DimKey) Metrics {
	a.mu.Lock()
	defer a.mu.Unlock()
	m := Metrics{DimKey: k}
	b, ok := a.buckets[k]
	if !ok {
		m.NoApplicableTraffic = true
		return m
	}
	m.Bucket = *b
	m.E = b.E()
	if m.E == 0 {
		m.NoApplicableTraffic = true
		return m
	}
	m.FullRate = float64(b.Full) / float64(m.E)
	m.EffectiveRate = float64(b.Full+b.Partial) / float64(m.E)
	return m
}

// Snapshot 当前全部维度键（按字典序稳定排序，供测试与导出）。
func (a *Aggregator) Snapshot() []DimKey {
	a.mu.Lock()
	defer a.mu.Unlock()
	keys := make([]DimKey, 0, len(a.buckets))
	for k := range a.buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return fmt.Sprintf("%v", keys[i]) < fmt.Sprintf("%v", keys[j])
	})
	return keys
}

// Drain 取出当前全部维度桶并清零（采集器 flush 用：返回自上次 Drain 以来的
// 增量计数；overflow/invalid 累计计数不清零）。返回 map 不保证顺序。
func (a *Aggregator) Drain() map[DimKey]Bucket {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[DimKey]Bucket, len(a.buckets))
	for k, b := range a.buckets {
		out[k] = *b
	}
	a.buckets = map[DimKey]*Bucket{}
	return out
}

// Sampler 明细采样器：每 N 条保留 1 条（N<=1 全保留），如实记录采样率与丢弃量。
type Sampler struct {
	n       uint64
	seen    uint64
	kept    uint64
	dropped uint64
}

// NewSampler 创建 1/N 采样器。
func NewSampler(n uint64) *Sampler {
	if n == 0 {
		n = 1
	}
	return &Sampler{n: n}
}

// Keep 判定本条是否保留（确定性计数采样，非随机）。
func (s *Sampler) Keep() bool {
	s.seen++
	if s.n <= 1 || s.seen%s.n == 0 {
		s.kept++
		return true
	}
	s.dropped++
	return false
}

// Rate 当前采样率（kept/seen）。
func (s *Sampler) Rate() float64 {
	if s.seen == 0 {
		return 0
	}
	return float64(s.kept) / float64(s.seen)
}

// Stats 采样对账：总见数/保留/丢弃。
func (s *Sampler) Stats() (seen, kept, dropped uint64) { return s.seen, s.kept, s.dropped }
