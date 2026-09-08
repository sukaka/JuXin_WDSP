// Package backpressure 背压自动降级链（Phase 4 契约 §3.1）与确定性采样（契约 §4）。
//
//   - 水位：内存队列深度比例（flow+http 合计占硬上限 10000）与限速桶饱和
//     （连续 N 秒无法足额发送，由上层折算为 0/1 指标），取两者最大值；
//   - 阶梯：L3 → L2 → L1 → L0 → SAMPLE（采样 rate=0.1，同流一致）；保底档
//     （仅心跳）由既有自我保护（CPU/内存停抓）直接接管，不经本状态机；
//   - 防抖/迟滞：高水位 70% 触发每水位档只降一级且每 10s 最多降一级（90% 不
//     额外加速——契约要求每 10s 最多降一级）；水位 <50% 持续 30s 逐级回升，
//     每 30s 最多升一级；
//   - 帽语义：生效等级 = min(策略/规则等级, 降级帽)；SAMPLE 档等价 L0 帽 +
//     强制 0.1 采样（临时覆盖策略采样，恢复后还原）。帽变化不修改策略；
//   - 时钟可注入（测试）；Check 由单 goroutine 周期驱动，Cap/Events 可并发读。
package backpressure

import (
	"crypto/sha256"
	"encoding/binary"
	"sync/atomic"
	"time"
)

// 阶梯与水位参数（契约 §3.1）。
const (
	HighWater         = 0.70             // 高水位（90% 危急同样只降一级，防抖优先）
	RecoverWater      = 0.50             // 恢复水位（须持续 RecoverHold）
	RecoverHold       = 30 * time.Second // 恢复需低水位持续时长
	DowngradeInterval = 10 * time.Second // 两次降级最小间隔
	UpgradeInterval   = 30 * time.Second // 两次回升最小间隔
	SampleRate        = 0.1              // SAMPLE 档强制采样率
)

// CapSample SAMPLE 档帽标识（metrics backpressure_cap 上报值）。
const CapSample = "SAMPLE"

// ladder 降级阶梯（idx 0=无降级 … idx 4=SAMPLE）。
var ladder = []string{"L3", "L2", "L1", "L0", CapSample}

// Monitor 降级帽状态机。Check 必须由同一 goroutine 串行调用；
// 帽与事件计数经 atomic 对外只读（热路径无锁）。
type Monitor struct {
	now func() time.Time

	idx    atomic.Int32  // ladder 下标
	events atomic.Uint64 // 累计降级次数（只增，恢复不清零）

	// 以下字段仅 Check  goroutine 访问。
	lastDown   time.Time
	lastUp     time.Time
	belowSince time.Time // 水位跌破 RecoverWater 的起点（回升迟滞计时）
}

// NewMonitor 创建状态机；now 为 nil 用 time.Now（测试注入假时钟）。
func NewMonitor(now func() time.Time) *Monitor {
	if now == nil {
		now = time.Now
	}
	return &Monitor{now: now}
}

// Check 喂入当前水位（0..1，取队列比例与限速饱和的最大值），推进状态机；
// 返回帽是否本次发生变化。
func (m *Monitor) Check(water float64) bool {
	now := m.now()
	changed := false
	idx := int(m.idx.Load())
	if water >= HighWater && idx < len(ladder)-1 &&
		(m.lastDown.IsZero() || now.Sub(m.lastDown) >= DowngradeInterval) {
		idx++
		m.idx.Store(int32(idx))
		m.lastDown = now
		m.events.Add(1)
		m.belowSince = time.Time{}
		changed = true
	}
	if water < RecoverWater {
		if m.belowSince.IsZero() {
			m.belowSince = now
		} else if idx > 0 && now.Sub(m.belowSince) >= RecoverHold &&
			(m.lastUp.IsZero() || now.Sub(m.lastUp) >= UpgradeInterval) {
			idx--
			m.idx.Store(int32(idx))
			m.lastUp = now
			changed = true
		}
	} else {
		m.belowSince = time.Time{}
	}
	return changed
}

// Cap 当前帽等级字符串（L3|L2|L1|L0|SAMPLE）。
func (m *Monitor) Cap() string { return ladder[m.idx.Load()] }

// CapRank 帽对应的等级序数（L3=3 … L0=0；SAMPLE 档按 L0 帽 + 强制采样处理）。
func (m *Monitor) CapRank() int {
	r := 3 - int(m.idx.Load())
	if r < 0 {
		return 0
	}
	return r
}

// IsSample 当前是否处于 SAMPLE 档（强制 rate=0.1 采样，临时覆盖策略采样）。
func (m *Monitor) IsSample() bool { return m.idx.Load() == int32(len(ladder)-1) }

// Degraded 帽 < L3（心跳应上报 status=DEGRADED 并携带 backpressure_cap）。
func (m *Monitor) Degraded() bool { return m.idx.Load() > 0 }

// Events 累计降级次数（metrics backpressure_events；只增不清零）。
func (m *Monitor) Events() uint64 { return m.events.Load() }

// SampleHit flow 级确定性采样：SHA-256(flow_id) 前 8 字节（大端）映射 [0,1)，
// 小于 rate 则采集。同一 flow_id 恒得同一结果（同流一致）；
// rate>=1 全采，rate<=0 全不采。
func SampleHit(flowID string, rate float64) bool {
	if rate >= 1 {
		return true
	}
	if rate <= 0 {
		return false
	}
	sum := sha256.Sum256([]byte(flowID))
	v := binary.BigEndian.Uint64(sum[:8])
	const two64 = 18446744073709551616.0 // 2^64
	return float64(v)/two64 < rate
}
