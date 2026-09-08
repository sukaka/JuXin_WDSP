// Phase 4 智能采集（契约 §2.4/§3.1/§4）：定向规则提升、背压降级帽与策略采样
// 的统一决策链。生效等级单点入口（effectiveRank）：
//
//	基础等级（策略 capture_level，/http 404 降级为 L0）
//	  → 定向规则 max 提升（只升不降；flow 包内完成首包/请求行两阶段求值）
//	  → 背压降级帽 min 压制（帽变化不修改策略、不产生 config ACK 失败）
//	  → 采样过滤（建流时判定，同流一致；采样外仅发 flow_end 计数）
package agent

import (
	"math"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/backpressure"
	"github.com/jiuzhang-waf/wdsp-agent/internal/override"
)

// bucketSaturationSec 限速桶饱和判定：连续无法足额发送达到该时长视为饱和
// （契约 §3.1「连续 N 秒」取 N=5，约为 5 个外发冲刷周期）。
const bucketSaturationSec = 5 * time.Second

// initPhase4 组装采集调制（New 与测试共用入口；幂等）。
func (a *Agent) initPhase4() {
	if a.bp == nil {
		a.bp = backpressure.NewMonitor(nil)
	}
	if a.overrides == nil {
		a.overrides = override.NewSet(a.log)
	}
	a.tracker.SetEvaluator(a.overrides)
	a.tracker.SetLevelFunc(a.effectiveRank)
	a.tracker.SetSampler(a.flowSampled)
}

// effectiveRank 生效等级序数（单点入口）：max(基础等级, 规则等级) 后按
// 降级帽 min 压制。规则只升不降（flow 包保证 ruleLevel 单调）。
func (a *Agent) effectiveRank(ruleLevel int) int {
	r := int(a.baseLevel.Load())
	if ruleLevel > r {
		r = ruleLevel
	}
	if capRank := a.bp.CapRank(); capRank < r {
		r = capRank
	}
	return r
}

// flowSampled 建流时采样成员判定（同流一致）：
// 背压 SAMPLE 档强制 rate=0.1（临时覆盖策略采样，恢复后还原——契约 §4）；
// 否则按策略采样（enabled 且 rate∈(0,1) 时生效；rate=1 等价关闭）。
func (a *Agent) flowSampled(flowID string) bool {
	if a.bp.IsSample() {
		return backpressure.SampleHit(flowID, backpressure.SampleRate)
	}
	if r := math.Float64frombits(uint64(a.policySampleRate.Load())); r > 0 {
		return backpressure.SampleHit(flowID, r)
	}
	return true
}

// backpressureWater 背压水位（0..1）：内存队列深度（flow+http 事件合计占
// 硬上限 10000 的比例）与限速桶饱和（连续 bucketSaturationSec 无法足额
// 发送 → 1.0）取最大值（契约 §3.1）。
func (a *Agent) backpressureWater() float64 {
	water := float64(len(a.flowQ)+len(a.httpQ)) / float64(flowQueueCap)
	if a.bucket.DenialStreak() >= bucketSaturationSec {
		water = 1.0
	}
	return water
}

// checkBackpressure 周期驱动背压状态机（housekeep 流表扫描同周期调用）。
// 帽变化只影响后续采集决策，不修改策略、不产生 config ACK 失败。
func (a *Agent) checkBackpressure() {
	water := a.backpressureWater()
	if a.bp.Check(water) {
		a.log.Warn("背压降级帽变化",
			"cap", a.bp.Cap(), "water", math.Round(water*100)/100, "events", a.bp.Events())
	}
}
