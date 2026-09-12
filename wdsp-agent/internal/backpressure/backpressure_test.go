// 背压降级帽状态机与确定性采样测试（Phase 4 契约 §3.1/§4）。
package backpressure

import (
	"testing"
	"time"
)

// fakeClock 可注入测试时钟。
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestMonitor() (*Monitor, *fakeClock) {
	c := &fakeClock{t: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}
	return NewMonitor(c.now), c
}

func TestInitialCapL3(t *testing.T) {
	m, _ := newTestMonitor()
	if m.Cap() != "L3" || m.CapRank() != 3 || m.Degraded() || m.IsSample() {
		t.Fatalf("初始帽应为 L3 未降级: cap=%s rank=%d", m.Cap(), m.CapRank())
	}
}

func TestStepwiseDowngradeDebounce(t *testing.T) {
	m, c := newTestMonitor()
	// 高水位立即降一级
	if !m.Check(0.75) {
		t.Fatal("首次高水位应降一级")
	}
	if m.Cap() != "L2" || m.Events() != 1 {
		t.Fatalf("应为 L2 events=1: cap=%s events=%d", m.Cap(), m.Events())
	}
	// 防抖：10s 内再次高水位不再降
	c.add(5 * time.Second)
	if m.Check(0.95) {
		t.Fatal("10s 内不应再降（90% 危急水位同样受防抖约束）")
	}
	if m.Cap() != "L2" {
		t.Fatalf("仍应 L2: %s", m.Cap())
	}
	// 满 10s 后再降一级
	c.add(5 * time.Second)
	if !m.Check(0.95) {
		t.Fatal("满 10s 应再降一级")
	}
	if m.Cap() != "L1" || m.Events() != 2 {
		t.Fatalf("应为 L1 events=2: cap=%s events=%d", m.Cap(), m.Events())
	}
	// 逐级降到 SAMPLE 封顶
	for _, want := range []string{"L0", CapSample} {
		c.add(DowngradeInterval)
		m.Check(0.8)
		if m.Cap() != want {
			t.Fatalf("期望 %s: cap=%s", want, m.Cap())
		}
	}
	if !m.IsSample() || m.CapRank() != 0 {
		t.Fatalf("SAMPLE 档: IsSample=%v rank=%d", m.IsSample(), m.CapRank())
	}
	// 已到底（SAMPLE 为末档）：继续高水位不再变化
	c.add(DowngradeInterval)
	if m.Check(0.99) {
		t.Fatal("SAMPLE 为末档不应再降")
	}
	if m.Events() != 4 {
		t.Fatalf("累计降级 4 次: %d", m.Events())
	}
}

func TestRecoveryHysteresis(t *testing.T) {
	m, c := newTestMonitor()
	m.Check(0.8) // → L2
	m.Check(0.8) // 同一 tick 内不会重复降（lastDown 已记）
	if m.Cap() != "L2" {
		t.Fatalf("前置: cap=%s", m.Cap())
	}
	// 水位 <50% 但持续不足 30s：不回升
	c.add(10 * time.Second)
	m.Check(0.4) // 建立低水位起点
	c.add(20 * time.Second)
	if m.Check(0.4) {
		t.Fatal("低水位未满 30s 不应回升")
	}
	// 满 30s：回升一级
	c.add(10 * time.Second)
	if !m.Check(0.4) {
		t.Fatal("低水位持续 30s 应回升一级")
	}
	if m.Cap() != "L3" {
		t.Fatalf("应回 L3: %s", m.Cap())
	}
}

func TestRecoveryWaterSpikeResetsHold(t *testing.T) {
	m, c := newTestMonitor()
	m.Check(0.8) // → L2
	c.add(11 * time.Second)
	m.Check(0.8) // → L1
	if m.Cap() != "L1" {
		t.Fatalf("前置: cap=%s", m.Cap())
	}
	// 低水位 20s → 中间一次 ≥50% 水位复位迟滞计时 → 重新计满 30s 才回升
	c.add(20 * time.Second)
	m.Check(0.4) // 建立低水位起点
	c.add(5 * time.Second)
	m.Check(0.6) // ≥50%：恢复计时清零（未达 70% 不触发降级）
	c.add(25 * time.Second)
	if m.Check(0.4) { // 重新建立起点
		t.Fatal("低水位重新计时未满 30s 不应回升")
	}
	c.add(31 * time.Second)
	if !m.Check(0.4) {
		t.Fatal("重新计时满 30s 应回升")
	}
	if m.Cap() != "L2" {
		t.Fatalf("应回 L2: %s", m.Cap())
	}
}

func TestUpgradeIntervalThirtySeconds(t *testing.T) {
	m, c := newTestMonitor()
	m.Check(0.8)
	c.add(11 * time.Second)
	m.Check(0.8)
	c.add(11 * time.Second)
	m.Check(0.8) // → L0（3 次降级）
	if m.Cap() != "L0" {
		t.Fatalf("前置: cap=%s", m.Cap())
	}
	// 持续低水位：每 30s 最多升一级
	c.add(31 * time.Second)
	m.Check(0.3) // 建立低水位起点
	c.add(30 * time.Second)
	if !m.Check(0.3) {
		t.Fatal("低水位满 30s 应升一级")
	}
	if m.Cap() != "L1" {
		t.Fatalf("应 L1: %s", m.Cap())
	}
	c.add(20 * time.Second)
	if m.Check(0.3) {
		t.Fatal("距上次回升不足 30s 不应再升")
	}
	c.add(10 * time.Second)
	if !m.Check(0.3) {
		t.Fatal("满 30s 应再升一级")
	}
	if m.Cap() != "L2" {
		t.Fatalf("应 L2: %s", m.Cap())
	}
	// 降级次数不因恢复清零
	if m.Events() != 3 {
		t.Fatalf("events 累计不清零: %d", m.Events())
	}
}

func TestDegradedFlagAndCapRank(t *testing.T) {
	m, c := newTestMonitor()
	m.Check(0.9)
	if !m.Degraded() || m.CapRank() != 2 {
		t.Fatalf("帽 L2 应 Degraded: %v", m.Degraded())
	}
	c.add(31 * time.Second)
	m.Check(0.1) // 建立低水位起点
	c.add(30 * time.Second)
	m.Check(0.1) // 恢复
	if m.Degraded() || m.Cap() != "L3" {
		t.Fatalf("恢复 L3 后不应 Degraded")
	}
}

func TestSampleHitDeterministic(t *testing.T) {
	id := "agent1-10.0.0.1-51234-10.0.0.2-8080-1788340800"
	first := SampleHit(id, 0.1)
	for i := 0; i < 100; i++ {
		if SampleHit(id, 0.1) != first {
			t.Fatal("同一 flow_id 采样结果必须恒定（同流一致）")
		}
	}
	// rate=1 全采（等价关闭）
	for _, id := range []string{"a", "b", "c", id} {
		if !SampleHit(id, 1.0) {
			t.Fatal("rate=1 应全采")
		}
	}
	// rate<=0 全不采
	if SampleHit(id, 0) || SampleHit(id, -1) {
		t.Fatal("rate<=0 应全不采")
	}
}

func TestSampleHitApproximateRate(t *testing.T) {
	// 粗略分布校验：1000 个不同 flow_id 在 rate=0.1 下命中数应明显偏离 0/1000
	hits := 0
	for i := 0; i < 1000; i++ {
		id := "agent1-10.0.0.1-10000-10.0.0.2-8080-" + time.Duration(i).String() + "-" + string(rune('a'+i%26))
		if SampleHit(id, 0.1) {
			hits++
		}
	}
	if hits == 0 || hits > 300 {
		t.Fatalf("rate=0.1 命中数应在粗略区间内（0,300]: %d", hits)
	}
}
