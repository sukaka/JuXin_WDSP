// Phase 4 决策链接线测试（契约 §2.4/§3.1/§4）：生效等级单点入口、
// 背压帽与规则叠加、采样档覆盖与还原、metrics/status 上报、onPacket 调制。
package agent

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/backpressure"
	"github.com/jiuzhang-waf/wdsp-agent/internal/capture"
	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/httpsensor"
	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

// bpWithClock 替换 Agent 背压状态机为假时钟版本（测试）。
func bpWithClock(a *Agent) (*backpressure.Monitor, *fakeBpClock) {
	c := &fakeBpClock{t: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}
	a.bp = backpressure.NewMonitor(c.now)
	return a.bp, c
}

type fakeBpClock struct{ t time.Time }

func (c *fakeBpClock) now() time.Time      { return c.t }
func (c *fakeBpClock) add(d time.Duration) { c.t = c.t.Add(d) }

func TestEffectiveRankChain(t *testing.T) {
	a := newTestAgent(t, "https://127.0.0.1:1")
	a.applyPolicy(a.cfg.EffectivePolicy()) // 基础 L2
	if got := a.effectiveRank(0); got != 2 {
		t.Fatalf("基础 L2: got %d", got)
	}
	// 规则提升（只升不降）：max(基础 L2, 规则 L3)
	if got := a.effectiveRank(3); got != 3 {
		t.Fatalf("规则提升应取 max: got %d", got)
	}
	// 规则低于基础不拉低
	if got := a.effectiveRank(1); got != 2 {
		t.Fatalf("规则只升不降: got %d", got)
	}
	// 背压帽压制：min(max(基础,规则), 帽)
	_, c := bpWithClock(a)
	a.bp.Check(0.8) // → 帽 L2
	if got := a.effectiveRank(3); got != 2 {
		t.Fatalf("帽 L2 应压制规则 L3: got %d", got)
	}
	c.add(11 * time.Second)
	a.bp.Check(0.9) // → 帽 L1
	if got := a.effectiveRank(3); got != 1 {
		t.Fatalf("帽 L1 应压制: got %d", got)
	}
	if got := a.effectiveRank(0); got != 1 {
		t.Fatalf("帽 L1 应压制基础 L2: got %d", got)
	}
	// /http 404 降级：基础 L0
	a.httpGone.Store(true)
	a.applyPolicy(a.cfg.EffectivePolicy())
	c.add(31 * time.Second)
	a.bp.Check(0.1)
	c.add(30 * time.Second)
	a.bp.Check(0.1) // 恢复帽 L3
	if got := a.effectiveRank(0); got != 0 {
		t.Fatalf("httpGone 后基础应 L0: got %d", got)
	}
}

func TestFlowSampledPolicyAndBackpressureOverride(t *testing.T) {
	a := newTestAgent(t, "https://127.0.0.1:1")
	a.applyPolicy(a.cfg.EffectivePolicy())
	id := "a1-10.0.0.1-5000-10.0.0.2-8080-1788340800"

	// 无策略采样：全采
	if !a.flowSampled(id) {
		t.Fatal("无采样配置应全采")
	}
	// 策略采样 rate=0.5：与 SampleHit 一致且同流恒定
	a.cfg.Policy.Sampling = config.Sampling{Enabled: true, Rate: 0.5}
	a.applyPolicy(a.cfg.EffectivePolicy())
	want := backpressure.SampleHit(id, 0.5)
	for i := 0; i < 10; i++ {
		if a.flowSampled(id) != want {
			t.Fatal("策略采样应确定性且同流一致")
		}
	}
	// 背压 SAMPLE 档：强制 0.1 覆盖策略 0.5
	_, c := bpWithClock(a)
	for i := 0; i < 4; i++ {
		a.bp.Check(0.9)
		c.add(11 * time.Second)
	}
	if !a.bp.IsSample() {
		t.Fatalf("前置应到 SAMPLE 档: %s", a.bp.Cap())
	}
	if got := a.flowSampled(id); got != backpressure.SampleHit(id, backpressure.SampleRate) {
		t.Fatal("SAMPLE 档应以 rate=0.1 临时覆盖策略采样")
	}
	// 恢复后还原策略采样（0.5）
	for a.bp.CapRank() < 3 {
		c.add(31 * time.Second)
		a.bp.Check(0.1)
	}
	if a.bp.Cap() != "L3" {
		t.Fatalf("应恢复 L3: %s", a.bp.Cap())
	}
	if a.flowSampled(id) != want {
		t.Fatal("退避结束后应还原策略采样率")
	}
	// rate=1 等价关闭
	a.cfg.Policy.Sampling = config.Sampling{Enabled: true, Rate: 1}
	a.applyPolicy(a.cfg.EffectivePolicy())
	if !a.flowSampled(id) {
		t.Fatal("rate=1 应等价关闭（全采）")
	}
	// rate 非法（>1/≤0）按关闭（管理端 400，Agent 侧防御）
	a.cfg.Policy.Sampling = config.Sampling{Enabled: true, Rate: 1.5}
	a.applyPolicy(a.cfg.EffectivePolicy())
	if !a.flowSampled(id) {
		t.Fatal("rate 非法应按关闭处理")
	}
}

func TestBackpressureStatusAndMetrics(t *testing.T) {
	a := newTestAgent(t, "https://127.0.0.1:1")
	a.applyPolicy(a.cfg.EffectivePolicy())
	if a.status() != "ONLINE" {
		t.Fatalf("初始应 ONLINE: %s", a.status())
	}
	m := a.metricsSnapshot()
	if m.BackpressureCap != "" || m.BackpressureEvents != 0 {
		t.Fatalf("未降级不应带 backpressure 字段: %+v", m)
	}
	// 帽 < L3 → DEGRADED + metrics 字段
	_, c := bpWithClock(a)
	a.bp.Check(0.8)
	if a.status() != "DEGRADED" {
		t.Fatalf("帽 < L3 应 DEGRADED: %s", a.status())
	}
	m = a.metricsSnapshot()
	if m.BackpressureCap != "L2" || m.BackpressureEvents != 1 {
		t.Fatalf("metrics 应带 backpressure_cap/events: %+v", m)
	}
	// omitempty 序列化验证：未降级时字段不出现
	data, err := json.Marshal(transport.Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["backpressure_cap"]; ok {
		t.Fatal("backpressure_cap 应 omitempty")
	}
	if _, ok := raw["backpressure_events"]; ok {
		t.Fatal("backpressure_events 应 omitempty")
	}
	// 恢复 L3 → ONLINE，events 累计保留上报
	c.add(31 * time.Second)
	a.bp.Check(0.1)
	c.add(30 * time.Second)
	a.bp.Check(0.1)
	if a.status() != "ONLINE" {
		t.Fatalf("恢复 L3 应回 ONLINE: %s", a.status())
	}
	m = a.metricsSnapshot()
	if m.BackpressureCap != "" || m.BackpressureEvents != 1 {
		t.Fatalf("恢复后 cap 应省略、events 保留: %+v", m)
	}
}

func TestBackpressureWaterQueueRatio(t *testing.T) {
	a := newTestAgent(t, "https://127.0.0.1:1")
	a.flowQ = make(chan events.FlowEvent, flowQueueCap)
	a.httpQ = make(chan httpQItem, httpQueueCap)
	// 注入 75% 队列深度（flow+http 合计占 10000）
	for i := 0; i < 7500; i++ {
		a.flowQ <- events.FlowEvent{}
	}
	if w := a.backpressureWater(); w < 0.7 {
		t.Fatalf("队列比例应 ≥0.7: %f", w)
	}
	// 驱动状态机降一级
	a.checkBackpressure()
	if a.bp.Cap() != "L2" {
		t.Fatalf("高水位应降一级: %s", a.bp.Cap())
	}
}

func TestOnPacketModulationEndToEnd(t *testing.T) {
	a := newTestAgent(t, "https://127.0.0.1:1")
	// 接上真实记录出口（newTestAgent 默认 onRecord=nil）
	a.sensor = httpsensor.New("a1", a.filt.HasPort, a.onHTTPRecord, a.log)
	// 基础 L0 + host 定向规则 L2
	a.cfg.Policy.CaptureLevel = config.LevelL0
	a.cfg.Overrides = []config.Override{{
		ID:           "r1",
		Match:        config.OverrideMatch{Host: "api.example.com"},
		CaptureLevel: config.LevelL2,
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}}
	a.applyPolicy(a.cfg.EffectivePolicy())
	a.flowQ = make(chan events.FlowEvent, 16)
	a.httpQ = make(chan httpQItem, 16)
	a.rawQ = make(chan events.PacketFrame, 16)

	base := time.Now()
	cseq := uint32(1000)
	sseq := uint32(7000)
	send := func(srcIP, dstIP string, srcPort, dstPort uint16, ingress bool, seq *uint32, payload []byte, syn bool) {
		p := capture.Packet{
			Ts: base, SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort,
			Ingress: ingress, Seq: *seq, SYN: syn, ACK: !syn, PSH: len(payload) > 0,
			Payload: payload, OrigLen: len(payload) + 54,
		}
		a.onPacket(p)
		*seq += uint32(len(payload))
		if syn {
			*seq++
		}
	}
	send("10.0.0.1", "10.0.0.2", 51234, 8080, true, &cseq, nil, true)
	send("10.0.0.2", "10.0.0.1", 8080, 51234, false, &sseq, nil, true)
	send("10.0.0.1", "10.0.0.2", 51234, 8080, true, &cseq,
		[]byte("POST /api/payment HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}"), false)
	send("10.0.0.2", "10.0.0.1", 8080, 51234, false, &sseq,
		[]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"), false)

	// L0 流被规则提升后应从当前请求起产出 HTTP 记录
	select {
	case item := <-a.httpQ:
		r := item.rec
		if r.Request.Method != "POST" || r.Request.Body != `{"a":1}` {
			t.Fatalf("提升后应按 L2 采集: %+v", r.Request)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("规则提升后应产出 HTTP 记录")
	}
	// 生效 L2：不应有旧 request 事件；RAW 不应入队（L2<L3 且 output=FLOW）
	select {
	case ev := <-a.flowQ:
		if ev.EventType == events.TypeRequest {
			t.Fatalf("生效 L2 不应发 request 事件: %+v", ev)
		}
	default:
	}
	select {
	case f := <-a.rawQ:
		t.Fatalf("L2 不应入队 RAW: %d bytes", len(f.Data))
	default:
	}
}
