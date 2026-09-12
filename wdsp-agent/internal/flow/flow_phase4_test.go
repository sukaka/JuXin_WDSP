// Phase 4 采集调制测试（契约 §2.4/§4）：定向规则两阶段求值提升、
// 生效等级驱动 request 事件抑制、采样外仅 flow_end 计数。
package flow

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/override"
)

var p4Base = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

func p4Tracker(ovs []config.Override) (*Tracker, *[]events.FlowEvent) {
	evs := &[]events.FlowEvent{}
	tr := NewTracker("a1", 0, 0, func(ev events.FlowEvent) { *evs = append(*evs, ev) }, nil)
	if ovs != nil {
		set := override.NewSet(slog.New(slog.NewTextHandler(io.Discard, nil)))
		set.Replace(ovs)
		tr.SetEvaluator(set)
	}
	return tr, evs
}

func p4Ov(match config.OverrideMatch, level string) config.Override {
	return config.Override{
		ID: "r", Match: match, CaptureLevel: level,
		ExpiresAt: p4Base.Add(time.Hour).Format(time.RFC3339),
	}
}

func TestFlowStageEvalBoostsAtFirstPacket(t *testing.T) {
	tr, _ := p4Tracker([]config.Override{
		p4Ov(config.OverrideMatch{DstPort: 8080}, config.LevelL2),
	})
	// 首包即按 dst_port 规则提升（levelFn 缺省=ruleLevel 原样）
	st := tr.Track(Packet{Ts: p4Base, SrcIP: "10.0.0.1", SrcPort: 5000,
		DstIP: "10.0.0.2", DstPort: 8080, Ingress: true})
	if st.Level != 2 {
		t.Fatalf("首包 dst_port 规则应提升到 L2，got %d", st.Level)
	}
	if !st.Sampled || !st.SensorWanted {
		t.Fatalf("期望 sampled=true sensorWanted=true（L2），got %+v", st)
	}
	// 不命中端口：无提升
	st2 := tr.Track(Packet{Ts: p4Base, SrcIP: "10.0.0.1", SrcPort: 5001,
		DstIP: "10.0.0.2", DstPort: 9090, Ingress: true})
	if st2.Level != 0 {
		t.Fatalf("不命中规则应保持 L0，got %d", st2.Level)
	}
}

func TestRequestLineBoostImmediate(t *testing.T) {
	tr, evs := p4Tracker([]config.Override{
		p4Ov(config.OverrideMatch{Host: "api.example.com"}, config.LevelL2),
	})
	// L0 流：SYN 无提升
	st := tr.Track(Packet{Ts: p4Base, SrcIP: "10.0.0.1", SrcPort: 5000,
		DstIP: "10.0.0.2", DstPort: 80, Ingress: true})
	if st.Level != 0 || st.SensorWanted {
		t.Fatalf("SYN 不应提升，got %+v", st)
	}
	// 请求行嗅探成功（host 命中）：即时提升该流后续采集等级
	st = tr.Track(Packet{Ts: p4Base.Add(time.Second), SrcIP: "10.0.0.1", SrcPort: 5000,
		DstIP: "10.0.0.2", DstPort: 80, Ingress: true,
		Payload: []byte("GET /api/payment HTTP/1.1\r\nHost: api.example.com\r\n\r\n")})
	if st.Level != 2 {
		t.Fatalf("请求行命中应即时提升 L2，got %d", st.Level)
	}
	if !st.SensorWanted {
		t.Fatal("提升后 SensorWanted 应置位（上层从当前包起建链采集）")
	}
	// 生效 L2 的流停发旧 request 事件（HTTP 记录替代）
	for _, ev := range *evs {
		if ev.EventType == events.TypeRequest {
			t.Fatalf("生效等级 ≥L1 不应再发 request 事件: %+v", ev)
		}
	}
	// flow_end 保留
	tr.Close(p4Base.Add(2 * time.Second))
	found := false
	for _, ev := range *evs {
		if ev.EventType == events.TypeFlowEnd {
			found = true
		}
	}
	if !found {
		t.Fatal("flow_end 应保留")
	}
}

func TestRuleOnlyUpgradesNeverDowngrades(t *testing.T) {
	tr, _ := p4Tracker([]config.Override{
		p4Ov(config.OverrideMatch{DstPort: 8080}, config.LevelL2),           // 首包命中 L2
		p4Ov(config.OverrideMatch{Host: "api.example.com"}, config.LevelL1), // 请求行命中仅 L1
	})
	tr.Track(Packet{Ts: p4Base, SrcIP: "10.0.0.1", SrcPort: 5000,
		DstIP: "10.0.0.2", DstPort: 8080, Ingress: true})
	st := tr.Track(Packet{Ts: p4Base.Add(time.Second), SrcIP: "10.0.0.1", SrcPort: 5000,
		DstIP: "10.0.0.2", DstPort: 8080, Ingress: true,
		Payload: []byte("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")})
	if st.Level != 2 {
		t.Fatalf("规则只升不降：请求行命中较低等级不应拉低，got %d", st.Level)
	}
}

func TestExpiredRuleNoBoost(t *testing.T) {
	expired := config.Override{
		ID: "old", Match: config.OverrideMatch{DstPort: 8080}, CaptureLevel: config.LevelL3,
		ExpiresAt: p4Base.Add(-time.Minute).Format(time.RFC3339),
	}
	tr, _ := p4Tracker([]config.Override{expired})
	st := tr.Track(Packet{Ts: p4Base, SrcIP: "10.0.0.1", SrcPort: 5000,
		DstIP: "10.0.0.2", DstPort: 8080, Ingress: true})
	if st.Level != 0 {
		t.Fatalf("过期规则应即时忽略，got %d", st.Level)
	}
}

func TestSampledOutFlowOnlyFlowEnd(t *testing.T) {
	tr, evs := p4Tracker(nil)
	tr.SetSampler(func(flowID string) bool { return false }) // 全部采样外
	tr.Track(Packet{Ts: p4Base, SrcIP: "10.0.0.1", SrcPort: 5000,
		DstIP: "10.0.0.2", DstPort: 80, Ingress: true})
	st := tr.Track(Packet{Ts: p4Base.Add(time.Second), SrcIP: "10.0.0.1", SrcPort: 5000,
		DstIP: "10.0.0.2", DstPort: 80, Ingress: true,
		Payload: []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")})
	if st.Sampled {
		t.Fatal("采样外 flow Sampled 应为 false")
	}
	if st.SensorWanted {
		t.Fatal("采样外 flow 不应挂接 HTTP 传感器")
	}
	tr.Close(p4Base.Add(2 * time.Second))
	var req, end int
	for _, ev := range *evs {
		switch ev.EventType {
		case events.TypeRequest:
			req++
		case events.TypeFlowEnd:
			end++
		}
	}
	if req != 0 {
		t.Fatalf("采样外 flow 不应发 request 事件: %d", req)
	}
	if end != 1 {
		t.Fatalf("采样外 flow 仅保留 flow_end 计数事件: %d", end)
	}
}

func TestLevelFuncCapPress(t *testing.T) {
	tr, evs := p4Tracker([]config.Override{
		p4Ov(config.OverrideMatch{DstPort: 8080}, config.LevelL3),
	})
	// 降级帽压制：帽 L1 → 生效 = min(规则 L3, 帽 L1) = L1
	tr.SetLevelFunc(func(ruleLevel int) int {
		if ruleLevel > 1 {
			return 1
		}
		return ruleLevel
	})
	tr.Track(Packet{Ts: p4Base, SrcIP: "10.0.0.1", SrcPort: 5000,
		DstIP: "10.0.0.2", DstPort: 8080, Ingress: true})
	st := tr.Track(Packet{Ts: p4Base.Add(time.Second), SrcIP: "10.0.0.1", SrcPort: 5000,
		DstIP: "10.0.0.2", DstPort: 8080, Ingress: true,
		Payload: []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")})
	if st.Level != 1 {
		t.Fatalf("帽压制应生效 L1，got %d", st.Level)
	}
	for _, ev := range *evs {
		if ev.EventType == events.TypeRequest {
			t.Fatal("帽压后生效 L1 仍应抑制 request 事件（HTTP 记录通道替代）")
		}
	}
}

func TestSamplerCalledWithFlowID(t *testing.T) {
	tr, _ := p4Tracker(nil)
	var gotID string
	tr.SetSampler(func(flowID string) bool { gotID = flowID; return true })
	st := tr.Track(Packet{Ts: p4Base, SrcIP: "10.0.0.1", SrcPort: 5000,
		DstIP: "10.0.0.2", DstPort: 80, Ingress: true})
	if gotID == "" || gotID != st.FlowID {
		t.Fatalf("采样判定应以 flow_id 调用: %q vs %q", gotID, st.FlowID)
	}
}
