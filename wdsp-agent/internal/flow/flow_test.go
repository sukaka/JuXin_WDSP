package flow

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
)

var base = time.Unix(1788256800, 0)

func pkt(src string, sport uint16, dst string, dport uint16, ingress bool, payload string, ts time.Time) Packet {
	return Packet{
		Ts: ts, SrcIP: src, DstIP: dst, SrcPort: sport, DstPort: dport,
		Ingress: ingress, Length: 60 + len(payload), Payload: []byte(payload),
	}
}

// pktF 带 TCP flags 的合成包。
func pktF(src string, sport uint16, dst string, dport uint16, ingress bool, payload string, fin, rst bool, ts time.Time) Packet {
	p := pkt(src, sport, dst, dport, ingress, payload, ts)
	p.FIN = fin
	p.RST = rst
	return p
}

func collect(evs *[]events.FlowEvent) func(events.FlowEvent) {
	return func(ev events.FlowEvent) { *evs = append(*evs, ev) }
}

func TestFirstPacketCreatesFlowAndRequestEvent(t *testing.T) {
	var evs []events.FlowEvent
	tr := NewTracker("agent-1", 0, 0, collect(&evs), nil)
	tr.Track(pkt("10.1.1.10", 51234, "10.1.2.20", 8080, true,
		"GET /api/login HTTP/1.1\r\nHost: api.example.com\r\n\r\n", base))
	if tr.Len() != 1 {
		t.Fatalf("flows=%d", tr.Len())
	}
	if len(evs) != 1 {
		t.Fatalf("events=%d", len(evs))
	}
	ev := evs[0]
	if ev.EventType != events.TypeRequest {
		t.Fatalf("type=%s", ev.EventType)
	}
	wantID := fmt.Sprintf("agent-1-10.1.1.10-51234-10.1.2.20-8080-%d", base.Unix())
	if ev.FlowID != wantID {
		t.Fatalf("flow_id=%s want %s", ev.FlowID, wantID)
	}
	if ev.Direction != "ingress" || ev.Protocol != "tcp" {
		t.Fatalf("direction=%s proto=%s", ev.Direction, ev.Protocol)
	}
	if ev.TLSVisibility != events.VisibilityPlaintext {
		t.Fatalf("visibility=%s", ev.TLSVisibility)
	}
	if ev.HTTPMethod != "GET" || ev.HTTPHost != "api.example.com" || ev.HTTPURI != "/api/login" {
		t.Fatalf("http=%s %s %s", ev.HTTPMethod, ev.HTTPHost, ev.HTTPURI)
	}
	if ev.HTTPStatus != 0 {
		t.Fatalf("http_status=%d, Phase 1 恒 0", ev.HTTPStatus)
	}
}

func TestBidirectionalCountsNormalized(t *testing.T) {
	var evs []events.FlowEvent
	tr := NewTracker("a", 0, 0, collect(&evs), nil)
	tr.Track(pkt("10.0.0.1", 5000, "10.0.0.2", 443, true, "", base))
	tr.Track(pkt("10.0.0.1", 5000, "10.0.0.2", 443, true, "", base.Add(time.Second)))
	// 反向包（响应）：src 端口命中 → egress 判定，应归并到同一条流
	tr.Track(pkt("10.0.0.2", 443, "10.0.0.1", 5000, false, "", base.Add(2*time.Second)))
	if tr.Len() != 1 {
		t.Fatalf("flows=%d, 双向包应归并为一条流", tr.Len())
	}
	tr.Expire(base.Add(93 * time.Second))
	if len(evs) != 1 || evs[0].EventType != events.TypeFlowEnd {
		t.Fatalf("events=%v", evs)
	}
	ev := evs[0]
	if ev.PacketsOut != 2 || ev.PacketsIn != 1 {
		t.Fatalf("packets out=%d in=%d", ev.PacketsOut, ev.PacketsIn)
	}
	if ev.BytesOut == 0 || ev.BytesIn == 0 {
		t.Fatalf("bytes out=%d in=%d", ev.BytesOut, ev.BytesIn)
	}
}

func TestTLSEncryptedMarking(t *testing.T) {
	var evs []events.FlowEvent
	tr := NewTracker("a", 0, 0, collect(&evs), nil)
	tr.Track(pkt("1.1.1.1", 4000, "2.2.2.2", 443, true,
		string([]byte{0x16, 0x03, 0x01, 0x00, 0x2e}), base))
	if len(evs) != 1 || evs[0].TLSVisibility != events.VisibilityEncrypted {
		t.Fatalf("evs=%v", evs)
	}
	if evs[0].EventType != events.TypeRequest {
		t.Fatalf("type=%s", evs[0].EventType)
	}
}

func TestUnknownMarking(t *testing.T) {
	var evs []events.FlowEvent
	tr := NewTracker("a", 0, 0, collect(&evs), nil)
	tr.Track(pkt("1.1.1.1", 4000, "2.2.2.2", 9000, true, "SSH-2.0-x\r\n", base))
	if len(evs) != 1 || evs[0].TLSVisibility != events.VisibilityUnknown {
		t.Fatalf("evs=%v", evs)
	}
}

func TestEgressFlowNormalization(t *testing.T) {
	var evs []events.FlowEvent
	tr := NewTracker("a", 0, 0, collect(&evs), nil)
	// 首包为响应方向（src 端口命中）→ egress 流，canonical 以 443 端为 server
	tr.Track(pkt("2.2.2.2", 443, "1.1.1.1", 4000, false, "", base))
	tr.Expire(base.Add(91 * time.Second))
	if len(evs) != 1 {
		t.Fatalf("evs=%v", evs)
	}
	ev := evs[0]
	if ev.Direction != "egress" {
		t.Fatalf("direction=%s", ev.Direction)
	}
	if ev.SrcIP != "1.1.1.1" || ev.SrcPort != 4000 || ev.DstIP != "2.2.2.2" || ev.DstPort != 443 {
		t.Fatalf("canonical 错误: %s:%d → %s:%d", ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort)
	}
	if !strings.HasPrefix(ev.FlowID, "a-1.1.1.1-4000-2.2.2.2-443-") {
		t.Fatalf("flow_id=%s", ev.FlowID)
	}
}

func TestIdleEviction(t *testing.T) {
	var evs []events.FlowEvent
	tr := NewTracker("a", 0, 90*time.Second, collect(&evs), nil)
	tr.Track(pkt("1.1.1.1", 1, "2.2.2.2", 80, true, "", base))
	tr.Expire(base.Add(89 * time.Second))
	if tr.Len() != 1 || len(evs) != 0 {
		t.Fatal("未到空闲超时不应驱逐")
	}
	tr.Expire(base.Add(90 * time.Second))
	if tr.Len() != 0 || len(evs) != 1 || evs[0].EventType != events.TypeFlowEnd {
		t.Fatalf("空闲驱逐失败: len=%d evs=%v", tr.Len(), evs)
	}
}

func TestMaxEntriesEvictsOldest(t *testing.T) {
	var evs []events.FlowEvent
	overflow := 0
	tr := NewTracker("a", 2, 0, collect(&evs), func() { overflow++ })
	tr.Track(pkt("1.1.1.1", 1, "2.2.2.2", 80, true, "", base))
	tr.Track(pkt("1.1.1.1", 2, "2.2.2.2", 80, true, "", base.Add(time.Second)))
	// 第三条流触发表满驱逐最旧（sport=1）
	tr.Track(pkt("1.1.1.1", 3, "2.2.2.2", 80, true, "", base.Add(2*time.Second)))
	if tr.Len() != 2 {
		t.Fatalf("flows=%d", tr.Len())
	}
	if overflow != 1 {
		t.Fatalf("overflow=%d", overflow)
	}
	if len(evs) != 1 || evs[0].EventType != events.TypeFlowEnd || evs[0].SrcPort != 1 {
		t.Fatalf("应驱逐最旧流并发 flow_end: %v", evs)
	}
}

func TestCloseFlushesAllFlows(t *testing.T) {
	var evs []events.FlowEvent
	tr := NewTracker("a", 0, 0, collect(&evs), nil)
	tr.Track(pkt("1.1.1.1", 1, "2.2.2.2", 80, true, "", base))
	tr.Track(pkt("1.1.1.1", 2, "2.2.2.2", 80, true, "", base))
	tr.Close(base)
	if tr.Len() != 0 || len(evs) != 2 {
		t.Fatalf("len=%d evs=%d", tr.Len(), len(evs))
	}
}

func TestSniffOnlyClientToServer(t *testing.T) {
	var evs []events.FlowEvent
	tr := NewTracker("a", 0, 0, collect(&evs), nil)
	// 先喂响应方向（egress 判定归并后仍是 server→client），payload 不应参与嗅探
	tr.Track(pkt("2.2.2.2", 80, "1.1.1.1", 4000, false, "HTTP/1.1 200 OK\r\n\r\n", base))
	if len(evs) != 0 {
		t.Fatalf("server→client payload 不应触发嗅探事件: %v", evs)
	}
	tr.Track(pkt("1.1.1.1", 4000, "2.2.2.2", 80, true, "GET /x HTTP/1.1\r\nHost: h\r\n\r\n", base))
	if len(evs) != 1 || evs[0].HTTPURI != "/x" {
		t.Fatalf("evs=%v", evs)
	}
}

// ── D-01：TCP FIN/RST 流关闭识别 ──────────────────────────

func flowEndEvents(evs []events.FlowEvent) []events.FlowEvent {
	var out []events.FlowEvent
	for _, e := range evs {
		if e.EventType == events.TypeFlowEnd {
			out = append(out, e)
		}
	}
	return out
}

// SYN→数据→双方 FIN：第二条 FIN 到达时立即 flow_end（不等空闲超时）。
func TestBothFINEndsFlowImmediately(t *testing.T) {
	var evs []events.FlowEvent
	tr := NewTracker("a", 0, 0, collect(&evs), nil)
	// SYN（c→s）
	tr.Track(pktF("10.0.0.1", 5000, "10.0.0.2", 80, true, "", false, false, base))
	// 请求数据
	tr.Track(pktF("10.0.0.1", 5000, "10.0.0.2", 80, true, "GET / HTTP/1.1\r\nHost: x\r\n\r\n", false, false, base.Add(time.Second)))
	// 响应数据（s→c）
	tr.Track(pktF("10.0.0.2", 80, "10.0.0.1", 5000, false, "HTTP/1.1 200 OK\r\n\r\n", false, false, base.Add(2*time.Second)))
	if tr.Len() != 1 || len(flowEndEvents(evs)) != 0 {
		t.Fatal("数据阶段不应结束")
	}
	// server 侧先 FIN（HTTP 短连接常见）
	tr.Track(pktF("10.0.0.2", 80, "10.0.0.1", 5000, false, "", true, false, base.Add(3*time.Second)))
	if tr.Len() != 1 || len(flowEndEvents(evs)) != 0 {
		t.Fatal("单方 FIN 不应立即结束")
	}
	// client 侧 FIN：双方到齐 → 立即结束
	tr.Track(pktF("10.0.0.1", 5000, "10.0.0.2", 80, true, "", true, false, base.Add(4*time.Second)))
	ends := flowEndEvents(evs)
	if tr.Len() != 0 || len(ends) != 1 {
		t.Fatalf("双方 FIN 应立即结束: len=%d ends=%d", tr.Len(), len(ends))
	}
	ev := ends[0]
	if ev.Timestamp != base.Add(4*time.Second).Unix() {
		t.Fatalf("flow_end 应及时（第二 FIN 时刻）: ts=%d", ev.Timestamp)
	}
	if ev.PacketsOut != 3 || ev.PacketsIn != 2 {
		t.Fatalf("计数错误: out=%d in=%d", ev.PacketsOut, ev.PacketsIn)
	}
	if ev.BytesOut == 0 || ev.BytesIn == 0 {
		t.Fatalf("字节计数错误: out=%d in=%d", ev.BytesOut, ev.BytesIn)
	}
}

// 单边 RST：立即 flow_end，RST 包本身计入累计。
func TestRSTEndsFlowImmediately(t *testing.T) {
	var evs []events.FlowEvent
	tr := NewTracker("a", 0, 0, collect(&evs), nil)
	tr.Track(pktF("10.0.0.1", 5000, "10.0.0.2", 443, true, "", false, false, base))
	tr.Track(pktF("10.0.0.1", 5000, "10.0.0.2", 443, true, string([]byte{0x16, 0x03, 0x01}), false, false, base.Add(time.Second)))
	// server→client RST
	tr.Track(pktF("10.0.0.2", 443, "10.0.0.1", 5000, false, "", false, true, base.Add(2*time.Second)))
	ends := flowEndEvents(evs)
	if tr.Len() != 0 || len(ends) != 1 {
		t.Fatalf("RST 应立即结束: len=%d ends=%d", tr.Len(), len(ends))
	}
	if ends[0].PacketsOut != 2 || ends[0].PacketsIn != 1 {
		t.Fatalf("RST 包未计入: out=%d in=%d", ends[0].PacketsOut, ends[0].PacketsIn)
	}
	if ends[0].TLSVisibility != events.VisibilityEncrypted {
		t.Fatalf("visibility=%s", ends[0].TLSVisibility)
	}
}

// 半关闭：单方 FIN 后对侧仍发数据 → 不提前结束且计数正确；
// 静默满宽限后才结束。
func TestHalfCloseKeepsCounting(t *testing.T) {
	var evs []events.FlowEvent
	tr := NewTracker("a", 0, 0, collect(&evs), nil)
	tr.Track(pktF("10.0.0.1", 5000, "10.0.0.2", 80, true, "", false, false, base))
	// server 先 FIN
	tr.Track(pktF("10.0.0.2", 80, "10.0.0.1", 5000, false, "", true, false, base.Add(time.Second)))
	// client 继续发数据（半关闭合法）
	tr.Track(pktF("10.0.0.1", 5000, "10.0.0.2", 80, true, "GET /more HTTP/1.1\r\nHost: x\r\n\r\n", false, false, base.Add(2*time.Second)))
	// 宽限按最后活动计：FIN 后 1.5s（距 FIN 已 >0 但距最后活动 <3s）不应结束
	tr.Expire(base.Add(3500 * time.Millisecond))
	if tr.Len() != 1 || len(flowEndEvents(evs)) != 0 {
		t.Fatal("半关闭且有活动不应提前结束")
	}
	// 最后活动后满 3s 宽限 → 结束
	tr.Expire(base.Add(5*time.Second + time.Millisecond))
	ends := flowEndEvents(evs)
	if tr.Len() != 0 || len(ends) != 1 {
		t.Fatalf("宽限后应结束: len=%d ends=%d", tr.Len(), len(ends))
	}
	if ends[0].PacketsOut != 2 || ends[0].PacketsIn != 1 {
		t.Fatalf("半关闭计数错误: out=%d in=%d", ends[0].PacketsOut, ends[0].PacketsIn)
	}
	// 单方 FIN 后 active side 的 payload 仍应被嗅探
	if ends[0].TLSVisibility != events.VisibilityPlaintext {
		t.Fatalf("visibility=%s", ends[0].TLSVisibility)
	}
}

// flow_end 幂等：双方 FIN 结束后，Expire/Close 不得重复发。
func TestFlowEndEmittedOnce(t *testing.T) {
	var evs []events.FlowEvent
	tr := NewTracker("a", 0, 0, collect(&evs), nil)
	tr.Track(pktF("10.0.0.1", 5000, "10.0.0.2", 80, true, "", true, false, base))
	tr.Track(pktF("10.0.0.2", 80, "10.0.0.1", 5000, false, "", true, false, base.Add(time.Second)))
	if len(flowEndEvents(evs)) != 1 {
		t.Fatal("双方 FIN 应发一次 flow_end")
	}
	tr.Expire(base.Add(time.Hour)) // 空闲超时路径
	tr.Close(base.Add(time.Hour))  // 停机冲刷路径
	if n := len(flowEndEvents(evs)); n != 1 {
		t.Fatalf("flow_end 重复: %d 条", n)
	}
}

// RST 结束后同样不得与空闲超时/宽限路径重复。
func TestRSTThenExpireNoDuplicate(t *testing.T) {
	var evs []events.FlowEvent
	tr := NewTracker("a", 0, 0, collect(&evs), nil)
	tr.Track(pktF("10.0.0.1", 5000, "10.0.0.2", 80, true, "", false, false, base))
	tr.Track(pktF("10.0.0.1", 5000, "10.0.0.2", 80, true, "", false, true, base.Add(time.Second)))
	tr.Expire(base.Add(time.Hour))
	tr.Close(base.Add(time.Hour))
	if n := len(flowEndEvents(evs)); n != 1 {
		t.Fatalf("flow_end 应恰好一条, got %d", n)
	}
}

// 单方 FIN 后宽限结束只发一次（宽限路径与后续扫描不重复）。
func TestFinGraceEmittedOnce(t *testing.T) {
	var evs []events.FlowEvent
	tr := NewTracker("a", 0, 0, collect(&evs), nil)
	tr.Track(pktF("10.0.0.1", 5000, "10.0.0.2", 80, true, "", true, false, base))
	tr.Expire(base.Add(4 * time.Second)) // 宽限触发
	tr.Expire(base.Add(8 * time.Second)) // 再次扫描
	tr.Expire(base.Add(time.Hour))       // 空闲路径
	if n := len(flowEndEvents(evs)); n != 1 {
		t.Fatalf("flow_end 应恰好一条, got %d", n)
	}
}
