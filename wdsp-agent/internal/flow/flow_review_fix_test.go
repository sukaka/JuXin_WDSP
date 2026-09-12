// 代码审查回归测试（批次5-A）：
//   - HIGH-12：flow 层把嗅探结论透传进 FlowState，ENCRYPTED 流不进 HTTP 重组器；
//   - LOW-A6：决策后释放嗅探器；
//   - LOW-A7：双采集端口连接的 canonical 归一化（五元组排序兜底）；
//   - LOW-A8：表满驱逐事件锁外发送 + 采样驱逐。
package flow

import (
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
)

// HIGH-12：Track 返回的 FlowState 携带嗅探结论（上层据此拦截 TLS 流进重组器）。
func TestFlowStateCarriesVisibility(t *testing.T) {
	var evs []events.FlowEvent
	tr := NewTracker("a", 0, 0, collect(&evs), nil)
	st := tr.Track(pkt("1.1.1.1", 4000, "2.2.2.2", 443, true, "", base))
	if st.Visibility != "" {
		t.Fatalf("嗅探未决时 Visibility 应为空: %q", st.Visibility)
	}
	st = tr.Track(pkt("1.1.1.1", 4000, "2.2.2.2", 443, true,
		string([]byte{0x16, 0x03, 0x01, 0x00, 0x2e}), base.Add(time.Second)))
	if st.Visibility != events.VisibilityEncrypted {
		t.Fatalf("TLS 首包后 Visibility 应为 ENCRYPTED: %q", st.Visibility)
	}
	// 后续包结论保持
	st = tr.Track(pkt("1.1.1.1", 4000, "2.2.2.2", 443, true,
		string([]byte{0x17, 0x03, 0x03, 0x00, 0x10}), base.Add(2*time.Second)))
	if st.Visibility != events.VisibilityEncrypted {
		t.Fatalf("Visibility 应随流保持: %q", st.Visibility)
	}
}

// LOW-A6：嗅探决策后 sniffer 立即释放（不随流常驻最高 16KB 到驱逐）。
func TestSnifferReleasedAfterDecision(t *testing.T) {
	tr := NewTracker("a", 0, 0, nil, nil)
	tr.Track(pkt("1.1.1.1", 4000, "2.2.2.2", 80, true,
		"GET /x HTTP/1.1\r\nHost: h\r\n\r\n", base))
	tr.mu.Lock()
	defer tr.mu.Unlock()
	for _, f := range tr.flows {
		if !f.sniffDone {
			t.Fatal("请求行完整应已决策")
		}
		if f.sniffer != nil {
			t.Fatal("决策后 sniffer 应释放")
		}
	}
}

// LOW-A7：连接两端端口均在采集集时，双方向包归并到同一条流
// （逐包 Ingress 判定会随包向翻转，canonical 以五元组排序兜底）。
func TestBothHitCanonicalMergesDirections(t *testing.T) {
	var evs []events.FlowEvent
	tr := NewTracker("a", 0, 0, collect(&evs), nil)
	// 两端端口都命中采集集：filter.Match 对两个方向都判 dst 命中（ingress=true）
	c2s := Packet{Ts: base, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 8080, DstPort: 8443, Ingress: true, BothHit: true, Length: 60,
		Payload: []byte("GET /x HTTP/1.1\r\nHost: h\r\n\r\n")}
	s2c := Packet{Ts: base.Add(time.Second), SrcIP: "10.0.0.2", DstIP: "10.0.0.1",
		SrcPort: 8443, DstPort: 8080, Ingress: true, BothHit: true, Length: 60,
		Payload: []byte("HTTP/1.1 200 OK\r\n\r\n")}
	tr.Track(c2s)
	tr.Track(s2c)
	if tr.Len() != 1 {
		t.Fatalf("双采集端口连接应归并为一条流: %d", tr.Len())
	}
	// 反序到达（响应包先到）同样归并
	tr2 := NewTracker("a", 0, 0, collect(&evs), nil)
	tr2.Track(s2c)
	tr2.Track(c2s)
	if tr2.Len() != 1 {
		t.Fatalf("响应先到也应归并为一条流: %d", tr2.Len())
	}
	tr.Expire(base.Add(91 * time.Second))
	ends := flowEndEvents(evs)
	if len(ends) != 1 {
		t.Fatalf("应只有一条 flow_end: %d", len(ends))
	}
	// canonical：小端点（10.0.0.1:8080）为 client 侧；c2s 计 out、s2c 计 in
	if ends[0].SrcIP != "10.0.0.1" || ends[0].SrcPort != 8080 {
		t.Fatalf("canonical 错误: %s:%d", ends[0].SrcIP, ends[0].SrcPort)
	}
	if ends[0].PacketsOut != 1 || ends[0].PacketsIn != 1 {
		t.Fatalf("方向计数错误: out=%d in=%d", ends[0].PacketsOut, ends[0].PacketsIn)
	}
}

// LOW-A8：表满驱逐的 flow_end 在锁外发送（回调重入取锁不得死锁）。
func TestOverflowEvictionEventSentOutsideLock(t *testing.T) {
	var tr *Tracker
	tr = NewTracker("a", 1, 0, func(ev events.FlowEvent) {
		_ = tr.Len() // 重入取锁：若事件在全局锁内发送将死锁
	}, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.Track(pkt("1.1.1.1", 1, "2.2.2.2", 80, true, "", base))
		tr.Track(pkt("1.1.1.1", 2, "2.2.2.2", 80, true, "", base.Add(time.Second))) // 触发驱逐
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("驱逐事件在全局锁内发送导致死锁")
	}
}

// LOW-A8：采样驱逐仍驱逐一条流并发 flow_end（驱逐数超过采样上限时退化为
// 采样内最旧，不保证全局最旧——此处验证计数与事件不丢）。
func TestOverflowEvictionSampledStillEvicts(t *testing.T) {
	var evs []events.FlowEvent
	overflow := 0
	tr := NewTracker("a", 4, 0, collect(&evs), func() { overflow++ })
	for i := 0; i < 4; i++ {
		tr.Track(pkt("1.1.1.1", uint16(1000+i), "2.2.2.2", 80, true, "", base.Add(time.Duration(i)*time.Second)))
	}
	// 第 5 条流触发表满驱逐
	tr.Track(pkt("1.1.1.1", 2000, "2.2.2.2", 80, true, "", base.Add(5*time.Second)))
	if tr.Len() != 4 {
		t.Fatalf("flows=%d", tr.Len())
	}
	if overflow != 1 {
		t.Fatalf("overflow=%d", overflow)
	}
	if n := len(flowEndEvents(evs)); n != 1 {
		t.Fatalf("驱逐应发一条 flow_end: %d", n)
	}
}
