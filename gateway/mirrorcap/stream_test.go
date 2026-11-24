// 重组/解析/请求构造的纯函数与合成流测试（无需 root、无需网卡）。
package mirrorcap

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// captureBody 截断与流对齐：超限 Body 只保留上限内字节，剩余排空后下一请求可正常解析。
func TestCaptureBodyTruncationKeepsStreamAligned(t *testing.T) {
	wire := "POST /upload HTTP/1.1\r\nHost: h\r\nContent-Length: 20\r\n\r\n0123456789ABCDEFGHIJ" +
		"GET /next HTTP/1.1\r\nHost: h\r\n\r\n"
	buf := bufio.NewReader(strings.NewReader(wire))

	req1, err := http.ReadRequest(buf)
	if err != nil {
		t.Fatalf("ReadRequest req1: %v", err)
	}
	body, truncated, err := captureBody(req1, 10)
	if err != nil {
		t.Fatalf("captureBody: %v", err)
	}
	if !truncated {
		t.Fatal("应标记截断")
	}
	if string(body) != "0123456789" {
		t.Errorf("捕获体=%q want %q", body, "0123456789")
	}
	// 剩余 10 字节已排空：下一请求应从 GET 开始解析
	req2, err := http.ReadRequest(buf)
	if err != nil {
		t.Fatalf("ReadRequest req2: %v", err)
	}
	if req2.Method != "GET" || req2.URL.Path != "/next" {
		t.Errorf("req2=%s %s want GET /next", req2.Method, req2.URL.Path)
	}
}

// captureBody 未超限：全量保留、不标记截断。
func TestCaptureBodyUnderLimit(t *testing.T) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello")))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	body, truncated, err := captureBody(req, 1024)
	if err != nil || truncated {
		t.Fatalf("captureBody err=%v truncated=%v", err, truncated)
	}
	if string(body) != "hello" {
		t.Errorf("body=%q want hello", body)
	}
}

// captureBody 支持 chunked 编码（http.ReadRequest 已解码，按解码后字节计上限）。
func TestCaptureBodyChunked(t *testing.T) {
	wire := "POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n5\r\nWORLD\r\n0\r\n\r\n"
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(wire)))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	body, truncated, err := captureBody(req, 7)
	if err != nil {
		t.Fatalf("captureBody: %v", err)
	}
	if !truncated || string(body) != "helloWO" {
		t.Errorf("body=%q truncated=%v want helloWO/true", body, truncated)
	}
}

// collectHandler 测试用请求收集器。
type collectHandler struct{ ch chan *http.Request }

func (h *collectHandler) HandleRequest(req *http.Request, meta FlowMeta, bodyTruncated bool) {
	h.ch <- req
}

// tcpPacket 构造合成 TCP 分片（调用方维护序号）。
// 注：TransportFlow() 依赖解码期填充的内部端口字节，手工构造需 SetInternalPortsForTesting。
func tcpPacket(sport, dport uint16, seq uint32, syn, ack, fin bool, payload []byte) *layers.TCP {
	t := &layers.TCP{
		SrcPort:   layers.TCPPort(sport),
		DstPort:   layers.TCPPort(dport),
		Seq:       seq,
		SYN:       syn,
		ACK:       ack,
		FIN:       fin,
		Window:    65535,
		BaseLayer: layers.BaseLayer{Payload: payload},
	}
	t.SetInternalPortsForTesting()
	return t
}

// TestAssemblerEndToEnd 合成四元组流（SYN → 乱切分片的两条 pipeline 请求 → FIN）
// 经真实 tcpassembly 重组后，应逐条还原出正确请求（方法/路径/源地址/Body）。
func TestAssemblerEndToEnd(t *testing.T) {
	stats := &Stats{}
	h := &collectHandler{ch: make(chan *http.Request, 4)}
	pool := tcpassembly.NewStreamPool(NewStreamFactory(h, 65536, 16, stats))
	asm := tcpassembly.NewAssembler(pool)

	cliIP, srvIP := net.ParseIP("10.1.0.10").To4(), net.ParseIP("10.1.0.20").To4()
	flow := gopacket.NewFlow(layers.EndpointIPv4, cliIP, srvIP)
	now := time.Now()

	const base = uint32(1000)
	req1 := "GET /hello?a=1 HTTP/1.1\r\nHost: example.com\r\nX-Test: x\r\n\r\n"
	req2 := "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\nname=abc123"
	wire := []byte(req1 + req2)

	// SYN（无载荷）
	asm.AssembleWithTimestamp(flow, tcpPacket(12345, 8080, base, true, false, false, nil), now)
	// 数据乱边界切三片（SEQ 连续）
	seq := base + 1
	cuts := []int{17, 41, len(wire)}
	prev := 0
	for _, c := range cuts {
		seg := wire[prev:c]
		asm.AssembleWithTimestamp(flow, tcpPacket(12345, 8080, seq, false, true, false, seg), now.Add(time.Millisecond))
		seq += uint32(len(seg))
		prev = c
	}
	// FIN
	asm.AssembleWithTimestamp(flow, tcpPacket(12345, 8080, seq, false, true, true, nil), now.Add(2*time.Millisecond))

	// 请求 1
	select {
	case r := <-h.ch:
		if r.Method != "GET" || r.URL.Path != "/hello" || r.URL.Query().Get("a") != "1" {
			t.Errorf("req1=%s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		if r.RemoteAddr != "10.1.0.10:12345" {
			t.Errorf("RemoteAddr=%q want 10.1.0.10:12345", r.RemoteAddr)
		}
		if !strings.HasPrefix(r.Header.Get("X-Request-Id"), "mirror-") {
			t.Errorf("X-Request-Id 应由旁路生成 mirror- 前缀, got %q", r.Header.Get("X-Request-Id"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("超时未收到 req1")
	}
	// 请求 2（Body 完整）
	select {
	case r := <-h.ch:
		b, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || r.URL.Path != "/submit" || string(b) != "name=abc123" {
			t.Errorf("req2=%s %s body=%q", r.Method, r.URL.Path, b)
		}
		if r.ContentLength != 11 {
			t.Errorf("ContentLength=%d want 11", r.ContentLength)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("超时未收到 req2")
	}
	// FIN 后流应关闭（goroutine 退出）
	deadline := time.Now().Add(2 * time.Second)
	for stats.StreamsClosed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if stats.StreamsClosed.Load() != 1 {
		t.Errorf("StreamsClosed=%d want 1", stats.StreamsClosed.Load())
	}
	if stats.RequestsParsed.Load() != 2 {
		t.Errorf("RequestsParsed=%d want 2", stats.RequestsParsed.Load())
	}
}

// assembleRequestFlow 合成一条 client→server 流（SYN → 单分片载荷 → FIN）喂给真实重组器。
func assembleRequestFlow(stats *Stats, h *collectHandler, payload []byte) {
	pool := tcpassembly.NewStreamPool(NewStreamFactory(h, 65536, 16, stats))
	asm := tcpassembly.NewAssembler(pool)
	cliIP, srvIP := net.ParseIP("10.2.0.10").To4(), net.ParseIP("10.2.0.20").To4()
	flow := gopacket.NewFlow(layers.EndpointIPv4, cliIP, srvIP)
	now := time.Now()
	const base = uint32(5000)
	asm.AssembleWithTimestamp(flow, tcpPacket(23456, 8080, base, true, false, false, nil), now)
	asm.AssembleWithTimestamp(flow, tcpPacket(23456, 8080, base+1, false, true, false, payload), now.Add(time.Millisecond))
	asm.AssembleWithTimestamp(flow, tcpPacket(23456, 8080, base+1+uint32(len(payload)), false, true, true, nil), now.Add(2*time.Millisecond))
}

// waitStreamClosed 等待流消费 goroutine 退出（StreamsClosed 达到 want）。
func waitStreamClosed(stats *Stats, want uint64) bool {
	deadline := time.Now().Add(2 * time.Second)
	for stats.StreamsClosed.Load() < want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	return stats.StreamsClosed.Load() >= want
}

// 头部护栏：单条 100KB 头行触发硬顶，流终止、请求不交付、计解析错误。
func TestHeaderGuardOversizedLineTerminatesStream(t *testing.T) {
	stats := &Stats{}
	h := &collectHandler{ch: make(chan *http.Request, 4)}
	wire := "GET / HTTP/1.1\r\nHost: h\r\nX-Pad: " + strings.Repeat("A", 100<<10) + "\r\n\r\n"
	assembleRequestFlow(stats, h, []byte(wire))

	if !waitStreamClosed(stats, 1) {
		t.Fatal("流未按预期关闭")
	}
	select {
	case r := <-h.ch:
		t.Fatalf("超限头部不应交付请求, got %s %s", r.Method, r.URL.Path)
	default:
	}
	if stats.RequestErrors.Load() != 1 {
		t.Errorf("RequestErrors=%d want 1", stats.RequestErrors.Load())
	}
	if stats.RequestsParsed.Load() != 0 {
		t.Errorf("RequestsParsed=%d want 0", stats.RequestsParsed.Load())
	}
}

// 头部精确复核：头部 70KB（低于硬顶、高于 64KB 上限）ReadRequest 可解析，
// 但复核按真实头部消耗判定超限，终止该流不交付。
func TestHeaderGuardPreciseRecheck(t *testing.T) {
	stats := &Stats{}
	h := &collectHandler{ch: make(chan *http.Request, 4)}
	pad := strings.Repeat("B", 70<<10)
	wire := "GET / HTTP/1.1\r\nHost: h\r\nX-Pad: " + pad + "\r\n\r\n"
	assembleRequestFlow(stats, h, []byte(wire))

	if !waitStreamClosed(stats, 1) {
		t.Fatal("流未按预期关闭")
	}
	select {
	case r := <-h.ch:
		t.Fatalf("复核超限不应交付请求, got %s %s", r.Method, r.URL.Path)
	default:
	}
	if stats.RequestErrors.Load() != 1 {
		t.Errorf("RequestErrors=%d want 1", stats.RequestErrors.Load())
	}
}

// 头部上限内（60KB 头值 + pipeline 第二条）不受影响，两条请求均正常还原。
func TestHeaderGuardUnderLimitPasses(t *testing.T) {
	stats := &Stats{}
	h := &collectHandler{ch: make(chan *http.Request, 4)}
	pad := strings.Repeat("C", 60<<10)
	wire := "GET /big HTTP/1.1\r\nHost: h\r\nX-Pad: " + pad + "\r\n\r\n" +
		"GET /next HTTP/1.1\r\nHost: h\r\n\r\n"
	assembleRequestFlow(stats, h, []byte(wire))

	for i, want := range []string{"/big", "/next"} {
		select {
		case r := <-h.ch:
			if r.URL.Path != want {
				t.Errorf("req%d path=%s want %s", i, r.URL.Path, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("超时未收到 req%d (%s)", i, want)
		}
	}
	if !waitStreamClosed(stats, 1) {
		t.Fatal("流未按预期关闭")
	}
	if stats.RequestsParsed.Load() != 2 {
		t.Errorf("RequestsParsed=%d want 2", stats.RequestsParsed.Load())
	}
	if stats.RequestErrors.Load() != 0 {
		t.Errorf("RequestErrors=%d want 0", stats.RequestErrors.Load())
	}
}

// 非目标端口方向的流不会进入本工厂（过滤在抓包层），此处直接验证 flowMetaFrom 映射。
func TestFlowMetaFrom(t *testing.T) {
	nf := gopacket.NewFlow(layers.EndpointIPv4, net.ParseIP("192.0.2.1").To4(), net.ParseIP("192.0.2.2").To4())
	tf := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x30, 0x39}, []byte{0x1F, 0x90}) // 12345 → 8080
	m := flowMetaFrom(nf, tf)
	if m.SrcIP != "192.0.2.1" || m.DstIP != "192.0.2.2" || m.SrcPort != 12345 || m.DstPort != 8080 {
		t.Errorf("meta=%+v", m)
	}
}

// TestMalformedLongLivedStreamRemainsBoundedByMaxStreamConns 验证三条异常终止分支
// （ReadRequest 畸形、头部精确复核超限、captureBody 畸形 chunked）均同步排空 rs，
// 在对端 FIN/空闲冲刷前持续占用 MaxStreamConns 名额，避免异常长连接逃逸并发上限。
func TestMalformedLongLivedStreamRemainsBoundedByMaxStreamConns(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{
			name:    "malformed_request_line",
			payload: "NOT_VALID_HTTP\r\n\r\n",
		},
		{
			name:    "header_precise_recheck_over_limit",
			payload: "GET / HTTP/1.1\r\nHost: h\r\nX-Pad: " + strings.Repeat("B", 70<<10) + "\r\n\r\n",
		},
		{
			name:    "malformed_chunked_body",
			payload: "POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\nZZZZ\r\n",
		},
	}

	cliIP, srvIP := net.ParseIP("10.3.0.10").To4(), net.ParseIP("10.3.0.20").To4()
	flow := gopacket.NewFlow(layers.EndpointIPv4, cliIP, srvIP)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stats := &Stats{}
			h := &collectHandler{ch: make(chan *http.Request, 4)}
			pool := tcpassembly.NewStreamPool(NewStreamFactory(h, 65536, 1, stats))
			asm := tcpassembly.NewAssembler(pool)
			now := time.Now()

			// 流 1：发送异常载荷但不发 FIN（模拟长连接保持打开）
			const base1 = uint32(7000)
			bad := []byte(tc.payload)
			asm.AssembleWithTimestamp(flow, tcpPacket(31001, 8080, base1, true, false, false, nil), now)
			asm.AssembleWithTimestamp(flow, tcpPacket(31001, 8080, base1+1, false, true, false, bad), now.Add(time.Millisecond))

			// 等待解析错误已触发并进入同步排空
			deadline := time.Now().Add(2 * time.Second)
			for stats.RequestErrors.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if stats.RequestErrors.Load() != 1 {
				t.Fatalf("RequestErrors=%d want 1", stats.RequestErrors.Load())
			}
			if stats.StreamsClosed.Load() != 0 {
				t.Fatalf("StreamsClosed=%d want 0（未 FIN 前异常流应仍占名额）", stats.StreamsClosed.Load())
			}

			// 流 2：在流 1 尚未 FIN 时打开，应因 MaxStreamConns=1 被拒绝
			const base2 = uint32(8000)
			okReq := []byte("GET /blocked HTTP/1.1\r\nHost: h\r\n\r\n")
			asm.AssembleWithTimestamp(flow, tcpPacket(31002, 8080, base2, true, false, false, nil), now.Add(2*time.Millisecond))
			asm.AssembleWithTimestamp(flow, tcpPacket(31002, 8080, base2+1, false, true, false, okReq), now.Add(3*time.Millisecond))
			asm.AssembleWithTimestamp(flow, tcpPacket(31002, 8080, base2+1+uint32(len(okReq)), false, true, true, nil), now.Add(4*time.Millisecond))
			if stats.StreamsRejected.Load() != 1 {
				t.Fatalf("StreamsRejected=%d want 1", stats.StreamsRejected.Load())
			}

			// 给流 1 发送 FIN：同步排空收到 EOF 后释放名额
			asm.AssembleWithTimestamp(flow, tcpPacket(31001, 8080, base1+1+uint32(len(bad)), false, true, true, nil), now.Add(5*time.Millisecond))
			if !waitStreamClosed(stats, 1) {
				t.Fatal("流 1 在 FIN 后未关闭")
			}

			// 流 3：名额释放后可正常解析
			const base3 = uint32(9000)
			goodReq := []byte("GET /after-release HTTP/1.1\r\nHost: h\r\n\r\n")
			asm.AssembleWithTimestamp(flow, tcpPacket(31003, 8080, base3, true, false, false, nil), now.Add(6*time.Millisecond))
			asm.AssembleWithTimestamp(flow, tcpPacket(31003, 8080, base3+1, false, true, false, goodReq), now.Add(7*time.Millisecond))
			asm.AssembleWithTimestamp(flow, tcpPacket(31003, 8080, base3+1+uint32(len(goodReq)), false, true, true, nil), now.Add(8*time.Millisecond))

			select {
			case r := <-h.ch:
				if r.URL.Path != "/after-release" {
					t.Fatalf("got %s, want /after-release", r.URL.Path)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("流 1 释放后流 3 未被解析")
			}
			if !waitStreamClosed(stats, 2) {
				t.Fatal("流 3 未关闭")
			}
		})
	}
}
