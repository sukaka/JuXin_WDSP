// 站点资产被动发现测试：协议分类、聚合/去重/上限、JSONL 落盘契约、嗅探分支、并发安全。
package mirrorcap

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// newTestAggregator 测试聚合器：临时目录输出、长周期（不自动落盘，测试显式 flush）。
func newTestAggregator(t *testing.T, mode string) *DiscoveryAggregator {
	t.Helper()
	agg, err := NewDiscoveryAggregator("gw-test", mode, filepath.Join(t.TempDir(), "site-discovery.jsonl"), time.Hour, &Stats{})
	if err != nil {
		t.Fatalf("NewDiscoveryAggregator: %v", err)
	}
	t.Cleanup(func() { _ = agg.Close() })
	return agg
}

// readDiscoveryRecords 读取 JSONL 全部记录（逐行必须是合法 JSON）。
func readDiscoveryRecords(t *testing.T, path string) []DiscoveryRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取发现日志: %v", err)
	}
	var out []DiscoveryRecord
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var rec DiscoveryRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("发现记录行非 JSON: %v", err)
		}
		out = append(out, rec)
	}
	return out
}

// ---------- 协议分类 ----------

func TestClassifyFlowHead(t *testing.T) {
	cases := []struct {
		name string
		head string
		want string
	}{
		{"GET", "GET / HTTP/1.1\r\n", protoHTTP},
		{"POST", "POST /submit HTTP/1.0\r\n", protoHTTP},
		{"CONNECT", "CONNECT example.com:443 HTTP/1.1\r\n", protoHTTP},
		{"PATCH", "PATCH /a HTTP/1.1\r\n", protoHTTP},
		{"TLS12", "\x16\x03\x01\x00\x2f", protoHTTPS},
		{"TLS13", "\x16\x03\x03\x00\x2f", protoHTTPS},
		{"HTTP响应行不识别", "HTTP/1.1 200 OK\r\n", ""},
		{"SSH不识别", "SSH-2.0-OpenSSH_9\r\n", ""},
		{"二进制不识别", "\x00\x01\x02\x03", ""},
		{"空流", "", ""},
		{"单字节", "G", ""},
		{"类GET但非方法", "GETTING /x", ""}, // 方法前缀必须带空格
	}
	for _, c := range cases {
		if got := classifyFlowHead([]byte(c.head)); got != c.want {
			t.Errorf("%s: classifyFlowHead=%q want %q", c.name, got, c.want)
		}
	}
}

// ---------- 聚合器 ----------

// 聚合去重与 hits 累计、flush 输出 JSON 行契约（字段名/取值逐一断言）。
func TestDiscoveryAggregatorFlushContract(t *testing.T) {
	agg := newTestAggregator(t, "MIRROR")
	meta1 := FlowMeta{SrcIP: "10.1.0.1", SrcPort: 50001, DstIP: "10.0.0.5", DstPort: 443}
	meta2 := FlowMeta{SrcIP: "10.1.0.2", SrcPort: 50002, DstIP: "10.0.0.5", DstPort: 443}

	agg.Observe("Example.COM ", meta1, protoHTTPS) // 域名小写归一、去空白
	agg.Observe("example.com", meta1, protoHTTPS)  // 同客户端重复：hits 计、集合不扩
	agg.Observe("example.com", meta2, protoHTTPS)
	agg.Observe("", FlowMeta{SrcIP: "10.1.0.9", SrcPort: 50003, DstIP: "10.0.0.6", DstPort: 8080}, protoHTTP)

	if err := agg.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	recs := readDiscoveryRecords(t, agg.path)
	if len(recs) != 2 {
		t.Fatalf("记录数=%d want 2", len(recs))
	}
	// 键序稳定：domain 空串排前
	r0, r1 := recs[0], recs[1]
	if r0.Type != recordTypeSiteDiscovery || r1.Type != recordTypeSiteDiscovery {
		t.Errorf("type 字段必须恒为 site_discovery: %q %q", r0.Type, r1.Type)
	}
	// r0: 未识别域名 HTTP 资产
	if r0.Domain != "" || r0.IP != "10.0.0.6" || r0.Port != 8080 || r0.Protocol != protoHTTP {
		t.Errorf("r0=%+v", r0)
	}
	if r0.Hits != 1 || r0.ClientCount != 1 {
		t.Errorf("r0 hits=%d client_count=%d want 1/1", r0.Hits, r0.ClientCount)
	}
	// r1: 去重聚合
	if r1.Domain != "example.com" || r1.IP != "10.0.0.5" || r1.Port != 443 || r1.Protocol != protoHTTPS {
		t.Errorf("r1=%+v", r1)
	}
	if r1.Hits != 3 || r1.ClientCount != 2 {
		t.Errorf("r1 hits=%d client_count=%d want 3/2（去重客户端）", r1.Hits, r1.ClientCount)
	}
	for i, r := range recs {
		if r.Node != "gw-test" || r.SourceMode != "MIRROR" {
			t.Errorf("rec[%d] node=%q source_mode=%q", i, r.Node, r.SourceMode)
		}
		ws, err := time.Parse(time.RFC3339, r.WindowStart)
		if err != nil {
			t.Fatalf("rec[%d] window_start 非 RFC3339: %v", i, err)
		}
		we, err := time.Parse(time.RFC3339, r.WindowEnd)
		if err != nil {
			t.Fatalf("rec[%d] window_end 非 RFC3339: %v", i, err)
		}
		if we.Before(ws) {
			t.Errorf("rec[%d] window_end < window_start", i)
		}
	}
}

// flush 重置窗口：无新观察时第二次 flush 不产生新行。
func TestDiscoveryAggregatorFlushResetsWindow(t *testing.T) {
	agg := newTestAggregator(t, "MIRROR")
	agg.Observe("a.com", FlowMeta{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", DstPort: 80}, protoHTTP)
	if err := agg.flush(); err != nil {
		t.Fatalf("flush1: %v", err)
	}
	if err := agg.flush(); err != nil {
		t.Fatalf("flush2: %v", err)
	}
	recs := readDiscoveryRecords(t, agg.path)
	if len(recs) != 1 {
		t.Fatalf("空窗口不应产出记录, got %d", len(recs))
	}
	// 新观察进入新窗口
	agg.Observe("a.com", FlowMeta{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", DstPort: 80}, protoHTTP)
	if err := agg.flush(); err != nil {
		t.Fatalf("flush3: %v", err)
	}
	recs = readDiscoveryRecords(t, agg.path)
	if len(recs) != 2 || recs[1].Hits != 1 {
		t.Fatalf("新窗口应独立计数, got %+v", recs)
	}
}

// 客户端集合上限：超 maxDiscoveryClients 后只计 hits 不再扩集合。
func TestDiscoveryAggregatorClientCap(t *testing.T) {
	agg := newTestAggregator(t, "MIRROR")
	meta := FlowMeta{DstIP: "10.0.0.5", DstPort: 443}
	for i := 0; i < maxDiscoveryClients+500; i++ {
		meta.SrcIP = fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)
		agg.Observe("hot.example.com", meta, protoHTTPS)
	}
	if err := agg.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	recs := readDiscoveryRecords(t, agg.path)
	if len(recs) != 1 {
		t.Fatalf("记录数=%d want 1", len(recs))
	}
	if recs[0].ClientCount != maxDiscoveryClients {
		t.Errorf("client_count=%d want %d（集合上限）", recs[0].ClientCount, maxDiscoveryClients)
	}
	if recs[0].Hits != uint64(maxDiscoveryClients+500) {
		t.Errorf("hits=%d want %d（超限后 hits 照计）", recs[0].Hits, maxDiscoveryClients+500)
	}
}

// 窗口键总数上限：随机域名洪泛超 maxDiscoveryKeys 后新键丢弃（已有键照计 hits）。
func TestDiscoveryAggregatorKeyCap(t *testing.T) {
	stats := &Stats{}
	agg, err := NewDiscoveryAggregator("gw-test", "MIRROR", filepath.Join(t.TempDir(), "site-discovery.jsonl"), time.Hour, stats)
	if err != nil {
		t.Fatalf("NewDiscoveryAggregator: %v", err)
	}
	t.Cleanup(func() { _ = agg.Close() })

	meta := FlowMeta{SrcIP: "10.1.0.1", DstIP: "10.0.0.5", DstPort: 443}
	for i := 0; i < maxDiscoveryKeys+500; i++ {
		agg.Observe(fmt.Sprintf("flood-%d.example.com", i), meta, protoHTTPS)
	}
	// 已有键超限后仍正常聚合
	agg.Observe("flood-0.example.com", meta, protoHTTPS)

	if err := agg.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	recs := readDiscoveryRecords(t, agg.path)
	if len(recs) != maxDiscoveryKeys {
		t.Fatalf("记录数=%d want %d（窗口键总数上限）", len(recs), maxDiscoveryKeys)
	}
	if stats.DiscoveryKeysDropped.Load() != 500 {
		t.Errorf("DiscoveryKeysDropped=%d want 500", stats.DiscoveryKeysDropped.Load())
	}
	var first *DiscoveryRecord
	for i := range recs {
		if recs[i].Domain == "flood-0.example.com" {
			first = &recs[i]
		}
	}
	if first == nil || first.Hits != 2 {
		t.Errorf("已有键超限后应照计 hits: %+v", first)
	}
}

// 并发 Observe：计数不丢不错（-race 下验证互斥）。
func TestDiscoveryAggregatorConcurrentObserve(t *testing.T) {
	agg := newTestAggregator(t, "ROUTED")
	const workers = 8
	const per = 250
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			meta := FlowMeta{SrcIP: fmt.Sprintf("192.168.0.%d", w+1), DstIP: "10.9.0.1", DstPort: 443}
			for i := 0; i < per; i++ {
				agg.Observe("concurrent.example.com", meta, protoHTTPS)
			}
		}(w)
	}
	wg.Wait()
	if err := agg.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	recs := readDiscoveryRecords(t, agg.path)
	if len(recs) != 1 {
		t.Fatalf("记录数=%d want 1", len(recs))
	}
	if recs[0].Hits != workers*per {
		t.Errorf("hits=%d want %d（并发不丢计）", recs[0].Hits, workers*per)
	}
	if recs[0].ClientCount != workers {
		t.Errorf("client_count=%d want %d", recs[0].ClientCount, workers)
	}
	if recs[0].SourceMode != "ROUTED" {
		t.Errorf("source_mode=%q want ROUTED（聚合器默认 mode）", recs[0].SourceMode)
	}
}

// 嗅探器显式 mode：覆盖聚合器默认（per-接口 mode 映射）。
func TestDiscoverySnifferModeOverride(t *testing.T) {
	agg := newTestAggregator(t, "MIRROR")
	sniff := newDiscoverySniffer(agg, "ROUTED")
	sniff.Sniff(strings.NewReader("GET / HTTP/1.1\r\nHost: routed.example.com\r\n\r\n"),
		FlowMeta{SrcIP: "10.0.0.1", SrcPort: 40000, DstIP: "10.0.0.2", DstPort: 8080})
	if err := agg.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	recs := readDiscoveryRecords(t, agg.path)
	if len(recs) != 1 || recs[0].SourceMode != "ROUTED" {
		t.Fatalf("source_mode 应按接口 mode 记 ROUTED: %+v", recs)
	}
}

// ---------- 嗅探分支 ----------

// HTTP 流：取 Host（去端口小写）记录；流剩余内容被排空。
func TestSniffHTTP(t *testing.T) {
	agg := newTestAggregator(t, "MIRROR")
	sniff := newDiscoverySniffer(agg, "MIRROR")
	rs := strings.NewReader("GET /index HTTP/1.1\r\nHost: Example.COM:8080\r\n\r\nREST-BYTES")
	sniff.Sniff(rs, FlowMeta{SrcIP: "172.16.0.10", SrcPort: 51000, DstIP: "172.16.0.20", DstPort: 8080})
	if rs.Len() != 0 {
		t.Errorf("嗅探后流应被排空, 剩 %d 字节", rs.Len())
	}
	if err := agg.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	recs := readDiscoveryRecords(t, agg.path)
	if len(recs) != 1 {
		t.Fatalf("记录数=%d want 1", len(recs))
	}
	r := recs[0]
	if r.Domain != "example.com" || r.Protocol != protoHTTP || r.IP != "172.16.0.20" || r.Port != 8080 {
		t.Errorf("rec=%+v", r)
	}
}

// TLS 流：ClientHello 取 SNI 记录。
func TestSniffTLSWithSNI(t *testing.T) {
	agg := newTestAggregator(t, "MIRROR")
	sniff := newDiscoverySniffer(agg, "MIRROR")
	wire := wrapClientHello(buildClientHelloBody("api.example.com", true), 0x03, 0)
	sniff.Sniff(strings.NewReader(string(wire)), FlowMeta{SrcIP: "10.0.0.1", SrcPort: 40000, DstIP: "10.0.0.2", DstPort: 443})
	if err := agg.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	recs := readDiscoveryRecords(t, agg.path)
	if len(recs) != 1 {
		t.Fatalf("记录数=%d want 1", len(recs))
	}
	if recs[0].Domain != "api.example.com" || recs[0].Protocol != protoHTTPS || recs[0].Port != 443 {
		t.Errorf("rec=%+v", recs[0])
	}
}

// TLS 流无 SNI（合法 ClientHello）：domain 空串仍记录（IP:Port 资产）。
func TestSniffTLSNoSNI(t *testing.T) {
	agg := newTestAggregator(t, "MIRROR")
	sniff := newDiscoverySniffer(agg, "MIRROR")
	wire := wrapClientHello(buildClientHelloBody("", true), 0x03, 0)
	sniff.Sniff(strings.NewReader(string(wire)), FlowMeta{SrcIP: "10.0.0.1", SrcPort: 40000, DstIP: "10.0.0.2", DstPort: 8443})
	if err := agg.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	recs := readDiscoveryRecords(t, agg.path)
	if len(recs) != 1 || recs[0].Domain != "" || recs[0].Protocol != protoHTTPS {
		t.Fatalf("无 SNI 应记空域名 HTTPS 记录: %+v", recs)
	}
}

// 响应方向流不产出记录：HTTP 状态行与 ServerHello 都不得污染发现结果。
func TestSniffResponseDirectionIgnored(t *testing.T) {
	agg := newTestAggregator(t, "MIRROR")
	sniff := newDiscoverySniffer(agg, "MIRROR")
	// HTTP 响应行
	sniff.Sniff(strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
		FlowMeta{SrcIP: "10.0.0.2", SrcPort: 80, DstIP: "10.0.0.1", DstPort: 40000})
	// TLS ServerHello（type=2）
	body := buildClientHelloBody("www.example.com", true)
	hs := append([]byte{0x02, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	serverHello := append([]byte{0x16, 0x03, 0x03, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	sniff.Sniff(strings.NewReader(string(serverHello)),
		FlowMeta{SrcIP: "10.0.0.2", SrcPort: 443, DstIP: "10.0.0.1", DstPort: 40001})
	if err := agg.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if recs := readDiscoveryRecords(t, agg.path); len(recs) != 0 {
		t.Fatalf("响应方向流不应产出记录, got %+v", recs)
	}
}

// 其他协议流：不记录且排空。
func TestSniffOtherProtocolDiscarded(t *testing.T) {
	agg := newTestAggregator(t, "MIRROR")
	sniff := newDiscoverySniffer(agg, "MIRROR")
	rs := strings.NewReader("SSH-2.0-OpenSSH_9.6\r\nmore-bytes")
	sniff.Sniff(rs, FlowMeta{SrcIP: "10.0.0.1", SrcPort: 40000, DstIP: "10.0.0.2", DstPort: 22})
	if rs.Len() != 0 {
		t.Errorf("未识别流应被排空, 剩 %d 字节", rs.Len())
	}
	if err := agg.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if recs := readDiscoveryRecords(t, agg.path); len(recs) != 0 {
		t.Fatalf("未识别协议不应产出记录, got %+v", recs)
	}
}

// 嗅探读取上限：超长首行 HTTP 流最多读 maxBytes，解析失败仍按空域名记录。
func TestSniffReadBounded(t *testing.T) {
	agg := newTestAggregator(t, "MIRROR")
	sniff := newDiscoverySniffer(agg, "MIRROR")
	sniff.maxBytes = 64 // 小上限便于验证
	rs := strings.NewReader("GET /" + strings.Repeat("a", 4096) + " HTTP/1.1\r\nHost: big.example.com\r\n\r\n")
	sniff.Sniff(rs, FlowMeta{SrcIP: "10.0.0.1", SrcPort: 40000, DstIP: "10.0.0.2", DstPort: 80})
	if err := agg.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	recs := readDiscoveryRecords(t, agg.path)
	if len(recs) != 1 || recs[0].Domain != "" || recs[0].Protocol != protoHTTP {
		t.Fatalf("超限截断应记空域名 HTTP 记录: %+v", recs)
	}
}

// ---------- 发现专用流工厂（端到端重组） ----------

// 合成四元组流经真实 tcpassembly 重组后，非检测端口流全部走嗅探分支产出记录。
func TestDiscoveryStreamFactoryEndToEnd(t *testing.T) {
	stats := &Stats{}
	agg := newTestAggregator(t, "MIRROR")
	sniff := newDiscoverySniffer(agg, "MIRROR")
	pool := tcpassembly.NewStreamPool(NewDiscoveryStreamFactory(sniff, 16, stats))
	asm := tcpassembly.NewAssembler(pool)

	cliIP, srvIP := net.ParseIP("10.2.0.10").To4(), net.ParseIP("10.2.0.20").To4()
	flow := gopacket.NewFlow(layers.EndpointIPv4, cliIP, srvIP)
	now := time.Now()

	const base = uint32(2000)
	wire := []byte("GET /hello HTTP/1.1\r\nHost: factory.example.com\r\n\r\n")
	asm.AssembleWithTimestamp(flow, tcpPacket(23456, 9090, base, true, false, false, nil), now)
	seq := base + 1
	// 乱边界切两片（SEQ 连续）
	for _, seg := range [][2]int{{0, 15}, {15, len(wire)}} {
		part := wire[seg[0]:seg[1]]
		asm.AssembleWithTimestamp(flow, tcpPacket(23456, 9090, seq, false, true, false, part), now.Add(time.Millisecond))
		seq += uint32(len(part))
	}
	asm.AssembleWithTimestamp(flow, tcpPacket(23456, 9090, seq, false, true, true, nil), now.Add(2*time.Millisecond))

	// 等流 goroutine 完成嗅探（FIN 触发 EOF）
	deadline := time.Now().Add(2 * time.Second)
	for stats.StreamsClosed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if stats.StreamsClosed.Load() != 1 {
		t.Fatalf("StreamsClosed=%d want 1", stats.StreamsClosed.Load())
	}
	if err := agg.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	recs := readDiscoveryRecords(t, agg.path)
	if len(recs) != 1 {
		t.Fatalf("记录数=%d want 1", len(recs))
	}
	r := recs[0]
	if r.Domain != "factory.example.com" || r.IP != "10.2.0.20" || r.Port != 9090 || r.Protocol != protoHTTP {
		t.Errorf("rec=%+v", r)
	}
}

// 复合工厂分流：命中检测端口的流走检测管线，其余走发现嗅探（双角色单句柄语义）。
func TestIfaceStreamFactoryDemux(t *testing.T) {
	stats := &Stats{}
	agg := newTestAggregator(t, "MIRROR")
	sniff := newDiscoverySniffer(agg, "MIRROR")
	detect := &collectHandler{ch: make(chan *http.Request, 4)}

	// 与生产一致的共享端口集合（atomic.Pointer 语义：SetPorts 热更新同源）
	ports := &atomic.Pointer[map[uint16]struct{}]{}
	portMap := map[uint16]struct{}{8080: {}}
	ports.Store(&portMap)
	pool := tcpassembly.NewStreamPool(newIfaceStreamFactory(IfaceConsumer{Detect: detect, Sniff: sniff}, ports, 65536, 16, stats))
	asm := tcpassembly.NewAssembler(pool)

	cliIP, srvIP := net.ParseIP("10.3.0.10").To4(), net.ParseIP("10.3.0.20").To4()
	now := time.Now()

	// 流 1：检测端口 8080 → 检测管线
	flow1 := gopacket.NewFlow(layers.EndpointIPv4, cliIP, srvIP)
	req := []byte("GET /detect HTTP/1.1\r\nHost: detect.example.com\r\n\r\n")
	asm.AssembleWithTimestamp(flow1, tcpPacket(30001, 8080, 1000, true, false, false, nil), now)
	asm.AssembleWithTimestamp(flow1, tcpPacket(30001, 8080, 1001, false, true, false, req), now.Add(time.Millisecond))
	asm.AssembleWithTimestamp(flow1, tcpPacket(30001, 8080, 1001+uint32(len(req)), false, true, true, nil), now.Add(2*time.Millisecond))

	// 流 2：非检测端口 443 → 发现嗅探
	flow2 := gopacket.NewFlow(layers.EndpointIPv4, cliIP, srvIP)
	tlsWire := wrapClientHello(buildClientHelloBody("sniff.example.com", true), 0x03, 0)
	asm.AssembleWithTimestamp(flow2, tcpPacket(30002, 443, 5000, true, false, false, nil), now)
	asm.AssembleWithTimestamp(flow2, tcpPacket(30002, 443, 5001, false, true, false, tlsWire), now.Add(time.Millisecond))
	asm.AssembleWithTimestamp(flow2, tcpPacket(30002, 443, 5001+uint32(len(tlsWire)), false, true, true, nil), now.Add(2*time.Millisecond))

	select {
	case r := <-detect.ch:
		if r.URL.Path != "/detect" {
			t.Errorf("检测流路径=%q want /detect", r.URL.Path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("超时未收到检测请求（端口分流失败）")
	}
	deadline := time.Now().Add(2 * time.Second)
	for stats.StreamsClosed.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if err := agg.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	recs := readDiscoveryRecords(t, agg.path)
	if len(recs) != 1 || recs[0].Domain != "sniff.example.com" || recs[0].Port != 443 {
		t.Fatalf("非检测端口流应走嗅探: %+v", recs)
	}
	if stats.RequestsParsed.Load() != 1 {
		t.Errorf("RequestsParsed=%d want 1（仅检测流解析 HTTP）", stats.RequestsParsed.Load())
	}
}
