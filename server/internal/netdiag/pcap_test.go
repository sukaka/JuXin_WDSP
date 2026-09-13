// pcap_test.go pcap 解析器单元测试：合成 pcap 字节流覆盖
// TCP（flags/端口/preview）、UDP、ICMP、IPv6、VLAN、非 IP ethertype、
// 截断/畸形包跳过、200 包上限截断、非法 magic、大小端两种端序。
package netdiag

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// pcapBuilder 合成 pcap 字节流。
type pcapBuilder struct {
	buf   bytes.Buffer
	order binary.ByteOrder
}

func newPcap(t *testing.T, order binary.ByteOrder) *pcapBuilder {
	t.Helper()
	b := &pcapBuilder{order: order}
	magic := uint32(0xa1b2c3d4) // 微秒变体；端序由写入序决定
	hdr := make([]byte, pcapGlobalHeaderLen)
	order.PutUint32(hdr[0:4], magic)
	order.PutUint16(hdr[4:6], 2)     // version major
	order.PutUint16(hdr[6:8], 4)     // version minor
	order.PutUint32(hdr[16:20], 128) // snaplen（对齐 tcpdump -s 128）
	order.PutUint32(hdr[20:24], linkTypeEthernet)
	b.buf.Write(hdr)
	return b
}

// add 追加一个包记录（frame 为捕获数据，origLen 为线原始长度）。
func (b *pcapBuilder) add(tsSec, tsUsec uint32, frame []byte, origLen int) *pcapBuilder {
	rec := make([]byte, pcapRecordHeaderLen)
	b.order.PutUint32(rec[0:4], tsSec)
	b.order.PutUint32(rec[4:8], tsUsec)
	b.order.PutUint32(rec[8:12], uint32(len(frame)))
	b.order.PutUint32(rec[12:16], uint32(origLen))
	b.buf.Write(rec)
	b.buf.Write(frame)
	return b
}

// addRaw 追加原始记录（用于构造截断文件尾）。
func (b *pcapBuilder) addRaw(tsSec, tsUsec uint32, inclLen, origLen uint32, frame []byte) *pcapBuilder {
	rec := make([]byte, pcapRecordHeaderLen)
	b.order.PutUint32(rec[0:4], tsSec)
	b.order.PutUint32(rec[4:8], tsUsec)
	b.order.PutUint32(rec[8:12], inclLen)
	b.order.PutUint32(rec[12:16], origLen)
	b.buf.Write(rec)
	b.buf.Write(frame)
	return b
}

func (b *pcapBuilder) bytes() []byte { return b.buf.Bytes() }

var (
	testSrcMAC = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	testDstMAC = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
)

// ethFrame 构造 Ethernet II 帧。
func ethFrame(etherType uint16, payload []byte) []byte {
	f := make([]byte, 14, 14+len(payload))
	copy(f[0:6], testDstMAC)
	copy(f[6:12], testSrcMAC)
	binary.BigEndian.PutUint16(f[12:14], etherType)
	return append(f, payload...)
}

// vlanFrame 构造带 802.1Q tag 的帧。
func vlanFrame(vlanID uint16, innerType uint16, payload []byte) []byte {
	tag := make([]byte, 4)
	binary.BigEndian.PutUint16(tag[0:2], vlanID)
	binary.BigEndian.PutUint16(tag[2:4], innerType)
	return ethFrame(0x8100, append(tag, payload...))
}

// ipv4Packet 构造 IPv4 包（无选项）。
func ipv4Packet(protoNum byte, src, dst [4]byte, transport []byte) []byte {
	p := make([]byte, 20, 20+len(transport))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(20+len(transport)))
	p[8] = 64
	p[9] = protoNum
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	return append(p, transport...)
}

// ipv6Packet 构造 IPv6 包（无扩展头）。
func ipv6Packet(next byte, src, dst [16]byte, transport []byte) []byte {
	p := make([]byte, 40, 40+len(transport))
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], uint16(len(transport)))
	p[6] = next
	p[7] = 64
	copy(p[8:24], src[:])
	copy(p[24:40], dst[:])
	return append(p, transport...)
}

// tcpSegment 构造 TCP 段（无选项，data offset=5）。
func tcpSegment(sport, dport uint16, flags byte, payload []byte) []byte {
	s := make([]byte, 20, 20+len(payload))
	binary.BigEndian.PutUint16(s[0:2], sport)
	binary.BigEndian.PutUint16(s[2:4], dport)
	s[12] = 5 << 4
	s[13] = flags
	return append(s, payload...)
}

// udpDatagram 构造 UDP 报文。
func udpDatagram(sport, dport uint16, payload []byte) []byte {
	d := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(d[0:2], sport)
	binary.BigEndian.PutUint16(d[2:4], dport)
	binary.BigEndian.PutUint16(d[4:6], uint16(8+len(payload)))
	return append(d, payload...)
}

// icmpMessage 构造 ICMP 消息（8 字节头 + payload）。
func icmpMessage(typ, code byte, payload []byte) []byte {
	m := make([]byte, 8, 8+len(payload))
	m[0], m[1] = typ, code
	return append(m, payload...)
}

func mustParse(t *testing.T, data []byte) ([]CapturePacket, bool) {
	t.Helper()
	pkts, truncated, err := ParsePcap(data)
	if err != nil {
		t.Fatalf("ParsePcap: %v", err)
	}
	return pkts, truncated
}

// TestParseTCPPacket TCP：端口/flags 顺序/payload 可打印预览/时间戳格式。
func TestParseTCPPacket(t *testing.T) {
	payload := []byte("GET /api/orders HTTP/1.1\r\nHost: example.com\r\n\r\n")
	frame := ethFrame(0x0800, ipv4Packet(6, [4]byte{172, 19, 0, 1}, [4]byte{172, 19, 0, 2},
		tcpSegment(52344, 8080, 0x12, payload))) // SYN+ACK
	b := newPcap(t, binary.LittleEndian).add(1700000000, 123456, frame, 74)

	pkts, truncated := mustParse(t, b.bytes())
	if truncated || len(pkts) != 1 {
		t.Fatalf("应解析 1 包不截断: len=%d truncated=%v", len(pkts), truncated)
	}
	p := pkts[0]
	if p.No != 1 || p.Proto != "TCP" || p.Flags != "SYN,ACK" {
		t.Fatalf("基础字段不符: %+v", p)
	}
	if p.Src != "172.19.0.1" || p.Dst != "172.19.0.2" {
		t.Fatalf("地址不符: %+v", p)
	}
	if p.Sport == nil || *p.Sport != 52344 || p.Dport == nil || *p.Dport != 8080 {
		t.Fatalf("端口不符: %+v", p)
	}
	if p.Length != 74 {
		t.Fatalf("length 应为 orig_len=74，实际 %d", p.Length)
	}
	if p.Ts != "2023-11-14T22:13:20.123456Z" {
		t.Fatalf("ts 应为 RFC3339 微秒格式，实际 %q", p.Ts)
	}
	if !strings.HasPrefix(p.Preview, "GET /api/orders HTTP/1.1") {
		t.Fatalf("preview 不符: %q", p.Preview)
	}
	// 非可打印字节（CR/LF）应替换为 .
	if strings.ContainsAny(p.Preview, "\r\n") {
		t.Fatalf("preview 不应含非可打印字节: %q", p.Preview)
	}
}

// TestParseTCPFlagsOrder flags 按 FIN,SYN,RST,PSH,ACK,URG,ECE,CWR 顺序输出。
func TestParseTCPFlagsOrder(t *testing.T) {
	frame := ethFrame(0x0800, ipv4Packet(6, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2},
		tcpSegment(1, 2, 0xff, nil)))
	pkts, _ := mustParse(t, newPcap(t, binary.LittleEndian).add(1700000000, 0, frame, 54).bytes())
	if pkts[0].Flags != "FIN,SYN,RST,PSH,ACK,URG,ECE,CWR" {
		t.Fatalf("flags 顺序不符: %q", pkts[0].Flags)
	}
}

// TestParseUDPPacket UDP：端口 + payload 预览。
func TestParseUDPPacket(t *testing.T) {
	frame := ethFrame(0x0800, ipv4Packet(17, [4]byte{10, 0, 0, 1}, [4]byte{8, 8, 8, 8},
		udpDatagram(5353, 53, []byte("dns-query"))))
	pkts, _ := mustParse(t, newPcap(t, binary.LittleEndian).add(1700000000, 0, frame, 51).bytes())
	p := pkts[0]
	if p.Proto != "UDP" || p.Sport == nil || *p.Sport != 5353 || p.Dport == nil || *p.Dport != 53 {
		t.Fatalf("UDP 字段不符: %+v", p)
	}
	if p.Flags != "" {
		t.Fatalf("UDP 不应有 flags: %q", p.Flags)
	}
	if p.Preview != "dns-query" {
		t.Fatalf("preview 不符: %q", p.Preview)
	}
}

// TestParseICMPPacket ICMP：无端口（sport/dport 为 null）。
func TestParseICMPPacket(t *testing.T) {
	frame := ethFrame(0x0800, ipv4Packet(1, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2},
		icmpMessage(8, 0, []byte("ping-payload"))))
	pkts, _ := mustParse(t, newPcap(t, binary.LittleEndian).add(1700000000, 0, frame, 60).bytes())
	p := pkts[0]
	if p.Proto != "ICMP" || p.Sport != nil || p.Dport != nil {
		t.Fatalf("ICMP 字段不符（端口应为 nil）: %+v", p)
	}
	if p.Preview != "ping-payload" {
		t.Fatalf("ICMP preview 不符: %q", p.Preview)
	}
}

// TestParseIPv6Packet IPv6 TCP：地址/端口/preview。
func TestParseIPv6Packet(t *testing.T) {
	var src, dst [16]byte
	src[15] = 1 // ::1
	dst[15] = 2 // ::2
	frame := ethFrame(0x86dd, ipv6Packet(6, src, dst, tcpSegment(443, 9000, 0x10, []byte("v6-data"))))
	pkts, _ := mustParse(t, newPcap(t, binary.LittleEndian).add(1700000000, 0, frame, 81).bytes())
	p := pkts[0]
	if p.Proto != "TCP" || p.Src != "::1" || p.Dst != "::2" {
		t.Fatalf("IPv6 字段不符: %+v", p)
	}
	if p.Flags != "ACK" || p.Preview != "v6-data" {
		t.Fatalf("IPv6 传输层不符: %+v", p)
	}
}

// TestParseICMPv6 ICMPv6：无端口。
func TestParseICMPv6(t *testing.T) {
	var src, dst [16]byte
	src[15] = 1
	dst[15] = 2
	frame := ethFrame(0x86dd, ipv6Packet(58, src, dst, icmpMessage(128, 0, []byte("v6ping"))))
	pkts, _ := mustParse(t, newPcap(t, binary.LittleEndian).add(1700000000, 0, frame, 68).bytes())
	p := pkts[0]
	if p.Proto != "ICMPv6" || p.Sport != nil || p.Preview != "v6ping" {
		t.Fatalf("ICMPv6 字段不符: %+v", p)
	}
}

// TestParseVLANTagged 802.1Q VLAN tag 跳过。
func TestParseVLANTagged(t *testing.T) {
	frame := vlanFrame(100, 0x0800, ipv4Packet(6, [4]byte{192, 168, 1, 1}, [4]byte{192, 168, 1, 2},
		tcpSegment(80, 12345, 0x02, nil)))
	pkts, _ := mustParse(t, newPcap(t, binary.LittleEndian).add(1700000000, 0, frame, 58).bytes())
	p := pkts[0]
	if p.Proto != "TCP" || p.Src != "192.168.1.1" || p.Flags != "SYN" {
		t.Fatalf("VLAN 帧解码不符: %+v", p)
	}
}

// TestParseNonIPEthertype 非 IP ethertype → ETH-0x<hex> + MAC 地址。
func TestParseNonIPEthertype(t *testing.T) {
	frame := ethFrame(0x0806, []byte("arp-payload"))
	pkts, _ := mustParse(t, newPcap(t, binary.LittleEndian).add(1700000000, 0, frame, 25).bytes())
	p := pkts[0]
	if p.Proto != "ETH-0x0806" {
		t.Fatalf("proto 应为 ETH-0x0806，实际 %q", p.Proto)
	}
	if p.Src != "02:00:00:00:00:01" || p.Dst != "02:00:00:00:00:02" {
		t.Fatalf("MAC 地址不符: %+v", p)
	}
	if p.Sport != nil || p.Preview != "arp-payload" {
		t.Fatalf("非 IP 包字段不符: %+v", p)
	}
}

// TestParseOtherIPProto 其他 IP 协议 → IP-<num>。
func TestParseOtherIPProto(t *testing.T) {
	frame := ethFrame(0x0800, ipv4Packet(47, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, []byte("gre")))
	pkts, _ := mustParse(t, newPcap(t, binary.LittleEndian).add(1700000000, 0, frame, 37).bytes())
	if pkts[0].Proto != "IP-47" {
		t.Fatalf("proto 应为 IP-47，实际 %q", pkts[0].Proto)
	}
}

// TestParseSkipsMalformed 畸形包跳过不报错，后续正常包继续解析。
func TestParseSkipsMalformed(t *testing.T) {
	b := newPcap(t, binary.LittleEndian)
	b.add(1700000000, 0, []byte{0x01, 0x02, 0x03}, 3) // 不足以太头 → 跳过
	good := ethFrame(0x0800, ipv4Packet(17, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2},
		udpDatagram(1, 2, []byte("ok"))))
	b.add(1700000001, 0, good, 44)
	pkts, truncated := mustParse(t, b.bytes())
	if truncated || len(pkts) != 1 {
		t.Fatalf("畸形包应跳过，实际 len=%d", len(pkts))
	}
	if pkts[0].No != 1 || pkts[0].Proto != "UDP" {
		t.Fatalf("剩余包序号/内容不符: %+v", pkts[0])
	}
}

// TestParseTruncatedFileTail 文件尾部记录截断 → 已解析部分正常返回不报错。
func TestParseTruncatedFileTail(t *testing.T) {
	good := ethFrame(0x0800, ipv4Packet(17, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2},
		udpDatagram(1, 2, []byte("ok"))))
	b := newPcap(t, binary.LittleEndian).add(1700000000, 0, good, 44)
	// 记录头声明 incl_len=100 但文件只有 10 字节数据 → 尾部截断
	b.addRaw(1700000001, 0, 100, 100, []byte("0123456789"))
	pkts, truncated := mustParse(t, b.bytes())
	if truncated || len(pkts) != 1 {
		t.Fatalf("尾部截断应保留已解析包: len=%d truncated=%v", len(pkts), truncated)
	}
}

// TestParseMaxPackets 超过 200 包 → 返回前 200 个并标记 truncated。
func TestParseMaxPackets(t *testing.T) {
	frame := ethFrame(0x0800, ipv4Packet(17, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2},
		udpDatagram(1, 2, []byte("x"))))
	b := newPcap(t, binary.LittleEndian)
	for i := 0; i < MaxCapturePackets+50; i++ {
		b.add(1700000000+uint32(i), 0, frame, 43)
	}
	pkts, truncated := mustParse(t, b.bytes())
	if !truncated {
		t.Fatal("超过 200 包应标记 truncated")
	}
	if len(pkts) != MaxCapturePackets {
		t.Fatalf("应返回前 %d 包，实际 %d", MaxCapturePackets, len(pkts))
	}
	if pkts[MaxCapturePackets-1].No != MaxCapturePackets {
		t.Fatalf("序号不符: %+v", pkts[MaxCapturePackets-1])
	}
}

// TestParseExactlyMaxPackets 恰好 200 包不标记截断。
func TestParseExactlyMaxPackets(t *testing.T) {
	frame := ethFrame(0x0800, ipv4Packet(17, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2},
		udpDatagram(1, 2, []byte("x"))))
	b := newPcap(t, binary.LittleEndian)
	for i := 0; i < MaxCapturePackets; i++ {
		b.add(1700000000+uint32(i), 0, frame, 43)
	}
	_, truncated := mustParse(t, b.bytes())
	if truncated {
		t.Fatal("恰好 200 包不应标记截断")
	}
}

// TestParseBadMagic 非法 magic / 过短全局头 → error。
func TestParseBadMagic(t *testing.T) {
	if _, _, err := ParsePcap([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatal("过短全局头应报错")
	}
	bad := make([]byte, pcapGlobalHeaderLen)
	binary.BigEndian.PutUint32(bad[:4], 0xdeadbeef)
	if _, _, err := ParsePcap(bad); err == nil {
		t.Fatal("非法 magic 应报错")
	}
	// 非 Ethernet 链路类型应报错
	raw := newPcap(t, binary.LittleEndian).bytes()
	binary.LittleEndian.PutUint32(raw[20:24], 113) // Linux cooked
	if _, _, err := ParsePcap(raw); err == nil {
		t.Fatal("非 Ethernet linktype 应报错")
	}
}

// TestParseBothEndians 大小端两种 magic 解码结果一致。
func TestParseBothEndians(t *testing.T) {
	frame := ethFrame(0x0800, ipv4Packet(6, [4]byte{172, 19, 0, 1}, [4]byte{172, 19, 0, 2},
		tcpSegment(52344, 8080, 0x18, []byte("hello")))) // PSH+ACK
	for name, order := range map[string]binary.ByteOrder{"little": binary.LittleEndian, "big": binary.BigEndian} {
		t.Run(name, func(t *testing.T) {
			pkts, truncated := mustParse(t, newPcap(t, order).add(1700000000, 500, frame, 59).bytes())
			if truncated || len(pkts) != 1 {
				t.Fatalf("应解析 1 包: len=%d", len(pkts))
			}
			p := pkts[0]
			if p.Proto != "TCP" || p.Flags != "PSH,ACK" || p.Preview != "hello" || p.Ts != "2023-11-14T22:13:20.000500Z" {
				t.Fatalf("%s 端序解码不符: %+v", name, p)
			}
		})
	}
}

// TestParsePreviewTruncation preview 截断 80 字符。
func TestParsePreviewTruncation(t *testing.T) {
	payload := []byte(strings.Repeat("A", 200))
	frame := ethFrame(0x0800, ipv4Packet(17, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2},
		udpDatagram(1, 2, payload)))
	pkts, _ := mustParse(t, newPcap(t, binary.LittleEndian).add(1700000000, 0, frame, 200).bytes())
	if len(pkts[0].Preview) != capturePreviewMaxLen {
		t.Fatalf("preview 应截断 %d 字符，实际 %d", capturePreviewMaxLen, len(pkts[0].Preview))
	}
}

// TestParseEmptyCapture 无包 pcap → 空数组不报错。
func TestParseEmptyCapture(t *testing.T) {
	pkts, truncated := mustParse(t, newPcap(t, binary.LittleEndian).bytes())
	if truncated || len(pkts) != 0 {
		t.Fatalf("空 pcap 应返回空列表: len=%d truncated=%v", len(pkts), truncated)
	}
	if pkts == nil {
		t.Fatal("空结果应是非 nil 切片（JSON 序列化为 []）")
	}
}
