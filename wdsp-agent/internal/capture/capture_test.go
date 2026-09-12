package capture

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/jiuzhang-waf/wdsp-agent/internal/filter"
)

// buildTCPPacket 用 gopacket 序列化构造合成 Ethernet/IPv4/TCP 包（跨平台可测）。
func buildTCPPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) gopacket.Packet {
	t.Helper()
	return buildTCPPacketFlags(t, srcIP, dstIP, srcPort, dstPort, payload, false, false)
}

// buildTCPPacketFlags 带 FIN/RST flags 的合成包。
func buildTCPPacketFlags(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, fin, rst bool) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1000, Window: 65535,
		FIN: fin, RST: rst,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	pkt.Metadata().Timestamp = time.Unix(1788256800, 0)
	pkt.Metadata().CaptureInfo.Length = len(buf.Bytes())
	pkt.Metadata().CaptureInfo.CaptureLength = len(buf.Bytes())
	return pkt
}

// buildUDPPacket 构造 UDP 包（应被过滤）。
func buildUDPPacket(t *testing.T) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: net.ParseIP("10.0.0.1").To4(), DstIP: net.ParseIP("10.0.0.2").To4(),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{SrcPort: 53, DstPort: 53}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, udp, gopacket.Payload([]byte("dns"))); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestDecodePacketDstPortHit(t *testing.T) {
	f := filter.New([]uint16{80, 443}, filter.Both)
	st := &Stats{}
	payload := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	pkt := buildTCPPacket(t, "10.1.1.10", "10.1.2.20", 51234, 80, payload)
	p, ok := DecodePacket(pkt, f, st)
	if !ok {
		t.Fatal("dst 端口命中应放行")
	}
	if !p.Ingress {
		t.Fatal("dst 命中应为 ingress")
	}
	if p.SrcIP != "10.1.1.10" || p.SrcPort != 51234 || p.DstIP != "10.1.2.20" || p.DstPort != 80 {
		t.Fatalf("五元组错误: %+v", p)
	}
	if string(p.Payload) != string(payload) {
		t.Fatalf("payload=%q", p.Payload)
	}
	if p.OrigLen == 0 || len(p.Frame) == 0 {
		t.Fatal("Frame/OrigLen 缺失")
	}
	if st.Received.Load() != 1 || st.Filtered.Load() != 0 {
		t.Fatalf("stats=%+v", st)
	}
}

func TestDecodePacketSrcPortHit(t *testing.T) {
	f := filter.New([]uint16{8080}, filter.Both)
	pkt := buildTCPPacket(t, "10.0.0.2", "10.0.0.1", 8080, 40000, []byte("HTTP/1.1 200 OK\r\n\r\n"))
	p, ok := DecodePacket(pkt, f, nil)
	if !ok || p.Ingress {
		t.Fatalf("src 命中应为 egress 放行: ok=%v ingress=%v", ok, p.Ingress)
	}
}

func TestDecodePacketFiltered(t *testing.T) {
	f := filter.New([]uint16{80}, filter.Ingress)
	st := &Stats{}
	// 端口不命中
	pkt := buildTCPPacket(t, "10.0.0.1", "10.0.0.2", 1234, 22, nil)
	if _, ok := DecodePacket(pkt, f, st); ok {
		t.Fatal("端口未命中应过滤")
	}
	// ingress 模式下 src 命中应过滤
	pkt2 := buildTCPPacket(t, "10.0.0.1", "10.0.0.2", 80, 1234, nil)
	if _, ok := DecodePacket(pkt2, f, st); ok {
		t.Fatal("ingress 模式 src 命中应过滤")
	}
	// 非 TCP 应过滤
	if _, ok := DecodePacket(buildUDPPacket(t), f, st); ok {
		t.Fatal("UDP 应过滤")
	}
	if st.Received.Load() != 3 || st.Filtered.Load() != 3 {
		t.Fatalf("stats received=%d filtered=%d", st.Received.Load(), st.Filtered.Load())
	}
}

// TestConsumerIsolation 验证 consumer callback 隔离：上层通过回调消费，
// 无需 AF_PACKET（接口隔离可测性）。
func TestConsumerIsolation(t *testing.T) {
	f := filter.New([]uint16{80}, filter.Both)
	var got []Packet
	consumer := func(p Packet) { got = append(got, p) }
	for _, tc := range []struct {
		src, dst     string
		sport, dport uint16
	}{
		{"10.0.0.1", "10.0.0.2", 5000, 80},
		{"10.0.0.1", "10.0.0.2", 5001, 22}, // 过滤
		{"10.0.0.2", "10.0.0.2", 80, 5000},
	} {
		pkt := buildTCPPacket(t, tc.src, tc.dst, tc.sport, tc.dport, []byte("x"))
		if p, ok := DecodePacket(pkt, f, nil); ok {
			consumer(p)
		}
	}
	if len(got) != 2 {
		t.Fatalf("consumer 应收 2 包, got %d", len(got))
	}
	if got[0].Ingress != true || got[1].Ingress != false {
		t.Fatalf("方向判定错误: %+v", got)
	}
}

func TestErrUnsupportedDefined(t *testing.T) {
	if ErrUnsupported == nil {
		t.Fatal("ErrUnsupported 应在所有平台定义")
	}
}

// TestDecodePacketTCPFlags D-01：FIN/RST flags 须透传给 flow 层。
func TestDecodePacketTCPFlags(t *testing.T) {
	f := filter.New([]uint16{80}, filter.Both)
	// FIN 包（server→client 方向，src 端口命中）
	pkt := buildTCPPacketFlags(t, "10.0.0.2", "10.0.0.1", 80, 5000, nil, true, false)
	p, ok := DecodePacket(pkt, f, nil)
	if !ok || !p.FIN || p.RST {
		t.Fatalf("FIN 透传失败: ok=%v fin=%v rst=%v", ok, p.FIN, p.RST)
	}
	// RST 包（client→server 方向）
	pkt2 := buildTCPPacketFlags(t, "10.0.0.1", "10.0.0.2", 5000, 80, nil, false, true)
	p2, ok := DecodePacket(pkt2, f, nil)
	if !ok || p2.FIN || !p2.RST {
		t.Fatalf("RST 透传失败: ok=%v fin=%v rst=%v", ok, p2.FIN, p2.RST)
	}
	// 无 flags 数据包
	pkt3 := buildTCPPacketFlags(t, "10.0.0.1", "10.0.0.2", 5000, 80, []byte("GET / HTTP/1.1\r\n\r\n"), false, false)
	p3, ok := DecodePacket(pkt3, f, nil)
	if !ok || p3.FIN || p3.RST {
		t.Fatalf("普通包 flags 应为零值: %+v", p3)
	}
}

// TestDecodePacketTruncated D-06：OrigLen > 实际捕获字节数时须标记 Truncated 并计数；
// 正常帧 Truncated=false。
func TestDecodePacketTruncated(t *testing.T) {
	f := filter.New([]uint16{80}, filter.Both)
	st := &Stats{}

	// 截断帧：线上 9000B，实际只捕获到帧长
	pkt := buildTCPPacket(t, "10.0.0.1", "10.0.0.2", 5000, 80, []byte("GET / HTTP/1.1\r\n\r\n"))
	pkt.Metadata().CaptureInfo.Length = 9000
	pkt.Metadata().CaptureInfo.CaptureLength = len(pkt.Data())
	p, ok := DecodePacket(pkt, f, st)
	if !ok {
		t.Fatal("截断帧端口命中仍应放行（由 httpsensor 快速失败处理）")
	}
	if !p.Truncated {
		t.Fatal("OrigLen > 捕获长度应标记 Truncated")
	}
	if p.OrigLen != 9000 {
		t.Fatalf("OrigLen 应为线上长度 9000, got %d", p.OrigLen)
	}
	if st.Truncated.Load() != 1 {
		t.Fatalf("st.Truncated 应为 1, got %d", st.Truncated.Load())
	}

	// 正常帧
	pkt2 := buildTCPPacket(t, "10.0.0.1", "10.0.0.2", 5000, 80, []byte("x"))
	pkt2.Metadata().CaptureInfo.Length = len(pkt2.Data())
	pkt2.Metadata().CaptureInfo.CaptureLength = len(pkt2.Data())
	p2, ok := DecodePacket(pkt2, f, st)
	if !ok || p2.Truncated {
		t.Fatalf("正常帧不应标记截断: ok=%v truncated=%v", ok, p2.Truncated)
	}
	if st.Truncated.Load() != 1 {
		t.Fatalf("正常帧不应增加截断计数, got %d", st.Truncated.Load())
	}
}
