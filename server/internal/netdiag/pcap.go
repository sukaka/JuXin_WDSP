// pcap.go 纯 Go pcap 解析器（不引入第三方依赖）：
// 解析 tcpdump 经典 pcap 文件（24 字节全局头 + 逐包 16 字节记录头），
// 解码层次 Ethernet II（含 802.1Q VLAN tag 跳过）→ IPv4/IPv6 → TCP/UDP/ICMP/ICMPv6，
// 产出页面内数据包列表（最多前 maxCapturePackets 个，截断包/畸形包跳过不报错）。
package netdiag

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"
)

// MaxCapturePackets 页面内解析展示的包数上限（超出标记 truncated，正常返回前 200 个）。
const MaxCapturePackets = 200

// capturePreviewMaxLen 传输层 payload 可打印预览的最大字符数。
const capturePreviewMaxLen = 80

// pcap 全局头/记录头长度与链路类型。
const (
	pcapGlobalHeaderLen = 24
	pcapRecordHeaderLen = 16
	linkTypeEthernet    = 1
	maxPcapFrameBytes   = 262144
)

// CapturePacket 单个数据包的页面展示结构（capture_packets JSONB 数组元素）。
type CapturePacket struct {
	No      int    `json:"no"`              // 包序号（按解析成功顺序从 1 编号）
	Ts      string `json:"ts"`              // 捕获时间（RFC3339，微秒精度）
	Src     string `json:"src"`             // 源地址（IP；非 IP 包为源 MAC）
	Dst     string `json:"dst"`             // 目的地址（IP；非 IP 包为目的 MAC）
	Sport   *int   `json:"sport"`           // 源端口（仅 TCP/UDP，其余 null）
	Dport   *int   `json:"dport"`           // 目的端口（仅 TCP/UDP，其余 null）
	Proto   string `json:"proto"`           // TCP/UDP/ICMP/ICMPv6；其他 IP 协议 IP-<num>；非 IP ETH-0x<ethertype hex>
	Flags   string `json:"flags,omitempty"` // 仅 TCP，按 FIN,SYN,RST,PSH,ACK,URG,ECE,CWR 顺序逗号连接
	Length  int    `json:"length"`          // orig_len（线原始长度）
	Preview string `json:"preview"`         // 传输层 payload 可打印 ASCII（非可打印字节替换为 .，截断 80 字符；无 payload 空串）
}

// pcapByteOrder 全局头魔数决定的端序与时间戳分辨率。
type pcapByteOrder struct {
	order binary.ByteOrder
	nano  bool // true = 纳秒变体，false = 微秒
}

// ParsePcap 解析 pcap 字节流，返回最多 MaxCapturePackets 个数据包。
func ParsePcap(data []byte) (packets []CapturePacket, truncated bool, err error) {
	return ParsePcapReader(bytes.NewReader(data))
}

// ParsePcapReader 流式解析 pcap 数据，仅读取至多 MaxCapturePackets 个包即停止，
// 避免将大体积抓包文件整体读入内存。
func ParsePcapReader(r io.Reader) (packets []CapturePacket, truncated bool, err error) {
	var globalHdr [pcapGlobalHeaderLen]byte
	n, err := io.ReadFull(r, globalHdr[:])
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, false, fmt.Errorf("pcap 全局头长度不足（%d < %d 字节）", n, pcapGlobalHeaderLen)
		}
		return nil, false, fmt.Errorf("读取 pcap 全局头失败: %w", err)
	}
	var bo pcapByteOrder
	switch binary.BigEndian.Uint32(globalHdr[:4]) {
	case 0xa1b2c3d4:
		bo = pcapByteOrder{order: binary.BigEndian}
	case 0xd4c3b2a1:
		bo = pcapByteOrder{order: binary.LittleEndian}
	case 0xa1b23c4d:
		bo = pcapByteOrder{order: binary.BigEndian, nano: true}
	case 0x4d3cb2a1:
		bo = pcapByteOrder{order: binary.LittleEndian, nano: true}
	default:
		return nil, false, fmt.Errorf("pcap 魔数非法: 0x%08x", binary.BigEndian.Uint32(globalHdr[:4]))
	}
	if linkType := bo.order.Uint32(globalHdr[20:24]); linkType != linkTypeEthernet {
		return nil, false, fmt.Errorf("pcap 链路类型不支持（linktype=%d，仅支持 Ethernet=%d）", linkType, linkTypeEthernet)
	}

	packets = []CapturePacket{}
	var recHdr [pcapRecordHeaderLen]byte
	var frameBuf []byte
	for {
		_, err := io.ReadFull(r, recHdr[:])
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return nil, false, fmt.Errorf("读取 pcap 记录头失败: %w", err)
		}
		if len(packets) >= MaxCapturePackets {
			return packets, true, nil // 后续仍有记录 → 截断标记，立即停止读取
		}
		tsSec := bo.order.Uint32(recHdr[0:4])
		tsFrac := bo.order.Uint32(recHdr[4:8])
		inclLen := bo.order.Uint32(recHdr[8:12])
		origLen := bo.order.Uint32(recHdr[12:16])
		if inclLen > maxPcapFrameBytes {
			if _, derr := io.CopyN(io.Discard, r, int64(inclLen)); derr != nil {
				break
			}
			continue
		}
		if cap(frameBuf) < int(inclLen) {
			frameBuf = make([]byte, inclLen)
		} else {
			frameBuf = frameBuf[:inclLen]
		}
		if _, err := io.ReadFull(r, frameBuf); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break // 文件尾部截断，正常收尾不报错
			}
			return nil, false, fmt.Errorf("读取 pcap 帧数据失败: %w", err)
		}
		pkt, ok := decodeFrame(frameBuf, tsSec, tsFrac, bo.nano, int(origLen))
		if !ok {
			continue // 截断/畸形包跳过
		}
		pkt.No = len(packets) + 1
		packets = append(packets, pkt)
	}
	return packets, false, nil
}

// decodeFrame 解码单个 Ethernet II 帧；无法解码（截断/畸形）返回 false。
func decodeFrame(frame []byte, tsSec, tsFrac uint32, nano bool, origLen int) (CapturePacket, bool) {
	var pkt CapturePacket
	pkt.Length = origLen
	nsec := int64(tsFrac) * 1000
	if nano {
		nsec = int64(tsFrac)
	}
	pkt.Ts = time.Unix(int64(tsSec), nsec).UTC().Format("2006-01-02T15:04:05.000000Z07:00")

	if len(frame) < 14 {
		return pkt, false
	}
	srcMAC, dstMAC := frame[6:12], frame[0:6]
	etherType := binary.BigEndian.Uint16(frame[12:14])
	payload := frame[14:]
	// 802.1Q / QinQ VLAN tag 跳过（可多层）
	for etherType == 0x8100 || etherType == 0x88a8 {
		if len(payload) < 4 {
			return pkt, false
		}
		etherType = binary.BigEndian.Uint16(payload[2:4])
		payload = payload[4:]
	}

	switch etherType {
	case 0x0800:
		if !decodeIPv4(&pkt, payload) {
			return pkt, false
		}
	case 0x86dd:
		if !decodeIPv6(&pkt, payload) {
			return pkt, false
		}
	default:
		pkt.Proto = fmt.Sprintf("ETH-0x%04x", etherType)
		pkt.Src = macString(srcMAC)
		pkt.Dst = macString(dstMAC)
		pkt.Preview = printablePreview(payload)
	}
	return pkt, true
}

// decodeIPv4 解码 IPv4 包（含 TCP/UDP/ICMP 传输层）。
func decodeIPv4(pkt *CapturePacket, b []byte) bool {
	if len(b) < 20 || b[0]>>4 != 4 {
		return false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return false
	}
	pkt.Src = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}).String()
	pkt.Dst = netip.AddrFrom4([4]byte{b[16], b[17], b[18], b[19]}).String()
	protoNum := b[9]
	// 非首片分片（offset>0）无传输层头可解，按 IP-<num> 呈现
	frag := binary.BigEndian.Uint16(b[6:8])
	if frag&0x1fff != 0 {
		pkt.Proto = fmt.Sprintf("IP-%d", protoNum)
		return true
	}
	decodeTransport(pkt, protoNum, b[ihl:])
	return true
}

// decodeIPv6 解码 IPv6 包（跳过常见扩展头后解 TCP/UDP/ICMPv6）。
func decodeIPv6(pkt *CapturePacket, b []byte) bool {
	if len(b) < 40 || b[0]>>4 != 6 {
		return false
	}
	pkt.Src = netip.AddrFrom16([16]byte(b[8:24])).String()
	pkt.Dst = netip.AddrFrom16([16]byte(b[24:40])).String()
	next := b[6]
	payload := b[40:]
	// 扩展头链：hop-by-hop(0)/routing(43)/destination(60) 按 (len+1)*8 跳过；
	// fragment(44) 固定 8 字节，非首片不解传输层
	for {
		switch next {
		case 0, 43, 60:
			if len(payload) < 2 {
				return false
			}
			hl := (int(payload[1]) + 1) * 8
			if len(payload) < hl {
				return false
			}
			next = payload[0]
			payload = payload[hl:]
		case 44:
			if len(payload) < 8 {
				return false
			}
			frag := binary.BigEndian.Uint16(payload[2:4])
			if frag&0xfff8 != 0 { // offset>0 非首片
				pkt.Proto = fmt.Sprintf("IP-%d", payload[0])
				return true
			}
			next = payload[0]
			payload = payload[8:]
		default:
			decodeTransport(pkt, next, payload)
			return true
		}
	}
}

// decodeTransport 解 TCP/UDP/ICMP/ICMPv6 传输层，填充 proto/端口/flags/preview。
func decodeTransport(pkt *CapturePacket, protoNum byte, b []byte) {
	switch protoNum {
	case 6: // TCP
		pkt.Proto = "TCP"
		if len(b) < 20 {
			return
		}
		sport, dport := int(binary.BigEndian.Uint16(b[0:2])), int(binary.BigEndian.Uint16(b[2:4]))
		pkt.Sport, pkt.Dport = &sport, &dport
		pkt.Flags = tcpFlags(b[13])
		dataOff := int(b[12]>>4) * 4
		if dataOff >= 20 && len(b) > dataOff {
			pkt.Preview = printablePreview(b[dataOff:])
		}
	case 17: // UDP
		pkt.Proto = "UDP"
		if len(b) < 8 {
			return
		}
		sport, dport := int(binary.BigEndian.Uint16(b[0:2])), int(binary.BigEndian.Uint16(b[2:4]))
		pkt.Sport, pkt.Dport = &sport, &dport
		pkt.Preview = printablePreview(b[8:])
	case 1: // ICMP
		pkt.Proto = "ICMP"
		pkt.Preview = printablePreview(icmpPayload(b))
	case 58: // ICMPv6
		pkt.Proto = "ICMPv6"
		pkt.Preview = printablePreview(icmpPayload(b))
	default:
		pkt.Proto = fmt.Sprintf("IP-%d", protoNum)
		pkt.Preview = printablePreview(b)
	}
}

// icmpPayload ICMP/ICMPv6 消息体（跳过 type/code/checksum 与前 4 字节消息头共 8 字节）。
func icmpPayload(b []byte) []byte {
	if len(b) <= 8 {
		return nil
	}
	return b[8:]
}

// tcpFlags 按 FIN,SYN,RST,PSH,ACK,URG,ECE,CWR 顺序逗号连接（无标志位为空串）。
func tcpFlags(f byte) string {
	names := []struct {
		bit  byte
		name string
	}{
		{0x01, "FIN"}, {0x02, "SYN"}, {0x04, "RST"}, {0x08, "PSH"},
		{0x10, "ACK"}, {0x20, "URG"}, {0x40, "ECE"}, {0x80, "CWR"},
	}
	out := ""
	for _, n := range names {
		if f&n.bit != 0 {
			if out != "" {
				out += ","
			}
			out += n.name
		}
	}
	return out
}

// printablePreview 可打印 ASCII 预览：非可打印字节替换为 .，截断 capturePreviewMaxLen 字符。
func printablePreview(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) > capturePreviewMaxLen {
		b = b[:capturePreviewMaxLen]
	}
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 0x20 && c <= 0x7e {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

// macString 格式化 MAC 地址。
func macString(b []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}
