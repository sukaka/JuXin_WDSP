// Package capture 旁路抓包：Backend 抽象（Phase 2：AF_PACKET / eBPF-TC 双后端，
// 见 backend.go 与 internal/ebpfcapture）、AF_PACKET 实现（TASK-004/005，
// linux build tag + 非 linux 桩）与平台无关解码过滤。
//
// 红线（设计 §72 / 契约 §6）：纯旁路只读——本包只从网卡收包，
// 不存在任何向网卡写报文的代码路径；抓包 goroutine 全部 recover 保护，
// 任何内部错误只降级重试，绝不退出进程。
//
// 实现说明（沿用 gateway/mirrorcap 的锁定结论）：gopacket v1.1.19 的 afpacket
// 子包含 cgo，CGO_ENABLED=0 不可用；pcapgo.EthernetHandle 为纯 syscall 实现
// （unix.Socket(AF_PACKET, SOCK_RAW) + recvmsg），满足静态编译约束。
package capture

import (
	"errors"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/jiuzhang-waf/wdsp-agent/internal/filter"
)

// ErrUnsupported 平台不支持当前抓包后端。
var ErrUnsupported = errors.New("capture: 该平台不支持此抓包后端")

// ErrStatsUnsupported 当前抓包后端不提供内核级收包/丢包统计（如 Windows Raw Socket）。
var ErrStatsUnsupported = errors.New("capture: 当前后端不支持内核丢包统计")

// Packet 解码后的单包交付件。
//
// 内存语义：Frame/Payload 在 NoCopy 解码下仅于回调期间有效，
// 消费方如需跨 goroutine 保留必须自行拷贝。
type Packet struct {
	Ts          time.Time
	Frame       []byte // 原始捕获字节（以太网后端含 Ethernet 头；L3 Raw Socket 为 IPv4 报文）
	NonEthernet bool   // Frame 不含二层以太网头（如 Windows Raw Socket / macOS DLT_NULL），RAW WDP1 跳过不伪造假头
	OrigLen     int    // 线上原始长度
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Payload []byte // TCP payload
	Ingress bool   // filter 判定方向（dst 端口命中=ingress）
	// BothHit 连接两端端口均在采集集（逐包方向判定随包向翻转，flow/httpsensor
	// 的 canonical 归一化须改用五元组排序兜底，否则同一连接被拆成两条单向流）。
	BothHit bool
	// Truncated 帧捕获不完整（OrigLen > 实际捕获字节数，D-06）：TSO/GRO 超帧
	// 超接收缓冲被截，或 eBPF snaplen 钳制。httpsensor 对含截断包的连接
	// 立即回退并补发 response=null（不得干等空闲冲刷）；flow 事件不受影响。
	Truncated bool
	Seq       uint32 // TCP 序列号（Phase 3 httpsensor 重组）
	SYN       bool   // TCP SYN
	ACK       bool   // TCP ACK
	PSH       bool   // TCP PSH
	FIN       bool   // TCP FIN（flow 层流关闭识别）
	RST       bool   // TCP RST
}

// Stats 抓包层计数（agent 聚合成心跳 metrics）。
type Stats struct {
	Received    atomic.Uint64 // 网卡交付报文数
	Filtered    atomic.Uint64 // 非 TCP/端口方向未命中被过滤
	KernelDrops atomic.Uint64 // 内核 socket 丢包（周期差值累计）
	Truncated   atomic.Uint64 // 捕获不完整帧数（OrigLen > CapLen，D-06）
}

// DecodePacket 解码 + 过滤（平台无关，可单测；Phase 2 起导出供 eBPF 后端复用，
// 保证两后端端口/方向语义完全一致）。
// 仅放行 TCP 且端口/方向命中的包；ts 为零值时用 time.Now()。
func DecodePacket(pkt gopacket.Packet, filt *filter.Filter, st *Stats) (Packet, bool) {
	if st != nil {
		st.Received.Add(1)
	}
	filtered := func() (Packet, bool) {
		if st != nil {
			st.Filtered.Add(1)
		}
		return Packet{}, false
	}
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return filtered()
	}
	tcp, _ := tcpLayer.(*layers.TCP)
	ok, ingress := filt.Match(uint16(tcp.SrcPort), uint16(tcp.DstPort))
	if !ok {
		return filtered()
	}
	nl := pkt.NetworkLayer()
	if nl == nil {
		return filtered()
	}
	src, dst := nl.NetworkFlow().Endpoints()
	ts := pkt.Metadata().Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	ci := pkt.Metadata().CaptureInfo
	frame := pkt.Data()
	truncated := ci.Length > len(frame) // D-06：线上长度 > 实际捕获字节 = 截断
	if truncated && st != nil {
		st.Truncated.Add(1)
	}
	return Packet{
		Ts:          ts,
		Frame:       frame,
		NonEthernet: pkt.Layer(layers.LayerTypeEthernet) == nil,
		OrigLen:     ci.Length,
		SrcIP:     src.String(),
		DstIP:     dst.String(),
		SrcPort:   uint16(tcp.SrcPort),
		DstPort:   uint16(tcp.DstPort),
		Payload:   tcp.Payload,
		Ingress:   ingress,
		BothHit:   filt.HasPort(uint16(tcp.SrcPort)) && filt.HasPort(uint16(tcp.DstPort)),
		Truncated: truncated,
		Seq:       tcp.Seq,
		SYN:       tcp.SYN,
		ACK:       tcp.ACK,
		PSH:       tcp.PSH,
		FIN:       tcp.FIN,
		RST:       tcp.RST,
	}, true
}
