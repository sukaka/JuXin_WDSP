// 平台无关部分：ringbuf 事件解码、端口集合增量更新、参数钳制（跨平台可单测）。
package ebpfcapture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// 与 tc_capture.c 对齐的常量。
const (
	// eventHdrLen 事件定长头字节数（struct event_hdr：8+4+4+4+1+3）。
	eventHdrLen = 24

	// DirIngress / DirEgress TC 挂点方向（事件 dir 字段）。
	DirIngress = 0
	DirEgress  = 1

	// DefaultSnaplen 默认单事件截取字节：覆盖完整 MTU1500 帧（1514B）。
	// HTTP 嗅探的 16KB 窗口是流重组后的累计量（httpparse 跨包累积），
	// 单包无需 16KB；ringbuf 吞吐 ≈ 事件数 × 事件字节数，snaplen 越大
	// 高 pps 下 ringbuf 越容易满（丢事件），故默认收敛在 2048。
	DefaultSnaplen = 2048
	// MaxSnaplen 截取硬上限（C 侧 scratch 缓冲同步为 4096）。
	MaxSnaplen = 4096
	// MinSnaplen 截取下限（完整以太网/IP/TCP 头 + 少量 payload）。
	MinSnaplen = 128

	// DefaultRingbufBytes ring buffer 默认大小（4MB，须 2 的幂）。
	DefaultRingbufBytes = 1 << 22
	minRingbufBytes     = 1 << 16
	maxRingbufBytes     = 1 << 26
)

// Event 解码后的 ringbuf 事件（定长头 + 帧字节）。
//
// 内存语义：Data 指向 ringbuf 记录缓冲内部，仅在下一次 Read 前有效
// （与 AF_PACKET 路径相同的 NoCopy 语义，消费方跨 goroutine 须拷贝）。
type Event struct {
	TsNs    uint64 // bpf_ktime_get_ns（CLOCK_MONOTONIC；用户态换算墙钟）
	Ifindex uint32 // 挂载网卡 ifindex
	OrigLen uint32 // 线上原始帧长
	CapLen  uint32 // 上送字节数
	Dir     uint8  // TC 挂点方向（DirIngress/DirEgress，随事件带给用户态）
	Data    []byte // 帧字节（len == CapLen）
}

// decodeEvent 解析一条 ringbuf 记录；畸形记录返回错误（调用方跳过不中断）。
func decodeEvent(raw []byte) (Event, error) {
	if len(raw) < eventHdrLen {
		return Event{}, fmt.Errorf("事件过短: %d < %d", len(raw), eventHdrLen)
	}
	ev := Event{
		TsNs:    binary.LittleEndian.Uint64(raw[0:8]),
		Ifindex: binary.LittleEndian.Uint32(raw[8:12]),
		OrigLen: binary.LittleEndian.Uint32(raw[12:16]),
		CapLen:  binary.LittleEndian.Uint32(raw[16:20]),
		Dir:     raw[20],
	}
	if ev.CapLen > MaxSnaplen {
		return Event{}, fmt.Errorf("cap_len 超限: %d > %d", ev.CapLen, MaxSnaplen)
	}
	if len(raw)-eventHdrLen < int(ev.CapLen) {
		return Event{}, fmt.Errorf("事件数据不完整: 剩余 %d < cap_len %d", len(raw)-eventHdrLen, ev.CapLen)
	}
	ev.Data = raw[eventHdrLen : eventHdrLen+ev.CapLen]
	return ev, nil
}

// ClampSnaplen 钳制 snaplen 到 [MinSnaplen, MaxSnaplen]；<=0 取默认。
func ClampSnaplen(n int) int {
	if n <= 0 {
		return DefaultSnaplen
	}
	if n < MinSnaplen {
		return MinSnaplen
	}
	if n > MaxSnaplen {
		return MaxSnaplen
	}
	return n
}

// normalizeRingbufBytes 规整 ring buffer 大小：<=0 取默认；向上取 2 的幂；
// 钳制到 [minRingbufBytes, maxRingbufBytes]。
func normalizeRingbufBytes(n int) int {
	if n <= 0 {
		return DefaultRingbufBytes
	}
	p := minRingbufBytes
	for p < n && p < maxRingbufBytes {
		p <<= 1
	}
	return p
}

// portsUpdate 计算端口集合两阶段增量更新计划（先加后删，避免短暂全丢窗口）：
// add = desired 中新增的端口；del = current 中不再需要的端口。
// 返回切片升序（结果确定性，便于测试与日志）。
func portsUpdate(current, desired []uint16) (add, del []uint16) {
	cur := make(map[uint16]struct{}, len(current))
	for _, p := range current {
		cur[p] = struct{}{}
	}
	des := make(map[uint16]struct{}, len(desired))
	for _, p := range desired {
		if _, dup := des[p]; dup {
			continue // 输入去重
		}
		des[p] = struct{}{}
		if _, ok := cur[p]; !ok {
			add = append(add, p)
		}
	}
	for p := range cur {
		if _, ok := des[p]; !ok {
			del = append(del, p)
		}
	}
	sort.Slice(add, func(i, j int) bool { return add[i] < add[j] })
	sort.Slice(del, func(i, j int) bool { return del[i] < del[j] })
	return add, del
}

var errNotLoaded = errors.New("ebpfcapture: eBPF 对象未加载")
