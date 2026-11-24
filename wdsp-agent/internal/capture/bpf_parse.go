package capture

import (
	"encoding/binary"
	"time"
)

// BSD / macOS struct bpf_hdr 最小头长（Timeval32(8) + Caplen(4) + Datalen(4) + Hdrlen(2) = 18B）。
const minBPFHdrLen = 18

// BPFFrame 从 BSD/macOS BPF read() 缓冲中切分出的单帧。
type BPFFrame struct {
	Timestamp time.Time
	CapLen    int
	OrigLen   int
	Data      []byte
}

// bpfWordAlign BSD BPF_WORDALIGN 对齐向上取整。
func bpfWordAlign(n, align int) int {
	if align <= 1 {
		return n
	}
	return (n + align - 1) &^ (align - 1)
}

// ParseBPFBuffer 遍历一次 BPF read() 返回的多帧缓冲，逐帧回调 onFrame，返回成功解析帧数。
// 默认按 4 字节对齐（Darwin 64-bit / BSD BPF_ALIGNMENT=4）；含严格越界与防死循环保护。
func ParseBPFBuffer(buf []byte, align int, onFrame func(BPFFrame)) int {
	if align <= 0 {
		align = 4
	}
	off := 0
	count := 0
	for off+minBPFHdrLen <= len(buf) {
		sec := int32(binary.LittleEndian.Uint32(buf[off : off+4]))
		usec := int32(binary.LittleEndian.Uint32(buf[off+4 : off+8]))
		capLen := binary.LittleEndian.Uint32(buf[off+8 : off+12])
		dataLen := binary.LittleEndian.Uint32(buf[off+12 : off+16])
		hdrLen := binary.LittleEndian.Uint16(buf[off+16 : off+18])

		if int(hdrLen) < minBPFHdrLen {
			break
		}
		payloadStart := off + int(hdrLen)
		if payloadStart > len(buf) {
			break
		}
		payloadEnd := payloadStart + int(capLen)
		if payloadEnd < payloadStart || payloadEnd > len(buf) {
			break
		}
		ts := time.Unix(int64(sec), int64(usec)*1000)
		if onFrame != nil {
			onFrame(BPFFrame{
				Timestamp: ts,
				CapLen:    int(capLen),
				OrigLen:   int(dataLen),
				Data:      buf[payloadStart:payloadEnd],
			})
		}
		count++
		step := bpfWordAlign(int(hdrLen)+int(capLen), align)
		if step <= 0 {
			break
		}
		off += step
	}
	return count
}

// CounterDelta 将累计型内核收包/丢包计数器（如 BSD BIOCGSTATS、Npcap pcap_stats）
// 转换为与 Linux PACKET_STATISTICS 一致的「自上次调用起的差值」语义。
type CounterDelta struct {
	lastRecv uint32
	lastDrop uint32
}

// Diff 计算本次读数与上次读数的无符号差值（天然兼容 uint32 回绕）。
func (c *CounterDelta) Diff(recv, drop uint32) (dRecv, dDrop uint32) {
	dRecv = recv - c.lastRecv
	dDrop = drop - c.lastDrop
	c.lastRecv = recv
	c.lastDrop = drop
	return dRecv, dDrop
}
