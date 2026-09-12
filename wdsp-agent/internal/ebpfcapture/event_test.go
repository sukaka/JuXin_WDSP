package ebpfcapture

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildEvent 按线上格式构造合成 ringbuf 事件（跨平台可测）。
func buildEvent(tsNs uint64, ifindex, origLen uint32, dir uint8, data []byte) []byte {
	raw := make([]byte, eventHdrLen+len(data))
	binary.LittleEndian.PutUint64(raw[0:8], tsNs)
	binary.LittleEndian.PutUint32(raw[8:12], ifindex)
	binary.LittleEndian.PutUint32(raw[12:16], origLen)
	binary.LittleEndian.PutUint32(raw[16:20], uint32(len(data)))
	raw[20] = dir
	copy(raw[eventHdrLen:], data)
	return raw
}

func TestDecodeEvent(t *testing.T) {
	frame := []byte("\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00ETHERNET-IP-TCP-PAYLOAD")
	raw := buildEvent(1788256800123456789, 7, 1514, DirEgress, frame)
	ev, err := decodeEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ev.TsNs != 1788256800123456789 || ev.Ifindex != 7 || ev.OrigLen != 1514 {
		t.Fatalf("头部字段错误: %+v", ev)
	}
	if ev.Dir != DirEgress {
		t.Fatalf("方向应随事件带给用户态: dir=%d", ev.Dir)
	}
	if !bytes.Equal(ev.Data, frame) || int(ev.CapLen) != len(frame) {
		t.Fatalf("帧数据错误: cap=%d data=%q", ev.CapLen, ev.Data)
	}
}

func TestDecodeEventMalformed(t *testing.T) {
	// 过短
	if _, err := decodeEvent([]byte{1, 2, 3}); err == nil {
		t.Fatal("过短事件应报错")
	}
	// cap_len 超硬上限
	raw := buildEvent(1, 1, 1, DirIngress, nil)
	binary.LittleEndian.PutUint32(raw[16:20], MaxSnaplen+1)
	if _, err := decodeEvent(raw); err == nil {
		t.Fatal("cap_len 超限应报错")
	}
	// cap_len 与实际数据不符
	raw2 := buildEvent(1, 1, 1, DirIngress, []byte("abc"))
	binary.LittleEndian.PutUint32(raw2[16:20], 100)
	if _, err := decodeEvent(raw2); err == nil {
		t.Fatal("数据不完整应报错")
	}
	// 空帧合法（cap_len=0）
	if _, err := decodeEvent(buildEvent(1, 1, 60, DirIngress, nil)); err != nil {
		t.Fatalf("空帧应合法: %v", err)
	}
}

func TestClampSnaplen(t *testing.T) {
	for in, want := range map[int]int{
		0:     DefaultSnaplen,
		-1:    DefaultSnaplen,
		2048:  2048,
		1:     MinSnaplen,
		4096:  MaxSnaplen,
		16384: MaxSnaplen, // 16KB 需求由流重组覆盖，单事件收敛在 4096
	} {
		if got := ClampSnaplen(in); got != want {
			t.Errorf("ClampSnaplen(%d)=%d, want %d", in, got, want)
		}
	}
}

func TestNormalizeRingbufBytes(t *testing.T) {
	if got := normalizeRingbufBytes(0); got != DefaultRingbufBytes {
		t.Fatalf("默认 ringbuf=%d", got)
	}
	if got := normalizeRingbufBytes(1); got != minRingbufBytes {
		t.Fatalf("下限 ringbuf=%d", got)
	}
	// 非 2 的幂向上取整
	if got := normalizeRingbufBytes(3 << 20); got != 4<<20 {
		t.Fatalf("应向上取 2 的幂: %d", got)
	}
	if got := normalizeRingbufBytes(1 << 30); got != maxRingbufBytes {
		t.Fatalf("上限 ringbuf=%d", got)
	}
}

// TestPortsUpdate 端口 map 两阶段热更计划（先加后删，避免全丢窗口）。
func TestPortsUpdate(t *testing.T) {
	add, del := portsUpdate([]uint16{80, 443, 8080}, []uint16{443, 9000, 80})
	if len(add) != 1 || add[0] != 9000 {
		t.Fatalf("add=%v", add)
	}
	if len(del) != 1 || del[0] != 8080 {
		t.Fatalf("del=%v", del)
	}
	// 全量替换
	add, del = portsUpdate([]uint16{80}, []uint16{443})
	if len(add) != 1 || len(del) != 1 {
		t.Fatalf("全量替换: add=%v del=%v", add, del)
	}
	// 清空
	add, del = portsUpdate([]uint16{80, 443}, nil)
	if len(add) != 0 || len(del) != 2 {
		t.Fatalf("清空: add=%v del=%v", add, del)
	}
	// 无变化
	add, del = portsUpdate([]uint16{80, 443}, []uint16{443, 80})
	if len(add) != 0 || len(del) != 0 {
		t.Fatalf("无变化: add=%v del=%v", add, del)
	}
	// 去重（输入重复端口不应重复下发）
	add, _ = portsUpdate(nil, []uint16{80, 80, 443})
	if len(add) != 2 {
		t.Fatalf("去重失败: add=%v", add)
	}
}
