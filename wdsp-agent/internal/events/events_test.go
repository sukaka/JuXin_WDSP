package events

import (
	"bytes"
	"testing"
	"time"
)

func TestPacketBatchRoundTrip(t *testing.T) {
	b := NewPacketBatcher(0, nil)
	ts1 := time.Unix(1788256800, 123456000)
	ts2 := time.Unix(1788256801, 0)
	if !b.Add(PacketFrame{Ts: ts1, OrigLen: 60, Data: bytes.Repeat([]byte{0xaa}, 60)}) {
		t.Fatal("首帧应成功")
	}
	if !b.Add(PacketFrame{Ts: ts2, OrigLen: 1514, Data: bytes.Repeat([]byte{0xbb}, 1514)}) {
		t.Fatal("次帧应成功")
	}
	body := b.Flush(time.Unix(1788256805, 0))
	if b.Len() != 0 {
		t.Fatal("Flush 后应清空")
	}
	if string(body[:4]) != PacketMagic {
		t.Fatalf("magic=%q", body[:4])
	}
	bts, frames, err := DecodePacketBatch(body)
	if err != nil {
		t.Fatal(err)
	}
	if bts != 1788256805 {
		t.Fatalf("batch_ts=%d", bts)
	}
	if len(frames) != 2 {
		t.Fatalf("frames=%d", len(frames))
	}
	if frames[0].Ts.Unix() != ts1.Unix() || frames[0].Ts.Nanosecond() != 123456000 {
		t.Fatalf("帧0 ts=%v", frames[0].Ts)
	}
	if frames[1].OrigLen != 1514 || len(frames[1].Data) != 1514 {
		t.Fatalf("帧1 orig=%d cap=%d", frames[1].OrigLen, len(frames[1].Data))
	}
}

func TestPacketBatchSizeLimit(t *testing.T) {
	b := NewPacketBatcher(1024, nil) // 小上限便于测试
	big := bytes.Repeat([]byte{0x01}, 600)
	if !b.Add(PacketFrame{Ts: time.Now(), OrigLen: 600, Data: big}) {
		t.Fatal("首帧应成功")
	}
	if b.Add(PacketFrame{Ts: time.Now(), OrigLen: 600, Data: big}) {
		t.Fatal("超上限应返回 false（调用方切批）")
	}
	body := b.Flush(time.Now())
	if body == nil {
		t.Fatal("Flush 应有内容")
	}
	// 切批后重试成功
	if !b.Add(PacketFrame{Ts: time.Now(), OrigLen: 600, Data: big}) {
		t.Fatal("新批首帧应成功")
	}
}

func TestOversizeFrameDropped(t *testing.T) {
	dropped := 0
	b := NewPacketBatcher(0, func(n int) { dropped += n })
	huge := make([]byte, MaxFrameCapLen+1)
	if !b.Add(PacketFrame{Ts: time.Now(), OrigLen: uint32(len(huge)), Data: huge}) {
		t.Fatal("超限帧丢弃不视为批满")
	}
	if dropped != 1 || b.Len() != 0 {
		t.Fatalf("dropped=%d len=%d", dropped, b.Len())
	}
}

func TestDecodeRejectsBadMagic(t *testing.T) {
	if _, _, err := DecodePacketBatch([]byte("XXXX00000000000000")); err == nil {
		t.Fatal("坏 magic 应报错")
	}
	if _, _, err := DecodePacketBatch([]byte("WDP1")); err == nil {
		t.Fatal("过短 body 应报错")
	}
}

func TestEmptyFlush(t *testing.T) {
	b := NewPacketBatcher(0, nil)
	if b.Flush(time.Now()) != nil {
		t.Fatal("空批 Flush 应为 nil")
	}
}
