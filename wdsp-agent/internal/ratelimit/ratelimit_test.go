package ratelimit

import (
	"testing"
	"time"
)

func TestAllowWithinRate(t *testing.T) {
	b := New(16)           // 16 Mbps = 2,000,000 B/s，桶=2,000,000B
	if !b.Allow(1 << 20) { // 1,048,576B
		t.Fatal("首笔 1MiB 应放行（满桶）")
	}
	if !b.Allow(900 << 10) { // 累计 1,970,176B < 2,000,000B
		t.Fatal("第二笔 900KiB 应放行")
	}
	if b.Allow(100 << 10) {
		t.Fatal("余额不足不应放行")
	}
}

func TestRefill(t *testing.T) {
	now := time.Now()
	b := New(16) // 2,000,000 B/s
	b.SetClock(func() time.Time { return now })
	if !b.Allow(2_000_000) {
		t.Fatal("满桶应放行")
	}
	if b.Allow(1) {
		t.Fatal("桶已空")
	}
	now = now.Add(500 * time.Millisecond) // 补充 1,000,000B
	if !b.Allow(1_000_000) {
		t.Fatal("0.5s 后应补充 1,000,000B")
	}
	if b.Allow(1) {
		t.Fatal("余额耗尽")
	}
}

func TestUnlimited(t *testing.T) {
	b := New(0)
	if !b.Allow(1 << 30) {
		t.Fatal("mbps<=0 应不限速")
	}
}

func TestSetRateHotUpdate(t *testing.T) {
	now := time.Now()
	b := New(8)
	b.SetClock(func() time.Time { return now })
	b.Allow(1 << 20) // 清空
	b.SetRate(800)   // 100MB/s，桶扩容
	now = now.Add(time.Second)
	if !b.Allow(90 << 20) {
		t.Fatal("提速后应允许更大突发")
	}
	b.SetRate(0)
	if !b.Allow(1 << 30) {
		t.Fatal("SetRate(0) 应解除限速")
	}
}

func TestBurstFloor(t *testing.T) {
	b := New(0.1) // 12.5KB/s → 桶容量取 64KB 下限
	if !b.Allow(60 << 10) {
		t.Fatal("低速率桶应有 64KB 下限容量")
	}
}
