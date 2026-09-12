// 限速桶饱和信号测试（Phase 4 契约 §3.1：连续 N 秒无法足额发送）。
package ratelimit

import (
	"testing"
	"time"
)

func TestDenialStreak(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	b := New(16) // 2,000,000 B/s
	b.SetClock(func() time.Time { return now })
	if b.DenialStreak() != 0 {
		t.Fatal("无拒绝时应为 0")
	}
	if !b.Allow(2_000_000) { // 空桶
		t.Fatal("满桶应放行")
	}
	// 连续拒绝 6s
	for i := 0; i < 6; i++ {
		now = now.Add(time.Second)
		if b.Allow(3_000_000) { // 每秒只补 2MB，请求 3MB 恒失败
			t.Fatal("超额请求不应放行")
		}
	}
	streak := b.DenialStreak()
	if streak < 5*time.Second {
		t.Fatalf("连续拒绝应有累计时长: %v", streak)
	}
	// 一次成功消费清零
	if !b.Allow(1) {
		t.Fatal("小额应放行")
	}
	if b.DenialStreak() != 0 {
		t.Fatal("成功消费后应清零")
	}
	// 拒绝后发送侧安静超 2s 视为不再饱和
	now = now.Add(time.Second)
	if b.Allow(3_000_000) {
		t.Fatal("超额请求不应放行")
	}
	now = now.Add(3 * time.Second)
	if b.DenialStreak() != 0 {
		t.Fatal("发送侧安静后应视为不再饱和")
	}
}
