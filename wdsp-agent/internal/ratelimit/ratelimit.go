// Package ratelimit 出站数据通道令牌桶限速（契约 §6：flows+packets 字节，默认 100Mbps）。
//
// 仅计数据通道（flows/packets）字节，心跳/metrics 小流量不计入；
// 桶满时由调用方决定：RAW 丢弃计数，FLOW 转磁盘缓存。
package ratelimit

import (
	"sync"
	"time"
)

// Bucket 令牌桶（字节维度）。零值不可用，必须 New。
type Bucket struct {
	mu     sync.Mutex
	rate   float64 // 字节/秒
	burst  float64 // 桶容量（=1s 速率，下限 64KB）
	tokens float64
	last   time.Time
	now    func() time.Time // 测试可注入

	// 背压饱和信号（Phase 4 契约 §3.1「限速桶饱和：连续 N 秒无法足额发送」）：
	// Allow 失败期间累计连续拒绝时长，任一次成功消费清零。
	denyFirst time.Time
	denyLast  time.Time
}

// New 按 mbps（兆比特/秒，10^6 进制）创建令牌桶；mbps<=0 表示不限速。
func New(mbps float64) *Bucket {
	b := &Bucket{now: time.Now}
	b.SetRate(mbps)
	return b
}

// SetRate 热更新速率；mbps<=0 表示不限速。
func (b *Bucket) SetRate(mbps float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if mbps <= 0 {
		b.rate = 0
		b.burst = 0
		b.tokens = 0
		return
	}
	rate := mbps * 1e6 / 8
	burst := rate // 1 秒突发
	if burst < 64<<10 {
		burst = 64 << 10
	}
	b.rate = rate
	b.burst = burst
	if b.tokens > burst {
		b.tokens = burst
	}
	if b.last.IsZero() {
		b.tokens = burst // 新建满桶
		b.last = b.now()
	}
}

// Mbps 当前速率（0 = 不限速）。
func (b *Bucket) Mbps() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rate * 8 / 1e6
}

// Burst 当前令牌桶容量（字节）；不限速时返回 0。
func (b *Bucket) Burst() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return int(b.burst)
}

// Allow 尝试消费 n 字节；不限速或余额足够返回 true。
func (b *Bucket) Allow(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rate <= 0 {
		return true
	}
	b.refillLocked()
	if float64(n) > b.tokens {
		now := b.now()
		if b.denyFirst.IsZero() {
			b.denyFirst = now
		}
		b.denyLast = now
		return false
	}
	b.tokens -= float64(n)
	b.denyFirst = time.Time{}
	return true
}

// DenialStreak 当前连续拒绝时长（背压「限速桶饱和」信号）。
// 发送侧已安静（距上次拒绝超 2s，约两个冲刷周期）视为不再饱和返回 0。
func (b *Bucket) DenialStreak() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.denyFirst.IsZero() {
		return 0
	}
	now := b.now()
	if now.Sub(b.denyLast) > 2*time.Second {
		return 0
	}
	return now.Sub(b.denyFirst)
}

// Wait 阻塞直到可消费 n 字节或 done 关闭（预留；数据通道当前用 Allow 非阻塞语义）。
func (b *Bucket) refillLocked() {
	now := b.now()
	if b.last.IsZero() {
		b.last = now
		return
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed <= 0 {
		return
	}
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
}

// SetClock 注入测试时钟（同时重置时间锚点，下次消费按新时钟起算）。
func (b *Bucket) SetClock(now func() time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.now = now
	b.last = time.Time{}
}
