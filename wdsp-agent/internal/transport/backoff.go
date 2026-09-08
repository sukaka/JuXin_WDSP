// 断线重连指数退避（契约 §6：1s 起，上限 60s）。
package transport

import "time"

// Backoff 指数退避器（非并发安全，单 goroutine 使用）。
type Backoff struct {
	min time.Duration
	max time.Duration
	cur time.Duration
}

// NewBackoff 创建退避器；min/max<=0 用契约默认（1s/60s）。
func NewBackoff(min, max time.Duration) *Backoff {
	if min <= 0 {
		min = time.Second
	}
	if max <= 0 {
		max = 60 * time.Second
	}
	return &Backoff{min: min, max: max}
}

// Next 返回本次应等待的时长并加倍（封顶 max）。
func (b *Backoff) Next() time.Duration {
	if b.cur <= 0 {
		b.cur = b.min
		return b.cur
	}
	b.cur *= 2
	if b.cur > b.max {
		b.cur = b.max
	}
	return b.cur
}

// Reset 成功一次后重置。
func (b *Backoff) Reset() { b.cur = 0 }
