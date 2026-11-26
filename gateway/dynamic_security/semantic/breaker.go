package semantic

import (
	"sync"
	"time"
)

// BreakerState 熔断器三态枚举。
type BreakerState string

const (
	BreakerClosed   BreakerState = "CLOSED"
	BreakerOpen     BreakerState = "OPEN"
	BreakerHalfOpen BreakerState = "HALF_OPEN"
)

// CircuitBreaker 并发安全的连续失败熔断器：
//   - Closed：正常放行；连续失败达到 failureThreshold 后切入 Open；
//   - Open：快速拒绝所有请求；持续 openDuration 后切入 HalfOpen 并仅放行单条探测请求；
//   - HalfOpen：探测成功回到 Closed 并清零计数；探测失败立刻重回 Open 并重置计时。
type CircuitBreaker struct {
	mu                  sync.Mutex
	failureThreshold    int
	openDuration        time.Duration
	now                 func() time.Time
	state               BreakerState
	consecutiveFailures int
	openedAt            time.Time
	halfOpenInFlight    bool
}

// NewCircuitBreaker 构造熔断器；非法阈值按默认边界兜底。
func NewCircuitBreaker(failureThreshold int, openDuration time.Duration) *CircuitBreaker {
	return newCircuitBreakerWithClock(failureThreshold, openDuration, time.Now)
}

func newCircuitBreakerWithClock(failureThreshold int, openDuration time.Duration, clock func() time.Time) *CircuitBreaker {
	if failureThreshold < 1 {
		failureThreshold = DefaultCircuitFailureThreshold
	}
	if openDuration <= 0 {
		openDuration = time.Duration(DefaultCircuitOpenSeconds) * time.Second
	}
	if clock == nil {
		clock = time.Now
	}
	return &CircuitBreaker{
		failureThreshold: failureThreshold,
		openDuration:     openDuration,
		now:              clock,
		state:            BreakerClosed,
	}
}

// Allow 判断当前请求是否允许发起 sidecar 调用。
// 返回 allowed=true 时，调用方必须在请求结束后调用 RecordSuccess 或 RecordFailure，
// 以确保 HalfOpen 单探针锁正确释放。
func (b *CircuitBreaker) Allow() (bool, BreakerState) {
	if b == nil {
		return true, BreakerClosed
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case BreakerClosed:
		return true, BreakerClosed
	case BreakerOpen:
		if b.now().Sub(b.openedAt) >= b.openDuration {
			b.state = BreakerHalfOpen
			b.halfOpenInFlight = true
			return true, BreakerHalfOpen
		}
		return false, BreakerOpen
	case BreakerHalfOpen:
		if !b.halfOpenInFlight {
			b.halfOpenInFlight = true
			return true, BreakerHalfOpen
		}
		return false, BreakerHalfOpen
	default:
		b.state = BreakerClosed
		return true, BreakerClosed
	}
}

// RecordSuccess 记录一次成功的 sidecar 响应，将熔断器恢复至 Closed 并清零失败计数。
func (b *CircuitBreaker) RecordSuccess() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = BreakerClosed
	b.consecutiveFailures = 0
	b.openedAt = time.Time{}
	b.halfOpenInFlight = false
}

// RecordFailure 记录一次失败（连接不可用、超时、非 200 响应、非法/超大响应体）。
func (b *CircuitBreaker) RecordFailure() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == BreakerHalfOpen {
		b.state = BreakerOpen
		b.openedAt = b.now()
		b.halfOpenInFlight = false
		return
	}
	b.consecutiveFailures++
	if b.consecutiveFailures >= b.failureThreshold {
		b.state = BreakerOpen
		b.openedAt = b.now()
		b.halfOpenInFlight = false
	}
}

// State 返回当前逻辑熔断状态（若 Open 已过冷却期则返回 HalfOpen）。
func (b *CircuitBreaker) State() BreakerState {
	if b == nil {
		return BreakerClosed
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == BreakerOpen && b.now().Sub(b.openedAt) >= b.openDuration {
		return BreakerHalfOpen
	}
	return b.state
}

// ConsecutiveFailures 返回当前连续失败次数（仅用于观测与测试）。
func (b *CircuitBreaker) ConsecutiveFailures() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.consecutiveFailures
}
