// Package ratelimit CC限速算法：令牌桶与滑动窗口，内存与 Valkey 两种后端。
//
// 设计说明：
//   - 令牌桶：匀速 refill（limit/window），容量为 burst（缺省取 limit），
//     适合实时限速，允许短突发；
//   - 滑动窗口：记录窗口内请求时间戳（Valkey ZSET）或双固定窗口加权（内存），
//     适合封禁判断，边界更严格；
//   - 时间精度：毫秒；内存后端取进程时钟，Valkey 后端取客户端时钟（单节点一致）；
//   - 故障策略由调用方决定（Fail-open/Fail-closed），本包只返回错误。
package ratelimit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
)

// Algorithm 限速算法。
type Algorithm string

const (
	TokenBucket   Algorithm = "TOKEN_BUCKET"
	SlidingWindow Algorithm = "SLIDING_WINDOW"
)

// Result 限速判定结果。
type Result struct {
	Allowed    bool
	Current    int64 // 当前窗口计数（滑动窗口）或剩余令牌取整（令牌桶）
	RetryAfter time.Duration
}

// Limiter 限速器接口。
type Limiter interface {
	Allow(ctx context.Context, key string, algo Algorithm, limit int64, window time.Duration, burst int64) (Result, error)
}

// ---------- 内存后端 ----------

type memBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

type memWindow struct {
	mu        sync.Mutex
	currStart time.Time
	curr      int64
	prev      int64
}

// MemoryLimiter 有界内存限速器（键上限防随机键攻击）。
type MemoryLimiter struct {
	buckets *counters.MemoryMap
	windows *counters.MemoryMap
	now     func() time.Time // 测试可注入
}

// NewMemoryLimiter 构造内存限速器。
func NewMemoryLimiter(maxKeys int) *MemoryLimiter {
	return &MemoryLimiter{
		buckets: counters.NewMemoryMap(maxKeys),
		windows: counters.NewMemoryMap(maxKeys),
		now:     time.Now,
	}
}

// KeysCount 当前键数量（指标）。
func (m *MemoryLimiter) KeysCount() int {
	return m.buckets.Len() + m.windows.Len()
}

// Allow 内存限速判定。
func (m *MemoryLimiter) Allow(_ context.Context, key string, algo Algorithm, limit int64, window time.Duration, burst int64) (Result, error) {
	if limit <= 0 || window <= 0 {
		return Result{}, fmt.Errorf("invalid limit/window")
	}
	if burst <= 0 {
		burst = limit
	}
	switch algo {
	case TokenBucket:
		return m.tokenBucket(key, limit, window, burst), nil
	case SlidingWindow:
		return m.slidingWindow(key, limit, window), nil
	default:
		return Result{}, fmt.Errorf("unknown algorithm %q", algo)
	}
}

func (m *MemoryLimiter) tokenBucket(key string, limit int64, window time.Duration, burst int64) Result {
	v := m.buckets.GetOrCreate("tb:"+key, func() interface{} {
		return &memBucket{tokens: float64(burst), last: m.now()}
	})
	b := v.(*memBucket)
	b.mu.Lock()
	defer b.mu.Unlock()
	now := m.now()
	rate := float64(limit) / window.Seconds() // 令牌/秒
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		// Current 表示已用量近似（burst - remaining）
		return Result{Allowed: true, Current: burst - int64(b.tokens)}
	}
	retry := time.Duration((1-b.tokens)/rate*1000) * time.Millisecond
	// 拒绝时 Current 至少为 limit，避免事件中心显示 0
	return Result{Allowed: false, Current: limit, RetryAfter: retry}
}

// slidingWindow 双固定窗口加权近似（标准 sliding window counter）。
func (m *MemoryLimiter) slidingWindow(key string, limit int64, window time.Duration) Result {
	v := m.windows.GetOrCreate("sw:"+key, func() interface{} {
		return &memWindow{currStart: m.now()}
	})
	w := v.(*memWindow)
	w.mu.Lock()
	defer w.mu.Unlock()
	now := m.now()
	elapsed := now.Sub(w.currStart)
	if elapsed >= 2*window {
		w.prev = 0
		w.curr = 0
		w.currStart = now
		elapsed = 0
	} else if elapsed >= window {
		w.prev = w.curr
		w.curr = 0
		w.currStart = w.currStart.Add(window)
		elapsed = now.Sub(w.currStart)
	}
	weight := 1 - elapsed.Seconds()/window.Seconds()
	estimate := w.curr + int64(float64(w.prev)*weight)
	if estimate < limit {
		w.curr++
		return Result{Allowed: true, Current: estimate + 1}
	}
	retry := window - elapsed
	return Result{Allowed: false, Current: estimate, RetryAfter: retry}
}

// ---------- Valkey 后端 ----------

// tokenBucketLua 原子令牌桶：HASH{tokens, ts}，返回 {allowed, floor(tokens), retry_ms}。
const tokenBucketLua = `
local data = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local burst = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])  -- 令牌/毫秒
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil then tokens = burst end
if ts == nil then ts = now end
tokens = math.min(burst, tokens + (now - ts) * rate)
local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end
redis.call('HMSET', KEYS[1], 'tokens', tokens, 'ts', now)
redis.call('PEXPIRE', KEYS[1], ttl)
local retry = 0
if allowed == 0 then retry = math.ceil((1 - tokens) / rate) end
return {allowed, math.floor(tokens), retry}
`

// slidingWindowLua 精确滑动窗口（ZSET 时间戳），返回 {allowed, count, retry_ms}。
const slidingWindowLua = `
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local ttl = tonumber(ARGV[5])
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - window)
local count = redis.call('ZCARD', KEYS[1])
local allowed = 0
if count < limit then
  redis.call('ZADD', KEYS[1], now, member)
  count = count + 1
  allowed = 1
end
redis.call('PEXPIRE', KEYS[1], ttl)
local retry = 0
if allowed == 0 then
  local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  if #oldest >= 2 then retry = tonumber(oldest[2]) + window - now end
end
return {allowed, count, retry}
`

// ValkeyLimiter Valkey 限速器（多进程共享）。
type ValkeyLimiter struct {
	cli    counters.ValkeyClient
	seq    atomic.Int64 // ZSET member 唯一序列（保持脚本确定性）
	inst   string       // 实例级随机前缀：多节点同毫秒同序号时 member 仍唯一，防 ZADD 互相覆盖少计
	now    func() time.Time
	keyPfx string
}

// NewValkeyLimiter 构造 Valkey 限速器（keyPfx 默认 jiuzhang:guard:cc）。
func NewValkeyLimiter(cli counters.ValkeyClient, keyPrefix string) *ValkeyLimiter {
	if keyPrefix == "" {
		keyPrefix = "jiuzhang:guard:cc"
	}
	return &ValkeyLimiter{cli: cli, keyPfx: keyPrefix, now: time.Now, inst: newInstanceID()}
}

// newInstanceID 启动期实例 ID：8 字节 crypto/rand hex；随机源故障时派生
// 纳秒时间+PID 的 SHA-256 截断（与 trace.go 派生兜底同一思路——仅作 ZSET member
// 跨节点去重，不构成安全边界）。
func newInstanceID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	sum := sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10) + "|" + strconv.Itoa(os.Getpid())))
	return hex.EncodeToString(sum[:])[:16]
}

// Allow Valkey 限速判定（一次原子脚本往返）。
func (v *ValkeyLimiter) Allow(ctx context.Context, key string, algo Algorithm, limit int64, window time.Duration, burst int64) (Result, error) {
	if limit <= 0 || window <= 0 {
		return Result{}, fmt.Errorf("invalid limit/window")
	}
	if burst <= 0 {
		burst = limit
	}
	fullKey := v.keyPfx + ":" + key
	nowMs := v.now().UnixMilli()
	ttlMs := window.Milliseconds()*2 + 60000 // 窗口两倍 + 余量，键自动过期
	switch algo {
	case TokenBucket:
		ratePerMs := float64(limit) / float64(window.Milliseconds())
		out, err := v.cli.Eval(ctx, tokenBucketLua, []string{fullKey}, []string{
			strconv.FormatInt(burst, 10),
			strconv.FormatFloat(ratePerMs, 'f', -1, 64),
			strconv.FormatInt(nowMs, 10),
			strconv.FormatInt(ttlMs, 10),
		})
		if err != nil {
			return Result{}, err
		}
		return Result{
			Allowed:    toInt64(out[0]) == 1,
			Current:    toInt64(out[1]),
			RetryAfter: time.Duration(toInt64(out[2])) * time.Millisecond,
		}, nil
	case SlidingWindow:
		member := v.inst + "-" + strconv.FormatInt(nowMs, 10) + "-" + strconv.FormatInt(v.seq.Add(1), 10)
		out, err := v.cli.Eval(ctx, slidingWindowLua, []string{fullKey}, []string{
			strconv.FormatInt(nowMs, 10),
			strconv.FormatInt(window.Milliseconds(), 10),
			strconv.FormatInt(limit, 10),
			member,
			strconv.FormatInt(ttlMs, 10),
		})
		if err != nil {
			return Result{}, err
		}
		return Result{
			Allowed:    toInt64(out[0]) == 1,
			Current:    toInt64(out[1]),
			RetryAfter: time.Duration(toInt64(out[2])) * time.Millisecond,
		}, nil
	default:
		return Result{}, fmt.Errorf("unknown algorithm %q", algo)
	}
}

func toInt64(v interface{}) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	default:
		return 0
	}
}
