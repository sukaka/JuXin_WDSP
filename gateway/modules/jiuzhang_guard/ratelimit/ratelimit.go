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
	// Peek 只读查询指定键当前用量（与 Allow 的 Result.Current 同口径）：
	// 不建键、不消费令牌、不写存储；键不存在 found=false。
	// 供调试回显端点（阶段5 §十七 CC 精确计数探针）使用，非请求热路径。
	Peek(ctx context.Context, key string, algo Algorithm, limit int64, window time.Duration, burst int64) (count int64, found bool, err error)
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

// Peek 内存只读查询：不建键、不消费、不写回（计数快照与 Allow 同口径近似）。
func (m *MemoryLimiter) Peek(_ context.Context, key string, algo Algorithm, limit int64, window time.Duration, burst int64) (int64, bool, error) {
	if limit <= 0 || window <= 0 {
		return 0, false, fmt.Errorf("invalid limit/window")
	}
	if burst <= 0 {
		burst = limit
	}
	switch algo {
	case TokenBucket:
		v, ok := m.buckets.Get("tb:" + key)
		if !ok {
			return 0, false, nil
		}
		b := v.(*memBucket)
		b.mu.Lock()
		defer b.mu.Unlock()
		rate := float64(limit) / window.Seconds() // 令牌/秒
		tokens := b.tokens + m.now().Sub(b.last).Seconds()*rate
		if tokens > float64(burst) {
			tokens = float64(burst)
		}
		used := burst - int64(tokens)
		if used < 0 {
			used = 0
		}
		return used, true, nil
	case SlidingWindow:
		v, ok := m.windows.Get("sw:" + key)
		if !ok {
			return 0, false, nil
		}
		w := v.(*memWindow)
		w.mu.Lock()
		defer w.mu.Unlock()
		elapsed := m.now().Sub(w.currStart)
		curr, prev := w.curr, w.prev
		switch {
		case elapsed >= 2*window:
			curr, prev, elapsed = 0, 0, 0
		case elapsed >= window:
			prev, curr = curr, 0
			elapsed -= window
		}
		weight := 1 - elapsed.Seconds()/window.Seconds()
		return curr + int64(float64(prev)*weight), true, nil
	default:
		return 0, false, fmt.Errorf("unknown algorithm %q", algo)
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

// tokenBucketLua 原子令牌桶：HASH{tokens, ts}，返回 {allowed, used, retry_ms}；
// used = burst - floor(tokens)（与 MemoryLimiter / peekTokenBucketLua 同口径，拒绝时至少为 limit）。
const tokenBucketLua = `
local data = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local burst = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])  -- 令牌/毫秒
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local limit = tonumber(ARGV[5])
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
local used = burst - math.floor(tokens)
if used < 0 then used = 0 end
if allowed == 0 and limit ~= nil and used < limit then used = limit end
return {allowed, used, retry}
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

// peekTokenBucketLua 只读令牌桶查询（纯 HMGET，不写不过期）：返回 {exists, used}，
// used = burst - floor(refill 后令牌数)，与 Allow 的 Current（已用量近似）同口径。
const peekTokenBucketLua = `
local data = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil or ts == nil then return {0, 0} end
local burst = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])  -- 令牌/毫秒
local now = tonumber(ARGV[3])
tokens = math.min(burst, tokens + (now - ts) * rate)
local used = burst - math.floor(tokens)
if used < 0 then used = 0 end
return {1, used}
`

// peekSlidingWindowLua 只读滑动窗口查询（EXISTS + ZCOUNT，不清理过期成员）：
// 返回 {exists, 窗口内计数}。
const peekSlidingWindowLua = `
local exists = redis.call('EXISTS', KEYS[1])
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local count = redis.call('ZCOUNT', KEYS[1], now - window, now)
return {exists, count}
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
			strconv.FormatInt(limit, 10),
		})
		if err != nil {
			return Result{}, err
		}
		if len(out) < 3 {
			return Result{}, fmt.Errorf("unexpected valkey token_bucket reply length: %d", len(out))
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
		if len(out) < 3 {
			return Result{}, fmt.Errorf("unexpected valkey sliding_window reply length: %d", len(out))
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

// Peek Valkey 只读查询（只读 Lua 脚本，不改变任何键内容）。
func (v *ValkeyLimiter) Peek(ctx context.Context, key string, algo Algorithm, limit int64, window time.Duration, burst int64) (int64, bool, error) {
	if limit <= 0 || window <= 0 {
		return 0, false, fmt.Errorf("invalid limit/window")
	}
	if burst <= 0 {
		burst = limit
	}
	fullKey := v.keyPfx + ":" + key
	nowMs := v.now().UnixMilli()
	switch algo {
	case TokenBucket:
		ratePerMs := float64(limit) / float64(window.Milliseconds())
		out, err := v.cli.Eval(ctx, peekTokenBucketLua, []string{fullKey}, []string{
			strconv.FormatInt(burst, 10),
			strconv.FormatFloat(ratePerMs, 'f', -1, 64),
			strconv.FormatInt(nowMs, 10),
		})
		if err != nil {
			return 0, false, err
		}
		if len(out) < 2 {
			return 0, false, fmt.Errorf("unexpected valkey peek token_bucket reply length: %d", len(out))
		}
		return toInt64(out[1]), toInt64(out[0]) == 1, nil
	case SlidingWindow:
		out, err := v.cli.Eval(ctx, peekSlidingWindowLua, []string{fullKey}, []string{
			strconv.FormatInt(nowMs, 10),
			strconv.FormatInt(window.Milliseconds(), 10),
		})
		if err != nil {
			return 0, false, err
		}
		if len(out) < 2 {
			return 0, false, fmt.Errorf("unexpected valkey peek sliding_window reply length: %d", len(out))
		}
		return toInt64(out[1]), toInt64(out[0]) == 1, nil
	default:
		return 0, false, fmt.Errorf("unknown algorithm %q", algo)
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
