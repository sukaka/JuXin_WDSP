package jwtverify

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// 缓存契约（§6.2）默认值：后台刷新 5 分钟、信任期 15 分钟、stale 宽限 0、
// 未知 kid 触发刷新的冷却 ≥30s、有界负缓存 256 项。
const (
	DefaultTrustTTL        = 15 * time.Minute
	DefaultRefreshInterval = 5 * time.Minute
	DefaultRefreshCooldown = 30 * time.Second
	defaultNegativeMax     = 256
	defaultNegativeTTL     = 5 * time.Minute
)

// Clock 可注入时钟。缓存年龄使用 Now 差值（真实实现含单调读数，时钟前后跳
// 不影响年龄）；JWT 声明时间校验使用同一 Now 的墙钟部分。测试注入假时钟。
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// KeysetSnapshot 不可变密钥集快照，原子替换；LoadedAt 取单调时钟读数。
type KeysetSnapshot struct {
	Keyset   *Keyset
	LoadedAt time.Time
	Remote   bool
}

// SnapshotState 快照可用状态。
type SnapshotState int

const (
	SnapshotValid   SnapshotState = iota // 信任期内，可完成验签
	SnapshotExpired                      // 硬过期（> trustTTL），不可用
	SnapshotCold                         // 冷启动无可用集合
)

// keysetCache 单个 issuer 的远程密钥集缓存：不可变快照 + 原子替换；
// 成功刷新全量替换（删除的 key 立即失效）；失败刷新不延长最后成功时间；
// 未知 kid 异步受限刷新（singleflight + 冷却 + 有界负缓存）。
type keysetCache struct {
	clock    Clock
	trustTTL time.Duration
	cooldown time.Duration
	negMax   int
	negTTL   time.Duration
	// fetchFn 拉取并解析远端 JWKS；由验证器注入（封装 Fetcher + ParseJWKS）。
	fetchFn func(ctx context.Context) (*Keyset, error)
	// onError 异步刷新失败回调（日志用，禁止含敏感内容）；可为 nil。
	onError func(err error)

	snap atomic.Pointer[KeysetSnapshot]

	mu          sync.Mutex
	inFlight    bool
	lastAttempt time.Time
	hasAttempt  bool
	negative    map[string]time.Time
}

func newKeysetCache(clock Clock, trustTTL, cooldown time.Duration,
	fetchFn func(ctx context.Context) (*Keyset, error), onError func(error)) *keysetCache {
	if trustTTL <= 0 {
		trustTTL = DefaultTrustTTL
	}
	if cooldown <= 0 {
		cooldown = DefaultRefreshCooldown
	}
	return &keysetCache{
		clock:    clock,
		trustTTL: trustTTL,
		cooldown: cooldown,
		negMax:   defaultNegativeMax,
		negTTL:   defaultNegativeTTL,
		fetchFn:  fetchFn,
		onError:  onError,
		negative: make(map[string]time.Time),
	}
}

// snapshot 读取当前快照与状态。Valid 表示在信任期内可完成验签。
func (c *keysetCache) snapshot() (*KeysetSnapshot, SnapshotState) {
	s := c.snap.Load()
	if s == nil {
		return nil, SnapshotCold
	}
	if c.clock.Now().Sub(s.LoadedAt) > c.trustTTL {
		return s, SnapshotExpired
	}
	return s, SnapshotValid
}

// RefreshSync 同步刷新（后台循环与测试使用）。成功：全量原子替换（删除的 key
// 立即失效）并清空负缓存；失败：不更新快照、不延长最后成功时间。
func (c *keysetCache) RefreshSync(ctx context.Context) error {
	if !c.beginAttempt() {
		return nil // singleflight：已有在途刷新
	}
	err := c.doRefresh(ctx)
	c.endAttempt(err == nil)
	return err
}

// NotifyUnknownKid 有效缓存内未知 kid：触发异步受限刷新。按缓存实例
// singleflight、刷新冷却 ≥30s、负缓存有界，禁止随机 kid 洪泛导致请求级
// 联网或无界内存增长。
func (c *keysetCache) NotifyUnknownKid(kid string) {
	c.mu.Lock()
	now := c.clock.Now()
	if ts, ok := c.negative[kid]; ok && now.Sub(ts) < c.negTTL {
		c.mu.Unlock()
		return
	}
	if len(c.negative) >= c.negMax {
		// 有界：满即整体清空重建（摊销有界，不做精确 LRU）。
		c.negative = make(map[string]time.Time, c.negMax)
	}
	c.negative[kid] = now
	if c.inFlightLocked() || c.inCooldownLocked(now) {
		c.mu.Unlock()
		return
	}
	c.inFlight = true
	c.lastAttempt = now
	c.hasAttempt = true
	c.mu.Unlock()
	go func() {
		err := c.doRefresh(context.Background())
		c.endAttempt(err == nil)
		if err != nil && c.onError != nil {
			c.onError(err)
		}
	}()
}

// notifyRefreshNeeded 快照缺失/硬过期时的异步刷新触发（与未知 kid 同受
// singleflight + 冷却约束，但不经负缓存）。
func (c *keysetCache) notifyRefreshNeeded() {
	c.mu.Lock()
	now := c.clock.Now()
	if c.inFlightLocked() || c.inCooldownLocked(now) {
		c.mu.Unlock()
		return
	}
	c.inFlight = true
	c.lastAttempt = now
	c.hasAttempt = true
	c.mu.Unlock()
	go func() {
		err := c.doRefresh(context.Background())
		c.endAttempt(err == nil)
		if err != nil && c.onError != nil {
			c.onError(err)
		}
	}()
}

func (c *keysetCache) beginAttempt() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inFlightLocked() {
		return false
	}
	c.inFlight = true
	c.lastAttempt = c.clock.Now()
	c.hasAttempt = true
	return true
}

func (c *keysetCache) endAttempt(success bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inFlight = false
	if success {
		c.negative = make(map[string]time.Time, c.negMax)
	}
}

func (c *keysetCache) inFlightLocked() bool { return c.inFlight }

func (c *keysetCache) inCooldownLocked(now time.Time) bool {
	return c.hasAttempt && now.Sub(c.lastAttempt) < c.cooldown
}

// doRefresh 实际拉取：成功则原子替换快照（LoadedAt 取当前单调读数）。
func (c *keysetCache) doRefresh(ctx context.Context) error {
	ks, err := c.fetchFn(ctx)
	if err != nil {
		return err
	}
	c.snap.Store(&KeysetSnapshot{Keyset: ks, LoadedAt: c.clock.Now(), Remote: true})
	return nil
}
