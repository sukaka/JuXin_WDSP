// Package temporaryblock 临时封禁：Valkey 存储 + 网关内存缓存轮询。
//
// 设计：封禁记录存 Valkey HASH（field 为 ip|app 的哈希，值为 JSON，含过期时间），
// 网关后台轮询同步到内存，请求路径只查内存（微秒级）；
// 到期由网关本地判定失效（Refresh 同时对过期 field 做条件 HDel 防哈希单调膨胀）
// + 管理平台/采集器落库标记 EXPIRED；
// 人工解封由管理平台 HDel，网关下一轮轮询生效。
package temporaryblock

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
)

// DefaultHashKey Valkey 哈希键。
const DefaultHashKey = "jiuzhang:guard:tempblocks"

// pruneLua 过期 field 条件删除：仅当当前值与读取快照完全一致时 HDel——
// 防 HGETALL 与删除之间管理平台/网关对同 field 重封写入被误删（竞态窗口内新值不等于快照值）。
// KEYS[1] = 封禁哈希；ARGV = field,value 对；返回实际删除条数。
const pruneLua = `
local n = 0
for i = 1, #ARGV, 2 do
  if redis.call('HGET', KEYS[1], ARGV[i]) == ARGV[i + 1] then
    redis.call('HDEL', KEYS[1], ARGV[i])
    n = n + 1
  end
end
return {n}
`

// Block 临时封禁记录。
type Block struct {
	ID        string    `json:"id"`
	ClientIP  string    `json:"client_ip"`
	AppID     string    `json:"application_id"` // 空 = 全局
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason,omitempty"`
	Auto      bool      `json:"auto"` // true=自动封禁（CC触发）
}

// FieldKey 封禁字段键（ip|app 哈希，禁止拼接原始输入）。
func FieldKey(ip, appID string) string {
	return counters.HashParts(ip, appID)
}

// Store Valkey 封禁存储。
type Store struct {
	cli     counters.ValkeyClient
	hashKey string
}

// NewStore 构造存储。
func NewStore(cli counters.ValkeyClient, hashKey string) *Store {
	if hashKey == "" {
		hashKey = DefaultHashKey
	}
	return &Store{cli: cli, hashKey: hashKey}
}

// Put 写入封禁（JSON 内含过期时间）。
func (s *Store) Put(ctx context.Context, b Block) error {
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	return s.cli.HSet(ctx, s.hashKey, FieldKey(b.ClientIP, b.AppID), string(data))
}

// All 读取全部封禁（损坏条目跳过，不静默吞掉：返回解析错误数；
// raw 为 field→原始值快照，供 PruneIfUnchanged 条件删除比对）。
func (s *Store) All(ctx context.Context) (items map[string]Block, raw map[string]string, bad int, err error) {
	m, err := s.cli.HGetAll(ctx, s.hashKey)
	if err != nil {
		return nil, nil, 0, err
	}
	items = make(map[string]Block, len(m))
	for k, v := range m {
		var b Block
		if err := json.Unmarshal([]byte(v), &b); err != nil {
			bad++
			continue
		}
		items[k] = b
	}
	return items, m, bad, nil
}

// PruneIfUnchanged 条件删除 field（仅当当前值与 expected 快照一致；单 Lua 原子往返）。
// 用于 Refresh 清理过期封禁：值不匹配说明读后已被重封/改写，放弃删除等下轮再判。
func (s *Store) PruneIfUnchanged(ctx context.Context, expected map[string]string) error {
	if len(expected) == 0 {
		return nil
	}
	args := make([]string, 0, 2*len(expected))
	for f, v := range expected {
		args = append(args, f, v)
	}
	_, err := s.cli.Eval(ctx, pruneLua, []string{s.hashKey}, args)
	return err
}

// Remove 删除封禁（人工解封/到期清理）。
func (s *Store) Remove(ctx context.Context, ip, appID string) error {
	return s.cli.HDel(ctx, s.hashKey, FieldKey(ip, appID))
}

const (
	// defaultMaxCacheItems / defaultMaxLocalOnly 防止 Valkey 异常或自动封禁洪泛撑爆网关内存（M-G4）。
	defaultMaxCacheItems = 100000
	defaultMaxLocalOnly  = 100000
	defaultSweepInterval = 30 * time.Second
)

// Cache 网关侧内存缓存（后台轮询同步）。
type Cache struct {
	store    *Store
	interval time.Duration
	now      func() time.Time

	maxItems      int
	maxLocalOnly  int
	sweepInterval time.Duration

	mu    sync.RWMutex
	items map[string]Block
	// localOnly：Valkey Put 失败时保留的本地条目；Refresh 时合并回 items，避免被全量覆盖冲掉。
	// 成功同步到 Valkey 或过期后清除。人工解封（远程删除）不在此集合内，Refresh 会正常清除。
	localOnly map[string]Block
	lastSweep time.Time
	lastErr   error

	stopCh chan struct{}
	doneCh chan struct{}
}

// NewCache 构造缓存（interval<=0 取 1s）。
func NewCache(store *Store, interval time.Duration) *Cache {
	if interval <= 0 {
		interval = time.Second
	}
	return &Cache{
		store:         store,
		interval:      interval,
		now:           time.Now,
		maxItems:      defaultMaxCacheItems,
		maxLocalOnly:  defaultMaxLocalOnly,
		sweepInterval: defaultSweepInterval,
		items:         map[string]Block{},
		localOnly:     map[string]Block{},
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
}

func (c *Cache) maxItemsLimit() int {
	if c.maxItems > 0 {
		return c.maxItems
	}
	return defaultMaxCacheItems
}

func (c *Cache) maxLocalOnlyLimit() int {
	if c.maxLocalOnly > 0 {
		return c.maxLocalOnly
	}
	return defaultMaxLocalOnly
}

func (c *Cache) sweepIntervalDur() time.Duration {
	if c.sweepInterval > 0 {
		return c.sweepInterval
	}
	return defaultSweepInterval
}

// sweepExpiredMap 清理指定 map 中已过期条目（须持有 c.mu.Lock）。
func sweepExpiredMap(m map[string]Block, now time.Time) {
	for k, cur := range m {
		if !cur.ExpiresAt.IsZero() && !now.Before(cur.ExpiresAt) {
			delete(m, k)
		}
	}
}

// putBounded 向有界封禁 map 写入条目：满额时优先清理过期项，其次淘汰最早过期的自动封禁，
// 绝不让自动封禁洪泛挤出人工封禁（M-G4）。须持有 c.mu.Lock。
func putBounded(m map[string]Block, key string, b Block, now time.Time, maxCap int) {
	if _, exists := m[key]; exists {
		m[key] = b
		return
	}
	if len(m) >= maxCap {
		sweepExpiredMap(m, now)
	}
	if len(m) >= maxCap {
		var victimKey string
		var victimExp time.Time
		foundAuto := false
		for k, cur := range m {
			if !cur.Auto {
				continue
			}
			if !foundAuto || (!cur.ExpiresAt.IsZero() && (victimExp.IsZero() || cur.ExpiresAt.Before(victimExp))) {
				victimKey = k
				victimExp = cur.ExpiresAt
				foundAuto = true
			}
		}
		if foundAuto {
			delete(m, victimKey)
		} else if b.Auto {
			// 全部均为有效人工封禁时，自动封禁不得挤出人工封禁
			return
		} else {
			// 新条目也是人工封禁：淘汰最早过期的条目腾出空间
			var anyKey string
			var anyExp time.Time
			found := false
			for k, cur := range m {
				if !found || (!cur.ExpiresAt.IsZero() && (anyExp.IsZero() || cur.ExpiresAt.Before(anyExp))) {
					anyKey = k
					anyExp = cur.ExpiresAt
					found = true
				}
			}
			if found {
				delete(m, anyKey)
			}
		}
	}
	m[key] = b
}

// Refresh 立即同步一次（启动与测试用）。
// 以 Valkey 全量为准，再合并 localOnly（Put 失败的本地封禁），避免抖动冲掉本节点刚写入的 ban。
// 过期 field 同步从 Valkey 条件删除（读后未被改写才 HDel），防哈希随历史封禁单调膨胀。
func (c *Cache) Refresh(ctx context.Context) error {
	if c.store == nil {
		return nil
	}
	items, raw, _, err := c.store.All(ctx)
	if err != nil {
		c.mu.Lock()
		c.lastErr = err
		c.mu.Unlock()
		return err
	}
	now := c.now()
	expired := map[string]string{}
	for k, b := range items {
		if !b.ExpiresAt.IsZero() && !now.Before(b.ExpiresAt) {
			delete(items, k)
			expired[k] = raw[k]
		}
	}
	c.mu.Lock()
	// 合并 Valkey 写入失败的本地条目；若远程已有同 key 且过期更晚，以远程为准并清除 dirty
	itemsCap := c.maxItemsLimit()
	for k, local := range c.localOnly {
		if !local.ExpiresAt.IsZero() && !now.Before(local.ExpiresAt) {
			delete(c.localOnly, k)
			continue
		}
		if remote, ok := items[k]; ok {
			if !remote.ExpiresAt.Before(local.ExpiresAt) {
				delete(c.localOnly, k)
				continue
			}
		}
		putBounded(items, k, local, now, itemsCap)
	}
	c.items = items
	c.lastSweep = now
	c.lastErr = nil
	c.mu.Unlock()
	// 锁外清理 Valkey 过期 field（网络调用不阻塞请求路径读锁）；失败留下轮重试并如实上报。
	if err := c.store.PruneIfUnchanged(ctx, expired); err != nil {
		c.mu.Lock()
		c.lastErr = err
		c.mu.Unlock()
		return err
	}
	return nil
}

// Start 后台轮询（直到 Stop 或 ctx 取消）。
func (c *Cache) Start(ctx context.Context) {
	go func() {
		defer close(c.doneCh)
		t := time.NewTicker(c.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			case <-t.C:
				_ = c.Refresh(ctx)
			}
		}
	}()
}

// Stop 停止轮询。
func (c *Cache) Stop() {
	close(c.stopCh)
	<-c.doneCh
}

// PutLocal 网关自动封禁：写 Valkey（可能失败时仍本地生效）并更新内存。
// 按周期（默认 30s）或达到容量上限时才惰性清扫过期项，避免每次写入在写锁内做 O(N) 全表扫描；
// 同时对 items 与 localOnly 施加上限保护，优先淘汰过期与自动封禁，保护人工封禁不被挤出（M-G4）。
func (c *Cache) PutLocal(ctx context.Context, b Block) error {
	key := FieldKey(b.ClientIP, b.AppID)
	now := c.now()
	c.mu.Lock()
	if c.lastSweep.IsZero() {
		c.lastSweep = now
	} else if now.Sub(c.lastSweep) >= c.sweepIntervalDur() {
		sweepExpiredMap(c.items, now)
		c.lastSweep = now
	}
	putBounded(c.items, key, b, now, c.maxItemsLimit())
	c.mu.Unlock()
	if c.store == nil {
		return nil
	}
	if err := c.store.Put(ctx, b); err != nil {
		c.mu.Lock()
		putBounded(c.localOnly, key, b, now, c.maxLocalOnlyLimit())
		c.mu.Unlock()
		return err
	}
	c.mu.Lock()
	delete(c.localOnly, key)
	c.mu.Unlock()
	return nil
}

// Blocked 查询是否被封禁（全局或应用级），返回命中记录。
func (c *Cache) Blocked(ip netip.Addr, appID string) (Block, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := c.now()
	var manual Block
	var automatic Block
	manualFound, automaticFound := false, false
	for _, key := range []string{FieldKey(ip.String(), appID), FieldKey(ip.String(), "")} {
		b, ok := c.items[key]
		if !ok {
			continue
		}
		if !b.ExpiresAt.IsZero() && !now.Before(b.ExpiresAt) {
			continue // 已过期
		}
		if b.Auto {
			if !automaticFound {
				automatic, automaticFound = b, true
			}
			continue
		}
		if !manualFound {
			manual, manualFound = b, true
		}
	}
	if manualFound {
		return manual, true
	}
	if automaticFound {
		return automatic, true
	}
	return Block{}, false
}

// LastError 最近一次同步错误（指标/告警用）。
func (c *Cache) LastError() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastErr
}
