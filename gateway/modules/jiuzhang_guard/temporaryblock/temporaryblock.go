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

// Cache 网关侧内存缓存（后台轮询同步）。
type Cache struct {
	store    *Store
	interval time.Duration
	now      func() time.Time

	mu    sync.RWMutex
	items map[string]Block
	// localOnly：Valkey Put 失败时保留的本地条目；Refresh 时合并回 items，避免被全量覆盖冲掉。
	// 成功同步到 Valkey 或过期后清除。人工解封（远程删除）不在此集合内，Refresh 会正常清除。
	localOnly map[string]Block
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
		store:     store,
		interval:  interval,
		now:       time.Now,
		items:     map[string]Block{},
		localOnly: map[string]Block{},
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
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
		items[k] = local
	}
	c.items = items
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
// 写入前惰性清扫内存中的过期项：纯内存模式（store 为 nil）无后台轮询，
// 过期条目仅靠 Blocked 跳过永不删除，轮换源 IP（如 IPv6 /64）自动封禁可无限撑大 map；
// 每次写入顺带全量清扫后，map 规模有界于存活封禁数（写入频率受 CC 触发节流，O(n) 可接受）。
func (c *Cache) PutLocal(ctx context.Context, b Block) error {
	key := FieldKey(b.ClientIP, b.AppID)
	now := c.now()
	c.mu.Lock()
	for k, cur := range c.items {
		if !cur.ExpiresAt.IsZero() && !now.Before(cur.ExpiresAt) {
			delete(c.items, k)
		}
	}
	c.items[key] = b
	c.mu.Unlock()
	if c.store == nil {
		return nil
	}
	if err := c.store.Put(ctx, b); err != nil {
		c.mu.Lock()
		c.localOnly[key] = b
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
	for _, key := range []string{FieldKey(ip.String(), appID), FieldKey(ip.String(), "")} {
		b, ok := c.items[key]
		if !ok {
			continue
		}
		if !b.ExpiresAt.IsZero() && !now.Before(b.ExpiresAt) {
			continue // 已过期
		}
		return b, true
	}
	return Block{}, false
}

// LastError 最近一次同步错误（指标/告警用）。
func (c *Cache) LastError() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastErr
}
