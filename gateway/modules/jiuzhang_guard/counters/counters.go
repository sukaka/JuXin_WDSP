// Package counters 计数器存储：有界内存 Map（防随机键耗尽）与 Valkey 客户端封装。
package counters

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	valkey "github.com/valkey-io/valkey-go"
)

// DefaultMaxKeys 内存键上限默认值。
const DefaultMaxKeys = 100000

// MemoryMap 并发安全、LRU 淘汰、容量有界的键值存储。
// 防随机 IP/URI 无限建键：超过 maxKeys 时淘汰最久未用键。
type MemoryMap struct {
	mu      sync.Mutex
	maxKeys int
	items   map[string]*list.Element
	lru     *list.List // front = 最近使用
}

type lruEntry struct {
	key   string
	value interface{}
}

// NewMemoryMap 构造有界 Map（maxKeys<=0 取默认）。
func NewMemoryMap(maxKeys int) *MemoryMap {
	if maxKeys <= 0 {
		maxKeys = DefaultMaxKeys
	}
	return &MemoryMap{
		maxKeys: maxKeys,
		items:   make(map[string]*list.Element, maxKeys),
		lru:     list.New(),
	}
}

// GetOrCreate 获取或原子创建键值（factory 仅在缺失时调用）。
func (m *MemoryMap) GetOrCreate(key string, factory func() interface{}) interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ok := m.items[key]; ok {
		m.lru.MoveToFront(el)
		return el.Value.(*lruEntry).value
	}
	// 容量淘汰
	for len(m.items) >= m.maxKeys {
		back := m.lru.Back()
		if back == nil {
			break
		}
		delete(m.items, back.Value.(*lruEntry).key)
		m.lru.Remove(back)
	}
	v := factory()
	el := m.lru.PushFront(&lruEntry{key: key, value: v})
	m.items[key] = el
	return v
}

// Len 当前键数量（指标）。
func (m *MemoryMap) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}

// MaxKeys 键上限（指标）。
func (m *MemoryMap) MaxKeys() int { return m.maxKeys }

// Purge 清空（测试用）。
func (m *MemoryMap) Purge() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = make(map[string]*list.Element, m.maxKeys)
	m.lru.Init()
}

// HashParts 将多个部分安全哈希为定长十六进制串（Valkey/内存键用，
// 禁止直接拼接用户输入与完整 URI）。
func HashParts(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		b := []byte(p)
		var lb [4]byte
		n := len(b)
		lb[0] = byte(n >> 24)
		lb[1] = byte(n >> 16)
		lb[2] = byte(n >> 8)
		lb[3] = byte(n)
		h.Write(lb[:])
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// ValkeyConfig Valkey 连接配置。
type ValkeyConfig struct {
	Address  string
	Username string
	Password string
	DB       int
}

// ValkeyClient Valkey 最小命令接口（便于测试替身与故障注入）。
type ValkeyClient interface {
	// Eval 执行 Lua 脚本，返回数组元素（int64/string）。
	Eval(ctx context.Context, script string, keys []string, args []string) ([]interface{}, error)
	// HSetJSON 写哈希字段（JSON 文本）。
	HSet(ctx context.Context, key, field, value string) error
	// HGetAll 读哈希全部字段。
	HGetAll(ctx context.Context, key string) (map[string]string, error)
	// HDel 删哈希字段。
	HDel(ctx context.Context, key string, fields ...string) error
	// Ping 健康检查。
	Ping(ctx context.Context) error
	// Close 关闭连接。
	Close() error
}

// realValkey 真实客户端（valkey-go，Apache-2.0）。
type realValkey struct {
	cli valkey.Client
}

// NewValkeyClient 创建真实 Valkey 客户端。
func NewValkeyClient(cfg ValkeyConfig) (ValkeyClient, error) {
	if cfg.Address == "" {
		return nil, errors.New("valkey address required")
	}
	opt := valkey.ClientOption{
		InitAddress: []string{cfg.Address},
		Username:    cfg.Username,
		Password:    cfg.Password,
		SelectDB:    cfg.DB,
	}
	cli, err := valkey.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("valkey client: %w", err)
	}
	return &realValkey{cli: cli}, nil
}

func (r *realValkey) Eval(ctx context.Context, script string, keys []string, args []string) ([]interface{}, error) {
	cmd := r.cli.B().Eval().Script(script).Numkeys(int64(len(keys))).Key(keys...).Arg(args...).Build()
	res := r.cli.Do(ctx, cmd)
	if err := res.Error(); err != nil {
		return nil, err
	}
	arr, err := res.ToArray()
	if err != nil {
		return nil, fmt.Errorf("eval result not array: %w", err)
	}
	out := make([]interface{}, len(arr))
	for i, m := range arr {
		if v, err := m.AsInt64(); err == nil {
			out[i] = v
			continue
		}
		if s, err := m.ToString(); err == nil {
			out[i] = s
			continue
		}
		out[i] = nil
	}
	return out, nil
}

func (r *realValkey) HSet(ctx context.Context, key, field, value string) error {
	cmd := r.cli.B().Hset().Key(key).FieldValue().FieldValue(field, value).Build()
	return r.cli.Do(ctx, cmd).Error()
}

func (r *realValkey) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	cmd := r.cli.B().Hgetall().Key(key).Build()
	res := r.cli.Do(ctx, cmd)
	if err := res.Error(); err != nil {
		return nil, err
	}
	return res.AsStrMap()
}

func (r *realValkey) HDel(ctx context.Context, key string, fields ...string) error {
	cmd := r.cli.B().Hdel().Key(key).Field(fields...).Build()
	return r.cli.Do(ctx, cmd).Error()
}

func (r *realValkey) Ping(ctx context.Context) error {
	cmd := r.cli.B().Ping().Build()
	return r.cli.Do(ctx, cmd).Error()
}

func (r *realValkey) Close() error {
	r.cli.Close()
	return nil
}
