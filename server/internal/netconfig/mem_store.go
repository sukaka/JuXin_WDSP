package netconfig

import (
	"context"
	"sync"
	"time"
)

// MemStore 是内存期望配置仓储（单元测试用）。
type MemStore struct {
	mu   sync.Mutex
	rows map[string]memEntry
}

type memEntry struct {
	cfg       Config
	updatedAt time.Time
}

// NewMemStore 创建内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{rows: map[string]memEntry{}}
}

// Get 读取节点期望配置（语义同 SQL 仓储）。
func (m *MemStore) Get(_ context.Context, nodeName string) (Config, time.Time, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.rows[nodeName]
	if !ok {
		return Config{}, time.Time{}, false, nil
	}
	return e.cfg, e.updatedAt, true, nil
}

// Save 整体替换节点期望配置（语义同 SQL 仓储）。
func (m *MemStore) Save(_ context.Context, nodeName string, cfg Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg.normalize()
	m.rows[nodeName] = memEntry{cfg: cfg, updatedAt: time.Now().UTC()}
	return nil
}
