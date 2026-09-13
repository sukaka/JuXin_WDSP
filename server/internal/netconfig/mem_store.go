package netconfig

import (
	"context"
	"sync"
	"time"

	"github.com/jiuzhang-waf/server/internal/sysconsole"
)

// MemStore 是内存期望配置仓储（单元测试用）。
type MemStore struct {
	mu   sync.Mutex
	rows map[string]memEntry
	// DNS/NTP 服务器设置原文（逗号分隔，语义同 system_settings network 组；
	// serversErr 非空时 NetworkServers 返回该错误，模拟读取失败降级路径）。
	dnsRaw     string
	ntpRaw     string
	serversErr error
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

// SetServers 设置 DNS/NTP 服务器设置原文（测试 NetworkServers 数据源）。
func (m *MemStore) SetServers(dnsRaw, ntpRaw string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dnsRaw, m.ntpRaw, m.serversErr = dnsRaw, ntpRaw, nil
}

// SetServersErr 模拟系统设置读取失败（NetworkServers 返回该错误）。
func (m *MemStore) SetServersErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.serversErr = err
}

// NetworkServers 解析预设的 DNS/NTP 设置原文（语义同 SQL 仓储：
// 原文非法记日志后按空处理，不视为错误；仅 serversErr 模拟的读取失败返回错误）。
func (m *MemStore) NetworkServers(_ context.Context) (dns, ntp []string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.serversErr != nil {
		return nil, nil, m.serversErr
	}
	dns, _ = sysconsole.ParseHostList(m.dnsRaw, maxServers)
	ntp, _ = sysconsole.ParseHostList(m.ntpRaw, maxServers)
	return dns, ntp, nil
}
