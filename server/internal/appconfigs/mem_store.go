package appconfigs

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// MemStore 进程内仓储：与 SQL Store 相同业务语义（校验、乐观锁、排序），
// 供单测与无库环境驱动真实 Handler。内存实现无应用表，不模拟外键
// （任意 appID 均视为存在；ErrAppNotFound 仅 SQL Store 产生）。
type MemStore struct {
	mu         sync.Mutex
	headers    map[uuid.UUID]*HeaderConfigRecord // appID → 头合规配置记录
	tlsConfigs map[uuid.UUID]*TLSConfigRecord    // appID → TLS/HTTP 协议策略记录
	routes     map[uuid.UUID]*PathRoute          // routeID → 路径转发
}

// NewMemStore 创建空内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{
		headers:    map[uuid.UUID]*HeaderConfigRecord{},
		tlsConfigs: map[uuid.UUID]*TLSConfigRecord{},
		routes:     map[uuid.UUID]*PathRoute{},
	}
}

var (
	_ Repository                       = (*MemStore)(nil)
	_ gatewayconfig.AppConfigsProvider = (*MemStore)(nil)
)

// GetHeaderConfig 查询应用头合规配置；无记录返回 (nil, nil)。
func (m *MemStore) GetHeaderConfig(ctx context.Context, appID uuid.UUID) (*gatewayconfig.AppHeaderConfig, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.headers[appID]
	if !ok {
		return nil, nil
	}
	return cloneHeaderConfig(rec.Config), nil
}

// GetHeaderConfigRecord 查询头合规配置完整记录；无记录返回 (nil, nil)。
func (m *MemStore) GetHeaderConfigRecord(ctx context.Context, appID uuid.UUID) (*HeaderConfigRecord, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.headers[appID]
	if !ok {
		return nil, nil
	}
	out := *rec
	out.Config = cloneHeaderConfig(rec.Config)
	return &out, nil
}

// UpsertHeaderConfig 全量 upsert + version 乐观锁（语义同 SQL Store）。
func (m *MemStore) UpsertHeaderConfig(ctx context.Context, appID uuid.UUID, cfg *gatewayconfig.AppHeaderConfig, updatedBy uuid.UUID, expectVersion int) (int, error) {
	_ = ctx
	if err := validateHeaderConfig(cfg); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	var ub *uuid.UUID
	if updatedBy != uuid.Nil {
		ub = &updatedBy
	}
	if expectVersion > 0 {
		rec, ok := m.headers[appID]
		if !ok || rec.Version != expectVersion {
			return 0, ErrVersionConflict
		}
		rec.Config = cloneHeaderConfig(cfg)
		rec.UpdatedBy = ub
		rec.UpdatedAt = now
		rec.Version++
		return rec.Version, nil
	}
	if _, ok := m.headers[appID]; ok {
		return 0, ErrVersionConflict
	}
	m.headers[appID] = &HeaderConfigRecord{
		Config:    cloneHeaderConfig(cfg),
		Version:   1,
		UpdatedBy: ub,
		CreatedAt: now,
		UpdatedAt: now,
	}
	return 1, nil
}

// ListEnabledPathRoutes 查询 ENABLED 路径转发（priority 升序，同优先级长前缀优先）。
func (m *MemStore) ListEnabledPathRoutes(ctx context.Context, appID uuid.UUID) ([]gatewayconfig.AppPathRoute, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	var rs []*PathRoute
	for _, r := range m.routes {
		if r.ApplicationID == appID && r.Status == "ENABLED" {
			rs = append(rs, r)
		}
	}
	sortRoutes(rs)
	out := []gatewayconfig.AppPathRoute{}
	for _, r := range rs {
		out = append(out, gatewayconfig.AppPathRoute{
			PathPrefix:     r.PathPrefix,
			UpstreamScheme: r.UpstreamScheme,
			UpstreamHost:   r.UpstreamHost,
			UpstreamPort:   r.UpstreamPort,
			StripPrefix:    r.StripPrefix,
			Priority:       r.Priority,
		})
	}
	return out, nil
}

// ListPathRoutes 分页查询（priority 升序，前缀字典序，与 SQL List 一致）。
func (m *MemStore) ListPathRoutes(ctx context.Context, appID uuid.UUID, page, pageSize int) ([]PathRoute, int64, error) {
	_ = ctx
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var rs []*PathRoute
	for _, r := range m.routes {
		if r.ApplicationID == appID {
			rs = append(rs, r)
		}
	}
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].Priority != rs[j].Priority {
			return rs[i].Priority < rs[j].Priority
		}
		if rs[i].PathPrefix != rs[j].PathPrefix {
			return rs[i].PathPrefix < rs[j].PathPrefix
		}
		return rs[i].CreatedAt.Before(rs[j].CreatedAt)
	})
	total := int64(len(rs))
	start := (page - 1) * pageSize
	if start >= len(rs) {
		return []PathRoute{}, total, nil
	}
	end := start + pageSize
	if end > len(rs) {
		end = len(rs)
	}
	out := []PathRoute{}
	for _, r := range rs[start:end] {
		out = append(out, *clonePathRoute(r))
	}
	return out, total, nil
}

// GetPathRoute 查询单条路径转发（限定应用）。
func (m *MemStore) GetPathRoute(ctx context.Context, appID, routeID uuid.UUID) (*PathRoute, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.routes[routeID]
	if !ok || r.ApplicationID != appID {
		return nil, ErrNotFound
	}
	return clonePathRoute(r), nil
}

// CreatePathRoute 创建路径转发（同前缀+源站重复报 ErrRouteConflict）。
func (m *MemStore) CreatePathRoute(ctx context.Context, r *PathRoute) error {
	_ = ctx
	if err := validatePathRoute(r); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.routes {
		if existing.ApplicationID == r.ApplicationID &&
			existing.PathPrefix == r.PathPrefix &&
			existing.UpstreamHost == r.UpstreamHost &&
			existing.UpstreamPort == r.UpstreamPort {
			return ErrRouteConflict
		}
	}
	now := time.Now().UTC()
	stored := clonePathRoute(r)
	stored.ID = uuid.New()
	stored.CreatedAt = now
	stored.UpdatedAt = now
	stored.Version = 1
	m.routes[stored.ID] = stored
	r.ID = stored.ID
	r.CreatedAt = now
	r.UpdatedAt = now
	r.Version = 1
	return nil
}

// UpdatePathRoute 全量更新（version 乐观锁）。
func (m *MemStore) UpdatePathRoute(ctx context.Context, r *PathRoute) error {
	_ = ctx
	if err := validatePathRoute(r); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, ok := m.routes[r.ID]
	if !ok || stored.ApplicationID != r.ApplicationID {
		return ErrNotFound
	}
	if stored.Version != r.Version {
		return ErrVersionConflict
	}
	for id, existing := range m.routes {
		if id != r.ID && existing.ApplicationID == r.ApplicationID &&
			existing.PathPrefix == r.PathPrefix &&
			existing.UpstreamHost == r.UpstreamHost &&
			existing.UpstreamPort == r.UpstreamPort {
			return ErrRouteConflict
		}
	}
	createdBy, createdAt := stored.CreatedBy, stored.CreatedAt
	newVersion := stored.Version + 1
	updated := clonePathRoute(r)
	updated.CreatedBy = createdBy
	updated.CreatedAt = createdAt
	updated.UpdatedAt = time.Now().UTC()
	updated.Version = newVersion
	m.routes[r.ID] = updated
	r.CreatedBy = createdBy
	r.CreatedAt = createdAt
	r.UpdatedAt = updated.UpdatedAt
	r.Version = newVersion
	return nil
}

// DeletePathRoute 删除路径转发（限定应用）。
func (m *MemStore) DeletePathRoute(ctx context.Context, appID, routeID uuid.UUID) error {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.routes[routeID]
	if !ok || r.ApplicationID != appID {
		return ErrNotFound
	}
	delete(m.routes, routeID)
	return nil
}

// sortRoutes 发布侧排序：priority 升序，同优先级长前缀优先。
func sortRoutes(rs []*PathRoute) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].Priority != rs[j].Priority {
			return rs[i].Priority < rs[j].Priority
		}
		if len(rs[i].PathPrefix) != len(rs[j].PathPrefix) {
			return len(rs[i].PathPrefix) > len(rs[j].PathPrefix)
		}
		return rs[i].PathPrefix < rs[j].PathPrefix
	})
}

func cloneHeaderConfig(c *gatewayconfig.AppHeaderConfig) *gatewayconfig.AppHeaderConfig {
	if c == nil {
		return nil
	}
	out := *c
	out.CustomRequestRules = append([]gatewayconfig.HeaderRule(nil), c.CustomRequestRules...)
	out.CustomResponseRules = append([]gatewayconfig.HeaderRule(nil), c.CustomResponseRules...)
	return &out
}

func clonePathRoute(r *PathRoute) *PathRoute {
	if r == nil {
		return nil
	}
	out := *r
	return &out
}
