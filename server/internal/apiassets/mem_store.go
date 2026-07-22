package apiassets

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemStore 进程内端点仓储：与 SQL Store 相同业务语义，供单测与无库环境驱动真实 Handler。
type MemStore struct {
	mu   sync.Mutex
	byID map[uuid.UUID]*Endpoint
	byKey map[string]uuid.UUID
}

// NewMemStore 创建空内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{
		byID:  map[uuid.UUID]*Endpoint{},
		byKey: map[string]uuid.UUID{},
	}
}

var _ Repository = (*MemStore)(nil)

// UpsertDiscovery 幂等登记发现结果。
func (m *MemStore) UpsertDiscovery(ctx context.Context, method, pathTemplate string, confidence float64, isAPI bool) (*Endpoint, error) {
	_ = ctx
	method = strings.ToUpper(strings.TrimSpace(method))
	pathTemplate = strings.TrimSpace(pathTemplate)
	if method == "" || pathTemplate == "" {
		return nil, errRequired
	}
	key := method + " " + pathTemplate
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.byKey[key]; ok {
		e := m.byID[id]
		e.HitCount++
		if confidence > e.Confidence {
			e.Confidence = confidence
		}
		e.LastSeenAt = time.Now().UTC()
		return cloneEP(e), nil
	}
	now := time.Now().UTC()
	id := uuid.New()
	e := &Endpoint{
		ID: id, Method: method, PathTemplate: pathTemplate, EndpointKey: key,
		Confidence: confidence, Status: "DISCOVERED", IsAPI: isAPI, HitCount: 1,
		FirstSeenAt: now, LastSeenAt: now,
	}
	m.byID[id] = e
	m.byKey[key] = id
	return cloneEP(e), nil
}

// List 列表。
func (m *MemStore) List(ctx context.Context, status string, page, pageSize int) ([]Endpoint, int64, error) {
	_ = ctx
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []Endpoint
	for _, e := range m.byID {
		if status != "" && e.Status != status {
			continue
		}
		all = append(all, *cloneEP(e))
	}
	total := int64(len(all))
	start := (page - 1) * pageSize
	if start >= len(all) {
		return []Endpoint{}, total, nil
	}
	end := start + pageSize
	if end > len(all) {
		end = len(all)
	}
	return all[start:end], total, nil
}

// Confirm 确认端点。
func (m *MemStore) Confirm(ctx context.Context, id uuid.UUID) (*Endpoint, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	now := time.Now().UTC()
	e.Status = "CONFIRMED"
	e.ConfirmedAt = &now
	return cloneEP(e), nil
}

// GetByID 查询。
func (m *MemStore) GetByID(ctx context.Context, id uuid.UUID) (*Endpoint, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneEP(e), nil
}

func cloneEP(e *Endpoint) *Endpoint {
	cp := *e
	if e.ConfirmedAt != nil {
		t := *e.ConfirmedAt
		cp.ConfirmedAt = &t
	}
	return &cp
}

// errRequired 与 SQL 路径校验一致。
var errRequired = errString("method and path_template required")

type errString string

func (e errString) Error() string { return string(e) }
