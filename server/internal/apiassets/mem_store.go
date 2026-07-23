package apiassets

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemStore 进程内端点仓储：与 SQL Store 相同业务语义，供单测与无库环境驱动真实 Handler。
type MemStore struct {
	mu      sync.Mutex
	byID    map[uuid.UUID]*Endpoint
	byKey   map[string]uuid.UUID
	assets  map[uuid.UUID]*Asset
	aliases map[string]uuid.UUID
	dims    map[uuid.UUID][]ClassificationDimension
	jobs    []*LearningJob
}

// NewMemStore 创建空内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{
		byID:    map[uuid.UUID]*Endpoint{},
		byKey:   map[string]uuid.UUID{},
		assets:  map[uuid.UUID]*Asset{},
		aliases: map[string]uuid.UUID{},
		dims:    map[uuid.UUID][]ClassificationDimension{},
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
		if confidence > e.APIConfidence {
			e.APIConfidence = confidence
		}
		e.LastSeenAt = time.Now().UTC()
		return cloneEP(e), nil
	}
	now := time.Now().UTC()
	id := uuid.New()
	e := &Endpoint{
		ID: id, HTTPMethod: method, NormalizedPath: pathTemplate, RawPathExample: pathTemplate,
		EndpointKey: key, APIConfidence: confidence, AssetStatus: "DISCOVERED",
		ProtocolType: "REST", LearningStatus: "NOT_STARTED", IsAPI: isAPI, HitCount: 1,
		FirstSeenAt: now, LastSeenAt: now,
	}
	m.byID[id] = e
	m.byKey[key] = id
	return cloneEP(e), nil
}

// List 列表（过滤语义与 SQL List 一致）。
func (m *MemStore) List(ctx context.Context, f ListFilter) ([]Endpoint, int64, error) {
	_ = ctx
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []Endpoint
	for _, e := range m.byID {
		if f.AssetStatus != "" && e.AssetStatus != f.AssetStatus {
			continue
		}
		if f.LearningStatus != "" && e.LearningStatus != f.LearningStatus {
			continue
		}
		if f.Keyword != "" && !strings.Contains(strings.ToLower(e.NormalizedPath), strings.ToLower(f.Keyword)) {
			continue
		}
		if f.ApplicationID != nil && (e.ApplicationID == nil || *e.ApplicationID != *f.ApplicationID) {
			continue
		}
		all = append(all, *cloneEP(e))
	}
	// 与 SQL 一致：last_seen_at 倒序
	sort.Slice(all, func(i, j int) bool { return all[i].LastSeenAt.After(all[j].LastSeenAt) })
	total := int64(len(all))
	start := (f.Page - 1) * f.PageSize
	if start >= len(all) {
		return []Endpoint{}, total, nil
	}
	end := start + f.PageSize
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
	e.AssetStatus = "CONFIRMED"
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

// Merge 把 other 并入 primary（命中数累加、历史键归档、删除 other）。
func (m *MemStore) Merge(ctx context.Context, primaryID, otherID uuid.UUID, actor string) (*Endpoint, error) {
	_ = ctx
	_ = actor
	if primaryID == otherID {
		return nil, fmt.Errorf("不能将端点合并到自身")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	primary, ok := m.byID[primaryID]
	if !ok {
		return nil, ErrNotFound
	}
	other, ok := m.byID[otherID]
	if !ok {
		return nil, ErrNotFound
	}
	m.aliases[other.EndpointKey] = primaryID
	primary.HitCount += other.HitCount
	if other.LastSeenAt.After(primary.LastSeenAt) {
		primary.LastSeenAt = other.LastSeenAt
	}
	delete(m.byID, otherID)
	delete(m.byKey, other.EndpointKey)
	delete(m.assets, otherID)
	delete(m.dims, otherID)
	jobs := m.jobs[:0]
	for _, j := range m.jobs {
		if j.EndpointID != otherID {
			jobs = append(jobs, j)
		}
	}
	m.jobs = jobs
	return cloneEP(primary), nil
}

// Split 按归一化路径拆分新端点（继承方法/置信度，状态 DISCOVERED）。
func (m *MemStore) Split(ctx context.Context, id uuid.UUID, newPaths []string, actor string) ([]Endpoint, error) {
	_ = ctx
	_ = actor
	if len(newPaths) == 0 {
		return nil, fmt.Errorf("拆分路径不能为空")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	src, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	created := []Endpoint{}
	for _, p := range newPaths {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("拆分路径不能为空")
		}
		key := src.HTTPMethod + " " + p
		if _, dup := m.byKey[key]; dup {
			return nil, fmt.Errorf("%w: %s", ErrEndpointConflict, key)
		}
		now := time.Now().UTC()
		nid := uuid.New()
		e := &Endpoint{
			ID: nid, ApplicationID: src.ApplicationID, DomainID: src.DomainID,
			HTTPMethod: src.HTTPMethod, NormalizedPath: p, RawPathExample: p,
			EndpointKey: key, APIConfidence: src.APIConfidence, AssetStatus: "DISCOVERED",
			ProtocolType: src.ProtocolType, LearningStatus: "NOT_STARTED", IsAPI: src.IsAPI,
			FirstSeenAt: now, LastSeenAt: now,
		}
		m.byID[nid] = e
		m.byKey[key] = nid
		created = append(created, *cloneEP(e))
	}
	return created, nil
}

// SetAssetStatus 变更资产状态。
func (m *MemStore) SetAssetStatus(ctx context.Context, id uuid.UUID, status, actor string) (*Endpoint, error) {
	_ = ctx
	_ = actor
	status = strings.ToUpper(strings.TrimSpace(status))
	if !validAssetStatuses[status] {
		return nil, fmt.Errorf("无效的资产状态：%s", status)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	e.AssetStatus = status
	return cloneEP(e), nil
}

// GetAsset 读取业务维度扩展；无记录返回 (nil, nil)。
func (m *MemStore) GetAsset(ctx context.Context, endpointID uuid.UUID) (*Asset, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.assets[endpointID]
	if !ok {
		return nil, nil
	}
	return cloneAsset(a), nil
}

// UpsertAsset 全量替换业务维度扩展。
func (m *MemStore) UpsertAsset(ctx context.Context, endpointID uuid.UUID, purpose, exposure, owner string, tags []string) (*Asset, error) {
	_ = ctx
	exposure = strings.ToUpper(strings.TrimSpace(exposure))
	if exposure == "" {
		exposure = "INTERNAL"
	}
	if tags == nil {
		tags = []string{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[endpointID]; !ok {
		return nil, ErrNotFound
	}
	now := time.Now().UTC()
	a, ok := m.assets[endpointID]
	if !ok {
		a = &Asset{EndpointID: endpointID, DataClassification: "UNKNOWN", CreatedAt: now}
		m.assets[endpointID] = a
	}
	a.Purpose = purpose
	a.Exposure = exposure
	a.Owner = owner
	a.Tags = append([]string{}, tags...)
	a.UpdatedAt = now
	return cloneAsset(a), nil
}

// SetClassificationLocked 设置分类锁定标记。
func (m *MemStore) SetClassificationLocked(ctx context.Context, id uuid.UUID, locked bool) error {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[id]
	if !ok {
		return ErrNotFound
	}
	e.ClassificationLocked = locked
	return nil
}

// SetLearningStatus 更新学习状态。
func (m *MemStore) SetLearningStatus(ctx context.Context, id uuid.UUID, status string) error {
	_ = ctx
	status = strings.ToUpper(strings.TrimSpace(status))
	if !validLearningStatuses[status] {
		return fmt.Errorf("无效的学习状态：%s", status)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[id]
	if !ok {
		return ErrNotFound
	}
	e.LearningStatus = status
	return nil
}

// AutoClassify 启发式自动分类（source=AUTO）；锁定返回 ErrClassificationLocked。
func (m *MemStore) AutoClassify(ctx context.Context, id uuid.UUID) ([]ClassificationDimension, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	if e.ClassificationLocked {
		return nil, ErrClassificationLocked
	}
	dims := classifyByPath(e.HTTPMethod, e.NormalizedPath)
	for i := range dims {
		dims[i].EndpointID = id
	}
	m.dims[id] = dims
	out := make([]ClassificationDimension, len(dims))
	copy(out, dims)
	return out, nil
}

// StartLearning 创建 RUNNING 任务并置 learning_status=LEARNING。
func (m *MemStore) StartLearning(ctx context.Context, endpointID uuid.UUID, createdBy *uuid.UUID) (*LearningJob, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[endpointID]
	if !ok {
		return nil, ErrNotFound
	}
	for _, j := range m.jobs {
		if j.EndpointID == endpointID && j.Status == "RUNNING" {
			return nil, ErrLearningRunning
		}
	}
	var createdByCopy *uuid.UUID
	if createdBy != nil {
		v := *createdBy
		createdByCopy = &v
	}
	job := &LearningJob{
		ID: uuid.New(), EndpointID: endpointID, Status: "RUNNING",
		StartedAt: time.Now().UTC(), CreatedBy: createdByCopy, CreatedAt: time.Now().UTC(),
	}
	m.jobs = append(m.jobs, job)
	e.LearningStatus = "LEARNING"
	cp := *job
	return &cp, nil
}

// StopLearning 停止 RUNNING 任务并置 learning_status=PAUSED。
func (m *MemStore) StopLearning(ctx context.Context, endpointID uuid.UUID, actor string) (*LearningJob, error) {
	_ = ctx
	_ = actor
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[endpointID]
	if !ok {
		return nil, ErrNotFound
	}
	for _, j := range m.jobs {
		if j.EndpointID == endpointID && j.Status == "RUNNING" {
			now := time.Now().UTC()
			j.Status = "STOPPED"
			j.StoppedAt = &now
			e.LearningStatus = "PAUSED"
			cp := *j
			return &cp, nil
		}
	}
	return nil, ErrLearningNotRunning
}

// LearningStatus 返回最近任务与样本统计（内存实现无样本，统计恒为 0）。
func (m *MemStore) LearningStatus(ctx context.Context, endpointID uuid.UUID) (*LearningJob, SampleStats, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	var latest *LearningJob
	for _, j := range m.jobs {
		if j.EndpointID != endpointID {
			continue
		}
		if latest == nil || j.StartedAt.After(latest.StartedAt) {
			latest = j
		}
	}
	if latest == nil {
		return nil, SampleStats{}, nil
	}
	cp := *latest
	return &cp, SampleStats{}, nil
}

func cloneEP(e *Endpoint) *Endpoint {
	cp := *e
	if e.ConfirmedAt != nil {
		t := *e.ConfirmedAt
		cp.ConfirmedAt = &t
	}
	if e.ApplicationID != nil {
		v := *e.ApplicationID
		cp.ApplicationID = &v
	}
	if e.DomainID != nil {
		v := *e.DomainID
		cp.DomainID = &v
	}
	if e.CurrentModelVersionID != nil {
		v := *e.CurrentModelVersionID
		cp.CurrentModelVersionID = &v
	}
	if e.Asset != nil {
		cp.Asset = cloneAsset(e.Asset)
	}
	return &cp
}

func cloneAsset(a *Asset) *Asset {
	cp := *a
	cp.Tags = append([]string{}, a.Tags...)
	return &cp
}

// errRequired 与 SQL 路径校验一致。
var errRequired = errString("method and path_template required")

type errString string

func (e errString) Error() string { return string(e) }
