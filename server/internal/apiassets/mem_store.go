package apiassets

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemStore 进程内接口仓储：与 SQL Store 相同业务语义，供单测与无库环境驱动真实 Handler。
type MemStore struct {
	mu       sync.Mutex
	byID     map[uuid.UUID]*Endpoint
	byKey    map[string]uuid.UUID
	assets   map[uuid.UUID]*Asset
	aliases  map[string]uuid.UUID
	dims     map[uuid.UUID][]ClassificationDimension
	segments map[uuid.UUID][]PathSegment // endpoint_id → 段形（派生口径同 SQL，见 segments.go）
	jobs     []*LearningJob
	events   []LifecycleEvent
	samples  []LearningSample
	traffic  map[uuid.UUID]map[time.Time]int64 // endpoint_id → 桶起点 → 计数
	// 生命周期增强（评分输入种子与计算时间；SQL 侧为表查询，语义一致）
	sensitiveCounts map[uuid.UUID]int       // endpoint_id → 敏感字段数
	authTypes       map[uuid.UUID]string    // endpoint_id → 主导认证形态
	valueComputedAt map[uuid.UUID]time.Time // endpoint_id → 上次评分计算时间
	serviceAssets   []ServiceAsset          // 服务资产种子（聚合 SQL 语义由集成测试覆盖）
	// endpointQuota 授权端点配额提供者（与 SQL Store 同口径：nil/0 = 不限制）
	endpointQuota func(ctx context.Context) int64
}

// NewMemStore 创建空内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{
		byID:            map[uuid.UUID]*Endpoint{},
		byKey:           map[string]uuid.UUID{},
		assets:          map[uuid.UUID]*Asset{},
		aliases:         map[string]uuid.UUID{},
		dims:            map[uuid.UUID][]ClassificationDimension{},
		segments:        map[uuid.UUID][]PathSegment{},
		traffic:         map[uuid.UUID]map[time.Time]int64{},
		sensitiveCounts: map[uuid.UUID]int{},
		authTypes:       map[uuid.UUID]string{},
		valueComputedAt: map[uuid.UUID]time.Time{},
	}
}

var _ Repository = (*MemStore)(nil)

// SetEndpointQuotaProvider 注入授权端点配额（与 SQL Store 同口径：0=不限制；
// 仅新端点首插强制，既有端点命中不受影响）。
func (m *MemStore) SetEndpointQuotaProvider(fn func(ctx context.Context) int64) *MemStore {
	m.endpointQuota = fn
	return m
}

// UpsertDiscovery 幂等登记发现结果。
func (m *MemStore) UpsertDiscovery(ctx context.Context, in DiscoveryInput) (*Endpoint, error) {
	_ = ctx
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	pathTemplate := strings.TrimSpace(in.PathTemplate)
	if method == "" || pathTemplate == "" {
		return nil, errRequired
	}
	runtimeKey := discoveryEndpointKey(method, pathTemplate, in.Host, in.ScopeKey, in.ApplicationID, in.DomainID, in.ProtocolType)
	key := discoveryScopeKey(method, pathTemplate, in.Host, in.ScopeKey, in.ApplicationID, in.DomainID, in.ApplicationBindingID, in.ProtocolType)
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.byKey[key]; ok {
		e := m.byID[id]
		e.HitCount++
		if in.Confidence > e.APIConfidence {
			e.APIConfidence = in.Confidence
		}
		if in.IsAPI {
			e.IsAPI = true
		}
		e.LastSeenAt = time.Now().UTC()
		return cloneEP(e), nil
	}
	// 授权端点配额强制（与 SQL Store 同口径）：仅统计 is_api=TRUE 端点数
	if in.IsAPI && m.endpointQuota != nil {
		if quota := m.endpointQuota(ctx); quota > 0 {
			var apiCount int64
			for _, existing := range m.byID {
				if existing.IsAPI {
					apiCount++
				}
			}
			if apiCount >= quota {
				return nil, ErrLicenseQuotaExceeded
			}
		}
	}
	now := time.Now().UTC()
	id := uuid.New()
	e := &Endpoint{
		ID: id, ApplicationID: in.ApplicationID, DomainID: in.DomainID,
		HTTPMethod: method, NormalizedPath: pathTemplate, RawPathExample: pathTemplate,
		DirectoryPath:        DirectoryOf(pathTemplate),
		ApplicationBindingID: in.ApplicationBindingID, Host: normalizeDiscoveryHost(in.Host),
		EndpointKey: runtimeKey, APIConfidence: in.Confidence, AssetStatus: "DISCOVERED",
		ProtocolType: protocolOrDefault(in.ProtocolType), LearningStatus: "NOT_STARTED", IsAPI: in.IsAPI, HitCount: 1,
		FirstSeenAt: now, LastSeenAt: now,
	}
	m.byID[id] = e
	m.byKey[key] = id
	// 首插派生段形（命中重放不重写，与 SQL 侧 xmax=0 分支同口径）
	m.segments[id] = withEndpointID(derivePathSegments(pathTemplate), id)
	return cloneEP(e), nil
}

// List 列表（过滤语义与 SQL List 一致；内存实现不带出应用名）。
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
	var idSet map[uuid.UUID]struct{}
	if len(f.IDs) > 0 {
		idSet = make(map[uuid.UUID]struct{}, len(f.IDs))
		for _, id := range f.IDs {
			idSet[id] = struct{}{}
		}
	}
	var all []Endpoint
	for _, e := range m.byID {
		if !f.IncludeNonAPI && !e.IsAPI {
			continue
		}
		if idSet != nil {
			if _, ok := idSet[e.ID]; !ok {
				continue
			}
		}
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
		if f.Unassigned && e.ApplicationID != nil {
			continue
		}
		if f.DirectoryPrefix != "" && e.DirectoryPath != f.DirectoryPrefix &&
			!strings.HasPrefix(e.DirectoryPath, f.DirectoryPrefix+"/") {
			continue
		}
		if f.BusinessType != "" {
			// 与 SQL 一致：无资产记录接口按 OTHER 计
			bt := "OTHER"
			if a, ok := m.assets[e.ID]; ok && a.BusinessType != "" {
				bt = a.BusinessType
			}
			if bt != f.BusinessType {
				continue
			}
		}
		item := cloneEP(e)
		// 与 SQL List 一致：列表带出 business_type（无资产记录归一 OTHER）与 tags
		item.BusinessType = "OTHER"
		if a, ok := m.assets[e.ID]; ok {
			if a.BusinessType != "" {
				item.BusinessType = a.BusinessType
			}
			item.Tags = append([]string{}, a.Tags...)
		}
		all = append(all, *item)
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

// ListPathSegments 读取端点段形（按位置升序；内存实现，语义同 SQL）。
func (m *MemStore) ListPathSegments(_ context.Context, endpointID uuid.UUID) ([]PathSegment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	segs := m.segments[endpointID]
	out := make([]PathSegment, len(segs))
	copy(out, segs)
	return out, nil
}

// SiteSummary 站点计数（内存实现无应用表，仅返回未归属桶计数，语义注释见 SQL）。
func (m *MemStore) SiteSummary(ctx context.Context) ([]SiteSummaryItem, int64, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	var unassigned int64
	for _, e := range m.byID {
		if !e.IsAPI {
			continue
		}
		if e.ApplicationID == nil {
			unassigned++
		}
	}
	return []SiteSummaryItem{}, unassigned, nil
}

// DirectoryTree 目录聚合（内存实现按目录分组计数，仅统计 is_api=TRUE）。
func (m *MemStore) DirectoryTree(ctx context.Context, applicationID *uuid.UUID, unassigned bool) ([]DirectoryCount, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	counts := map[string]int64{}
	for _, e := range m.byID {
		if !e.IsAPI {
			continue
		}
		if applicationID != nil && (e.ApplicationID == nil || *e.ApplicationID != *applicationID) {
			continue
		}
		if unassigned && e.ApplicationID != nil {
			continue
		}
		counts[e.DirectoryPath]++
	}
	out := make([]DirectoryCount, 0, len(counts))
	for dir, n := range counts {
		out = append(out, DirectoryCount{DirectoryPath: dir, EndpointCount: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DirectoryPath < out[j].DirectoryPath })
	return out, nil
}

// Confirm 确认接口。
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

// ListConfirmedByApplication 应用下 CONFIRMED 端点键（按 endpoint_key 升序，与 SQL 实现同口径）。
func (m *MemStore) ListConfirmedByApplication(ctx context.Context, appID uuid.UUID) ([]string, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []string{}
	for _, e := range m.byID {
		if e.ApplicationID != nil && *e.ApplicationID == appID && e.AssetStatus == "CONFIRMED" {
			out = append(out, e.EndpointKey)
		}
	}
	sort.Strings(out)
	return out, nil
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
	if primaryID == otherID {
		return nil, fmt.Errorf("不能将接口合并到自身")
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
	delete(m.byKey, endpointScopeKey(other))
	delete(m.assets, otherID)
	delete(m.dims, otherID)
	delete(m.segments, otherID) // 段形随端点删除清理（对应 SQL 侧 ON DELETE CASCADE）
	jobs := m.jobs[:0]
	for _, j := range m.jobs {
		if j.EndpointID != otherID {
			jobs = append(jobs, j)
		}
	}
	m.jobs = jobs
	m.appendEventLocked(primaryID, "", "MERGED",
		fmt.Sprintf("合并接口 %s（%s）", otherID, other.EndpointKey), actor)
	return cloneEP(primary), nil
}

// Split 按归一化路径拆分新接口（继承方法/置信度，状态 DISCOVERED）。
func (m *MemStore) Split(ctx context.Context, id uuid.UUID, newPaths []string, actor string) ([]Endpoint, error) {
	_ = ctx
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
		key := discoveryScopeKey(src.HTTPMethod, p, src.Host, "", src.ApplicationID, src.DomainID, src.ApplicationBindingID, src.ProtocolType)
		runtimeKey := discoveryEndpointKey(src.HTTPMethod, p, src.Host, "", src.ApplicationID, src.DomainID, src.ProtocolType)
		if _, dup := m.byKey[key]; dup {
			return nil, fmt.Errorf("%w: %s", ErrEndpointConflict, key)
		}
		now := time.Now().UTC()
		nid := uuid.New()
		e := &Endpoint{
			ID: nid, ApplicationID: src.ApplicationID, DomainID: src.DomainID,
			HTTPMethod: src.HTTPMethod, NormalizedPath: p, RawPathExample: p,
			DirectoryPath:        DirectoryOf(p),
			ApplicationBindingID: src.ApplicationBindingID, Host: src.Host,
			EndpointKey: runtimeKey, APIConfidence: src.APIConfidence, AssetStatus: "DISCOVERED",
			ProtocolType: src.ProtocolType, LearningStatus: "NOT_STARTED", IsAPI: src.IsAPI,
			FirstSeenAt: now, LastSeenAt: now,
		}
		m.byID[nid] = e
		m.byKey[key] = nid
		m.segments[nid] = withEndpointID(derivePathSegments(p), nid)
		created = append(created, *cloneEP(e))
	}
	m.appendEventLocked(id, "", "SPLIT",
		fmt.Sprintf("拆分出 %d 个接口：%s", len(created), strings.Join(newPaths, ", ")), actor)
	return created, nil
}

// SetAssetStatus 变更资产状态。
func (m *MemStore) SetAssetStatus(ctx context.Context, id uuid.UUID, status, actor string) (*Endpoint, error) {
	_ = ctx
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
	from := e.AssetStatus
	e.AssetStatus = status
	if status != "ZOMBIE" {
		e.ZombieSince = nil
	}
	if from != status {
		m.appendEventLocked(id, from, status, "资产状态变更", actor)
	}
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
func (m *MemStore) UpsertAsset(ctx context.Context, endpointID uuid.UUID, p AssetProfile) (*Asset, error) {
	_ = ctx
	p, err := normalizeAssetProfile(p)
	if err != nil {
		return nil, err
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
	a.Purpose = p.Purpose
	a.Exposure = p.Exposure
	a.Owner = p.Owner
	a.Tags = append([]string{}, p.Tags...)
	a.BusinessType = p.BusinessType
	a.Organization = p.Organization
	a.BusinessSystem = p.BusinessSystem
	a.TechnicalOwner = p.TechnicalOwner
	a.DataOwner = p.DataOwner
	a.DataLevel = p.DataLevel
	a.APILevel = p.APILevel
	a.AuthType = p.AuthType
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

// AutoClassify 路径/方法启发式与协议确定性自动分类（source=AUTO）；锁定返回 ErrClassificationLocked。
// 内存实现没有当前模型参数、运行时事件、流程基线、风险发现与对象模型源，不产出
// DATA_SENSITIVITY/IDENTITY_REQUIREMENT/BUSINESS_FLOW_STAGE/RISK_LABEL/BUSINESS_OBJECT。
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
	dims = append(dims, classifyByProtocol(e.ProtocolType)...)
	for i := range dims {
		dims[i].EndpointID = id
	}
	m.dims[id] = dims
	out := make([]ClassificationDimension, len(dims))
	copy(out, dims)
	return out, nil
}

// StartLearning 创建 RUNNING 任务并置 learning_status=LEARNING。
// sampleTarget 语义同 SQL 侧：0 取缺省，越界返回 ErrInvalidSampleTarget。
func (m *MemStore) StartLearning(ctx context.Context, endpointID uuid.UUID, sampleTarget int, createdBy *uuid.UUID) (*LearningJob, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	if sampleTarget == 0 {
		sampleTarget = DefaultSampleTarget
	}
	if sampleTarget < MinSampleTarget || sampleTarget > MaxSampleTarget {
		return nil, ErrInvalidSampleTarget
	}
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
		ID: uuid.New(), EndpointID: endpointID, Status: "RUNNING", SampleTarget: sampleTarget,
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
			m.appendEventLocked(endpointID, "LEARNING", "PAUSED", "停止学习", actor)
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

// appendEventLocked 记录生命周期事件（调用方须已持锁；语义对齐 SQL 侧 INSERT）。
func (m *MemStore) appendEventLocked(endpointID uuid.UUID, from, to, reason, actor string) {
	if actor == "" {
		actor = "system"
	}
	m.events = append(m.events, LifecycleEvent{
		ID: uuid.New(), EndpointID: endpointID, FromStatus: from, ToStatus: to,
		Reason: reason, Actor: actor, CreatedAt: time.Now().UTC(),
	})
}

// ListLifecycleEvents 生命周期事件（created_at DESC 分页，语义同 SQL）。
func (m *MemStore) ListLifecycleEvents(ctx context.Context, endpointID uuid.UUID, page, pageSize int) ([]LifecycleEvent, int64, error) {
	_ = ctx
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []LifecycleEvent
	for _, ev := range m.events {
		if ev.EndpointID == endpointID {
			all = append(all, ev)
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].CreatedAt.After(all[j].CreatedAt) })
	total := int64(len(all))
	start := (page - 1) * pageSize
	if start >= len(all) {
		return []LifecycleEvent{}, total, nil
	}
	end := start + pageSize
	if end > len(all) {
		end = len(all)
	}
	return all[start:end], total, nil
}

// ListLearningSamples 学习样本（accepted 可空过滤，collected_at DESC 分页，语义同 SQL）。
func (m *MemStore) ListLearningSamples(ctx context.Context, endpointID uuid.UUID, accepted *bool, page, pageSize int) ([]LearningSample, int64, error) {
	_ = ctx
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []LearningSample
	for _, sm := range m.samples {
		if sm.EndpointID != endpointID {
			continue
		}
		if accepted != nil && sm.Accepted != *accepted {
			continue
		}
		all = append(all, sm)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].CollectedAt.After(all[j].CollectedAt) })
	total := int64(len(all))
	start := (page - 1) * pageSize
	if start >= len(all) {
		return []LearningSample{}, total, nil
	}
	end := start + pageSize
	if end > len(all) {
		end = len(all)
	}
	return all[start:end], total, nil
}

// AddLearningSample 登记学习样本（测试/回放置入；生产样本由网关侧写入数据库）。
func (m *MemStore) AddLearningSample(s LearningSample) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	if s.CollectedAt.IsZero() {
		s.CollectedAt = time.Now().UTC()
	}
	m.samples = append(m.samples, s)
}

// RecordTrafficBucket 流量桶自增（语义同 SQL：按桶起点对齐累加）。
func (m *MemStore) RecordTrafficBucket(ctx context.Context, endpointID uuid.UUID, bucketStart time.Time) error {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	b := TrafficBucketStart(bucketStart)
	if m.traffic[endpointID] == nil {
		m.traffic[endpointID] = map[time.Time]int64{}
	}
	m.traffic[endpointID][b]++
	return nil
}

// TrafficBuckets 读取 [from, to) 窗口内流量桶（语义同 SQL）。
func (m *MemStore) TrafficBuckets(ctx context.Context, endpointID uuid.UUID, from, to time.Time) (map[time.Time]int64, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[time.Time]int64{}
	start := TrafficBucketStart(from)
	for b, c := range m.traffic[endpointID] {
		if !b.Before(start) && b.Before(to) {
			out[b] = c
		}
	}
	return out, nil
}

// RefreshAssetValues 内存实现：候选口径同 SQL（未评分或评分后又有新流量的非 IGNORED 端点，
// last_seen_at 倒序、limit 截断）；评分输入由内存状态装配（分类维度/资产扩展/流量桶/种子）。
func (m *MemStore) RefreshAssetValues(ctx context.Context, limit int) (int, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	var candidates []*Endpoint
	for _, e := range m.byID {
		if e.AssetStatus == "IGNORED" {
			continue
		}
		computedAt, ok := m.valueComputedAt[e.ID]
		if ok && !e.LastSeenAt.After(computedAt) {
			continue
		}
		candidates = append(candidates, e)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].LastSeenAt.After(candidates[j].LastSeenAt) })
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	now := time.Now().UTC()
	for _, e := range candidates {
		if err := m.refreshAssetValueLocked(e, now); err != nil {
			return 0, err
		}
	}
	return len(candidates), nil
}

// refreshAssetValueLocked 单端点评分回填（调用方须已持锁；纯函数 ScoreAssetValue 与 SQL 侧共用）。
func (m *MemStore) refreshAssetValueLocked(e *Endpoint, now time.Time) error {
	in := AssetValueInput{
		HTTPMethod:          e.HTTPMethod,
		AuthType:            m.authTypes[e.ID],
		SensitiveFieldCount: m.sensitiveCounts[e.ID],
		// 内存实现不读 api_call_edges（表自阶段8 起由 aggregations.RunCallEdges 分钟级生产），恒 0
	}
	for _, d := range m.dims[e.ID] {
		switch d.Dimension {
		case "PURPOSE":
			in.Purpose = d.Value
		case "EXPOSURE":
			in.Exposure = d.Value
		}
	}
	if in.Exposure == "" {
		if a, ok := m.assets[e.ID]; ok {
			in.Exposure = a.Exposure
		}
	}
	since := now.Add(-valueTrafficWindowDays * 24 * time.Hour)
	for b, c := range m.traffic[e.ID] {
		if !b.Before(since) {
			in.DailyTraffic += c
		}
	}
	in.DailyTraffic /= valueTrafficWindowDays
	score := ScoreAssetValue(in)
	score.ComputedAt = &now
	raw, err := json.Marshal(score)
	if err != nil {
		return fmt.Errorf("序列化资产价值评分失败：%w", err)
	}
	e.AssetValue = score.Level
	e.AssetValueExplain = raw
	m.valueComputedAt[e.ID] = now
	return nil
}

// ListServiceAssets 服务资产分页（内存实现按种子返回；聚合 SQL 语义由集成测试覆盖）。
func (m *MemStore) ListServiceAssets(ctx context.Context, page, pageSize int) ([]ServiceAsset, int64, error) {
	_ = ctx
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	total := int64(len(m.serviceAssets))
	start := (page - 1) * pageSize
	if start >= len(m.serviceAssets) {
		return []ServiceAsset{}, total, nil
	}
	end := start + pageSize
	if end > len(m.serviceAssets) {
		end = len(m.serviceAssets)
	}
	out := make([]ServiceAsset, end-start)
	copy(out, m.serviceAssets[start:end])
	return out, total, nil
}

// AddServiceAsset 登记服务资产种子（测试用；生产数据由 upstreams 表聚合）。
func (m *MemStore) AddServiceAsset(sa ServiceAsset) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.serviceAssets = append(m.serviceAssets, sa)
}

// SetSensitiveFieldCount 设置端点敏感字段数种子（评分输入；测试用）。
func (m *MemStore) SetSensitiveFieldCount(endpointID uuid.UUID, n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sensitiveCounts[endpointID] = n
}

// SetAuthType 设置端点主导认证形态种子（评分输入；测试用）。
func (m *MemStore) SetAuthType(endpointID uuid.UUID, authType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authTypes[endpointID] = authType
}

func cloneEP(e *Endpoint) *Endpoint {
	cp := *e
	if e.ConfirmedAt != nil {
		t := *e.ConfirmedAt
		cp.ConfirmedAt = &t
	}
	if e.ZombieSince != nil {
		t := *e.ZombieSince
		cp.ZombieSince = &t
	}
	if e.AssetValueExplain != nil {
		cp.AssetValueExplain = append(json.RawMessage{}, e.AssetValueExplain...)
	}
	if e.Tags != nil {
		cp.Tags = append([]string{}, e.Tags...)
	}
	if e.ApplicationID != nil {
		v := *e.ApplicationID
		cp.ApplicationID = &v
	}
	if e.DomainID != nil {
		v := *e.DomainID
		cp.DomainID = &v
	}
	if e.ApplicationBindingID != nil {
		v := *e.ApplicationBindingID
		cp.ApplicationBindingID = &v
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

func endpointScopeKey(e *Endpoint) string {
	return discoveryScopeKey(e.HTTPMethod, e.NormalizedPath, e.Host, "", e.ApplicationID,
		e.DomainID, e.ApplicationBindingID, e.ProtocolType)
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
