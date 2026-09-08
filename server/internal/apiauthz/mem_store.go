// mem_store.go 授权实体层内存仓储：与 SQL Store 相同业务语义，
// 供包内单测与无库环境驱动真实 Handler / SweepOnce / EvaluateBOLA。
package apiauthz

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// memEndpoint 内存端点行（api_endpoints 镜像，sweep 解析用）。
type memEndpoint struct {
	id       uuid.UUID
	template string // normalized_path
}

// memRuntimeEvent 内存运行时事件（api_runtime_events 镜像，仅保留 sweep/评估所需列）。
type memRuntimeEvent struct {
	id         uuid.UUID
	key        string
	identity   string
	rawPath    string
	occurredAt time.Time
}

// MemStore 进程内仓储。
type MemStore struct {
	mu           sync.Mutex
	baselines    map[uuid.UUID]*RoleBaseline
	fieldPerms   map[uuid.UUID]*FieldPermission
	ownership    map[string]*ObjectOwnership // endpoint|identity|type|object → 权属行
	objectModels map[string]*ObjectModel     // endpoint|segment → 对象模型行
	seq          map[uuid.UUID]int           // 插入序号（模拟 created_at 稳定排序）
	seqNext      int
	endpoints    map[string]*memEndpoint // endpoint_key → 端点（sweep 解析/评估端点存在性）
	events       []memRuntimeEvent       // 运行时事件（sweep/评估数据源）
}

// NewMemStore 创建空内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{
		baselines:    map[uuid.UUID]*RoleBaseline{},
		fieldPerms:   map[uuid.UUID]*FieldPermission{},
		ownership:    map[string]*ObjectOwnership{},
		objectModels: map[string]*ObjectModel{},
		seq:          map[uuid.UUID]int{},
		endpoints:    map[string]*memEndpoint{},
	}
}

// cloneBaseline / cloneFieldPerm / cloneOwnership 深拷贝（避免调用方改到内部状态）。
func cloneBaseline(b *RoleBaseline) *RoleBaseline {
	c := *b
	if b.CreatedBy != nil {
		cb := *b.CreatedBy
		c.CreatedBy = &cb
	}
	return &c
}

func cloneFieldPerm(p *FieldPermission) *FieldPermission {
	c := *p
	if p.Role != nil {
		r := *p.Role
		c.Role = &r
	}
	if p.Tenant != nil {
		t := *p.Tenant
		c.Tenant = &t
	}
	if p.CreatedBy != nil {
		cb := *p.CreatedBy
		c.CreatedBy = &cb
	}
	return &c
}

func cloneOwnership(o *ObjectOwnership) *ObjectOwnership {
	c := *o
	return &c
}

// ownershipKey 权属唯一键（与表约束同口径）。
func ownershipKey(endpointID uuid.UUID, identity, objectType, objectID string) string {
	return endpointID.String() + "|" + identity + "|" + objectType + "|" + objectID
}

// baselineUniqueKey 角色基线唯一键（与表约束同口径）。
func baselineUniqueKey(endpointID uuid.UUID, role, method, action string) string {
	return endpointID.String() + "|" + role + "|" + method + "|" + action
}

// fieldPermUniqueKey 字段权限唯一键（NULL 归一空串，与迁移 000044 唯一索引同口径）。
func fieldPermUniqueKey(endpointID uuid.UUID, fieldPath, direction string, role, tenant *string) string {
	r, t := "", ""
	if role != nil {
		r = *role
	}
	if tenant != nil {
		t = *tenant
	}
	return endpointID.String() + "|" + fieldPath + "|" + direction + "|" + r + "|" + t
}

// paginate 排序后的实体切片分页（泛型，三类实体共用）。
func paginate[T any](items []T, page, pageSize int) []T {
	page, pageSize = normPage(page, pageSize)
	start := (page - 1) * pageSize
	if start >= len(items) {
		return []T{}
	}
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

// ---------- 角色基线 ----------

// baselineKeyExists 唯一键是否已被占用（exclude 自身更新场景）。
func (m *MemStore) baselineKeyExists(key string, exclude uuid.UUID) bool {
	for id, b := range m.baselines {
		if id != exclude && baselineUniqueKey(b.EndpointID, b.Role, b.Method, b.Action) == key {
			return true
		}
	}
	return false
}

// ListRoleBaselines 分页列表（过滤/排序语义与 SQL 一致：按创建时间倒序）。
func (m *MemStore) ListRoleBaselines(_ context.Context, f RoleBaselineFilter) ([]RoleBaseline, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	matched := []RoleBaseline{}
	for _, b := range m.baselines {
		if f.EndpointID != nil && b.EndpointID != *f.EndpointID {
			continue
		}
		if f.Role != "" && b.Role != f.Role {
			continue
		}
		if f.Method != "" && b.Method != f.Method {
			continue
		}
		if f.Source != "" && b.Source != f.Source {
			continue
		}
		if f.Confirmed != nil && b.Confirmed != *f.Confirmed {
			continue
		}
		matched = append(matched, *cloneBaseline(b))
	}
	sort.Slice(matched, func(i, j int) bool { return m.seq[matched[i].ID] > m.seq[matched[j].ID] })
	total := int64(len(matched))
	return paginate(matched, f.Page, f.PageSize), total, nil
}

// GetRoleBaseline 按 ID 读取。
func (m *MemStore) GetRoleBaseline(_ context.Context, id uuid.UUID) (*RoleBaseline, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.baselines[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneBaseline(b), nil
}

// CreateRoleBaseline 新增（唯一键冲突 → ErrBaselineConflict；endpoint 未登记 → ErrEndpointNotFound；
// confirmed 恒 FALSE 起步）。
func (m *MemStore) CreateRoleBaseline(_ context.Context, b *RoleBaseline) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.baselineKeyExists(baselineUniqueKey(b.EndpointID, b.Role, b.Method, b.Action), uuid.Nil) {
		return ErrBaselineConflict
	}
	if !m.endpointExists(b.EndpointID) {
		return ErrEndpointNotFound
	}
	now := time.Now().UTC()
	c := cloneBaseline(b)
	c.ID = uuid.New()
	c.Confirmed = false
	c.CreatedAt = now
	c.UpdatedAt = now
	m.seqNext++
	m.seq[c.ID] = m.seqNext
	m.baselines[c.ID] = c
	*b = *cloneBaseline(c)
	return nil
}

// UpdateRoleBaseline 更新（endpoint_id 不可改；confirmed 不随编辑变更）。
func (m *MemStore) UpdateRoleBaseline(_ context.Context, b *RoleBaseline) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.baselines[b.ID]
	if !ok {
		return ErrNotFound
	}
	if m.baselineKeyExists(baselineUniqueKey(cur.EndpointID, b.Role, b.Method, b.Action), b.ID) {
		return ErrBaselineConflict
	}
	c := cloneBaseline(b)
	c.EndpointID = cur.EndpointID
	c.Confirmed = cur.Confirmed
	c.CreatedAt = cur.CreatedAt
	c.UpdatedAt = time.Now().UTC()
	m.baselines[c.ID] = c
	*b = *cloneBaseline(c)
	return nil
}

// DeleteRoleBaseline 删除。
func (m *MemStore) DeleteRoleBaseline(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.baselines[id]; !ok {
		return ErrNotFound
	}
	delete(m.baselines, id)
	delete(m.seq, id)
	return nil
}

// ConfirmRoleBaseline 确认/取消确认（返回更新后实体）。
func (m *MemStore) ConfirmRoleBaseline(_ context.Context, id uuid.UUID, confirmed bool) (*RoleBaseline, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.baselines[id]
	if !ok {
		return nil, ErrNotFound
	}
	cur.Confirmed = confirmed
	cur.UpdatedAt = time.Now().UTC()
	return cloneBaseline(cur), nil
}

// ---------- 对象权属（只读查询） ----------

// ListOwnership 分页列表（过滤语义与 SQL 一致；按 last_seen 倒序）。
func (m *MemStore) ListOwnership(_ context.Context, f OwnershipFilter) ([]ObjectOwnership, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	matched := []ObjectOwnership{}
	for _, o := range m.ownership {
		if f.EndpointID != nil && o.EndpointID != *f.EndpointID {
			continue
		}
		if f.Identity != "" && o.IdentityFingerprint != f.Identity {
			continue
		}
		if f.ObjectType != "" && o.ObjectType != f.ObjectType {
			continue
		}
		if f.ObjectID != "" && o.ObjectID != f.ObjectID {
			continue
		}
		matched = append(matched, *cloneOwnership(o))
	}
	sort.Slice(matched, func(i, j int) bool {
		if !matched[i].LastSeen.Equal(matched[j].LastSeen) {
			return matched[i].LastSeen.After(matched[j].LastSeen)
		}
		return matched[i].ID.String() < matched[j].ID.String()
	})
	total := int64(len(matched))
	return paginate(matched, f.Page, f.PageSize), total, nil
}

// ---------- 字段权限 ----------

// fieldPermKeyExists 唯一键是否已被占用（exclude 自身更新场景）。
func (m *MemStore) fieldPermKeyExists(key string, exclude uuid.UUID) bool {
	for id, p := range m.fieldPerms {
		if id != exclude && fieldPermUniqueKey(p.EndpointID, p.FieldPath, p.Direction, p.Role, p.Tenant) == key {
			return true
		}
	}
	return false
}

// ListFieldPermissions 分页列表（过滤/排序语义与 SQL 一致：按创建时间倒序）。
func (m *MemStore) ListFieldPermissions(_ context.Context, f FieldPermFilter) ([]FieldPermission, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	matched := []FieldPermission{}
	for _, p := range m.fieldPerms {
		if f.EndpointID != nil && p.EndpointID != *f.EndpointID {
			continue
		}
		if f.Direction != "" && p.Direction != f.Direction {
			continue
		}
		if f.Attribute != "" && p.Attribute != f.Attribute {
			continue
		}
		if f.Role != "" && (p.Role == nil || *p.Role != f.Role) {
			continue
		}
		if f.Tenant != "" && (p.Tenant == nil || *p.Tenant != f.Tenant) {
			continue
		}
		if f.DefaultsOnly && (p.Role != nil || p.Tenant != nil) {
			continue
		}
		matched = append(matched, *cloneFieldPerm(p))
	}
	sort.Slice(matched, func(i, j int) bool { return m.seq[matched[i].ID] > m.seq[matched[j].ID] })
	total := int64(len(matched))
	return paginate(matched, f.Page, f.PageSize), total, nil
}

// GetFieldPermission 按 ID 读取。
func (m *MemStore) GetFieldPermission(_ context.Context, id uuid.UUID) (*FieldPermission, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.fieldPerms[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneFieldPerm(p), nil
}

// CreateFieldPermission 新增（唯一键冲突 → ErrFieldPermConflict；endpoint 未登记 → ErrEndpointNotFound）。
func (m *MemStore) CreateFieldPermission(_ context.Context, p *FieldPermission) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fieldPermKeyExists(fieldPermUniqueKey(p.EndpointID, p.FieldPath, p.Direction, p.Role, p.Tenant), uuid.Nil) {
		return ErrFieldPermConflict
	}
	if !m.endpointExists(p.EndpointID) {
		return ErrEndpointNotFound
	}
	now := time.Now().UTC()
	c := cloneFieldPerm(p)
	c.ID = uuid.New()
	c.CreatedAt = now
	c.UpdatedAt = now
	m.seqNext++
	m.seq[c.ID] = m.seqNext
	m.fieldPerms[c.ID] = c
	*p = *cloneFieldPerm(c)
	return nil
}

// UpdateFieldPermission 更新（endpoint_id 不可改）。
func (m *MemStore) UpdateFieldPermission(_ context.Context, p *FieldPermission) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.fieldPerms[p.ID]
	if !ok {
		return ErrNotFound
	}
	if m.fieldPermKeyExists(fieldPermUniqueKey(cur.EndpointID, p.FieldPath, p.Direction, p.Role, p.Tenant), p.ID) {
		return ErrFieldPermConflict
	}
	c := cloneFieldPerm(p)
	c.EndpointID = cur.EndpointID
	c.CreatedAt = cur.CreatedAt
	c.UpdatedAt = time.Now().UTC()
	m.fieldPerms[c.ID] = c
	*p = *cloneFieldPerm(c)
	return nil
}

// DeleteFieldPermission 删除。
func (m *MemStore) DeleteFieldPermission(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.fieldPerms[id]; !ok {
		return ErrNotFound
	}
	delete(m.fieldPerms, id)
	delete(m.seq, id)
	return nil
}

// ---------- BOLA 评估（内存实现，信号采集语义同 SQL） ----------

// endpointExists 端点是否已登记（模拟 api_endpoints 存在性检查）。
func (m *MemStore) endpointExists(id uuid.UUID) bool {
	for _, ep := range m.endpoints {
		if ep.id == id {
			return true
		}
	}
	return false
}

// endpointKeyByID 端点 ID → endpoint_key（评估身份历史事件计数用）。
func (m *MemStore) endpointKeyByID(id uuid.UUID) (string, bool) {
	for key, ep := range m.endpoints {
		if ep.id == id {
			return key, true
		}
	}
	return "", false
}

// EvaluateBOLA 内存评估：与 SQL 实现同一信号口径，同走 decideVerdict 判定阶梯。
func (m *MemStore) EvaluateBOLA(_ context.Context, in EvaluateInput) (*EvaluateResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, ok := m.endpointKeyByID(in.EndpointID)
	if !ok {
		return nil, ErrNotFound
	}
	sig := evalSignals{}
	for _, o := range m.ownership {
		if o.EndpointID != in.EndpointID {
			continue
		}
		sig.endpointOwnershipRows++
		if o.ObjectID == in.ObjectID {
			sig.objectOwnerCount++
		}
		if in.Identity != "" && o.IdentityFingerprint == in.Identity {
			sig.identityObjectCount++
			if o.ObjectID == in.ObjectID {
				sig.ownMatch = true
			}
		}
	}
	if in.Identity != "" {
		for _, ev := range m.events {
			if ev.key == key && ev.identity == in.Identity {
				sig.identityEventCount++
			}
		}
	}
	return buildEvaluateResult(in, sig), nil
}

// ---------- SweepOnce（内存实现，语义同 SQL） ----------

// addEndpoint 登记端点（单测辅助；模拟 api_endpoints 资产行）。
func (m *MemStore) addEndpoint(endpointKey, normalizedPath string) uuid.UUID {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ep, ok := m.endpoints[endpointKey]; ok {
		return ep.id
	}
	id := uuid.New()
	m.endpoints[endpointKey] = &memEndpoint{id: id, template: normalizedPath}
	return id
}

// addRuntimeEvent 登记运行时事件（单测辅助；模拟 api_runtime_events 行）。
// 空 raw_path 事件丢弃（两个 sweep 的 SQL WHERE 都要求 raw_path 非空）；匿名事件
// 保留入库——权属 SweepOnce 在扫描时按身份过滤（与 SQL WHERE identity_fingerprint <> ”
// 同口径），对象模型 SweepObjectModelsOnce 则不限身份（与各自 SQL 实现一致）。
func (m *MemStore) addRuntimeEvent(endpointKey, identity, rawPath string, occurredAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rawPath == "" {
		return
	}
	m.events = append(m.events, memRuntimeEvent{
		id:         uuid.New(),
		key:        endpointKey,
		identity:   identity,
		rawPath:    rawPath,
		occurredAt: occurredAt,
	})
}

// ownershipRows 权属行快照（单测断言用；按对象排序输出稳定）。
func (m *MemStore) ownershipRows() []ObjectOwnership {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []ObjectOwnership{}
	for _, o := range m.ownership {
		out = append(out, *cloneOwnership(o))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ObjectType != out[j].ObjectType {
			return out[i].ObjectType < out[j].ObjectType
		}
		if out[i].ObjectID != out[j].ObjectID {
			return out[i].ObjectID < out[j].ObjectID
		}
		return out[i].IdentityFingerprint < out[j].IdentityFingerprint
	})
	return out
}

// SweepOnce 内存清扫：水位 = 权属行 max(last_seen)；与 SQL 实现同一 upsert 语义。
func (m *MemStore) SweepOnce(_ context.Context) (*SweepResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := &SweepResult{}
	var wm *time.Time
	for _, o := range m.ownership {
		if wm == nil || o.LastSeen.After(*wm) {
			t := o.LastSeen
			wm = &t
		}
	}
	candidates := []memRuntimeEvent{}
	for _, ev := range m.events {
		if ev.identity == "" {
			continue // 权属只取实名事件（与 SQL WHERE identity_fingerprint <> '' 同口径）
		}
		if wm != nil && !ev.occurredAt.After(*wm) {
			continue
		}
		candidates = append(candidates, ev)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].occurredAt.Equal(candidates[j].occurredAt) {
			return candidates[i].occurredAt.Before(candidates[j].occurredAt)
		}
		return candidates[i].id.String() < candidates[j].id.String()
	})
	if len(candidates) > sweepBatchSize {
		candidates = candidates[:sweepBatchSize]
		res.HasMore = true
	}
	if len(candidates) == 0 {
		return res, nil
	}
	for _, ev := range candidates {
		res.EventsScanned++
		info, ok := m.endpoints[ev.key]
		if !ok {
			res.SkippedNoEndpoint++
			continue
		}
		refs := extractObjectRefs(info.template, ev.rawPath)
		if len(refs) == 0 {
			res.SkippedNoMatch++
			continue
		}
		res.ObjectsExtracted += len(refs)
		for _, ref := range refs {
			key := ownershipKey(info.id, ev.identity, ref.ObjectType, ref.ObjectID)
			row, ok := m.ownership[key]
			if !ok {
				row = &ObjectOwnership{
					ID:                  uuid.New(),
					EndpointID:          info.id,
					IdentityFingerprint: ev.identity,
					ObjectType:          ref.ObjectType,
					ObjectID:            ref.ObjectID,
					FirstSeen:           ev.occurredAt,
					LastSeen:            ev.occurredAt,
					AccessCount:         1, // 与列 DEFAULT 1 的插入语义一致
				}
				m.ownership[key] = row
			} else {
				row.AccessCount++
				if ev.occurredAt.Before(row.FirstSeen) {
					row.FirstSeen = ev.occurredAt
				}
				if ev.occurredAt.After(row.LastSeen) {
					row.LastSeen = ev.occurredAt
				}
			}
			res.OwnershipUpserted++
		}
	}
	last := candidates[len(candidates)-1].occurredAt
	res.Watermark = &last
	return res, nil
}

// ---------- SweepObjectModelsOnce（内存实现，语义同 SQL） ----------

// objectModelKey 对象模型唯一键（与表约束 (endpoint_id, object_segment) 同口径）。
func objectModelKey(endpointID uuid.UUID, segment string) string {
	return endpointID.String() + "|" + segment
}

// objectModelRows 对象模型行快照（单测断言用；按键排序输出稳定）。
func (m *MemStore) objectModelRows() []ObjectModel {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []ObjectModel{}
	for _, o := range m.objectModels {
		out = append(out, *o)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EndpointID != out[j].EndpointID {
			return out[i].EndpointID.String() < out[j].EndpointID.String()
		}
		return out[i].ObjectSegment < out[j].ObjectSegment
	})
	return out
}

// SweepObjectModelsOnce 内存对象模型清扫：水位 = 对象模型行 max(last_seen)；
// 不限事件身份（与 SQL 实现同一口径），upsert 语义同 mergeIdentifierType/首末次不回头。
func (m *MemStore) SweepObjectModelsOnce(_ context.Context) (*ObjectModelSweepResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := &ObjectModelSweepResult{}
	var wm *time.Time
	for _, o := range m.objectModels {
		if wm == nil || o.LastSeen.After(*wm) {
			t := o.LastSeen
			wm = &t
		}
	}
	candidates := []memRuntimeEvent{}
	for _, ev := range m.events {
		if wm != nil && !ev.occurredAt.After(*wm) {
			continue
		}
		candidates = append(candidates, ev)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].occurredAt.Equal(candidates[j].occurredAt) {
			return candidates[i].occurredAt.Before(candidates[j].occurredAt)
		}
		return candidates[i].id.String() < candidates[j].id.String()
	})
	if len(candidates) > sweepBatchSize {
		candidates = candidates[:sweepBatchSize]
		res.HasMore = true
	}
	if len(candidates) == 0 {
		return res, nil
	}
	for _, ev := range candidates {
		res.EventsScanned++
		info, ok := m.endpoints[ev.key]
		if !ok {
			res.SkippedNoEndpoint++
			continue
		}
		refs := extractObjectSegmentRefs(info.template, ev.rawPath)
		if len(refs) == 0 {
			res.SkippedNoMatch++
			continue
		}
		res.SegmentsExtracted += len(refs)
		for _, ref := range refs {
			key := objectModelKey(info.id, ref.Segment)
			row, ok := m.objectModels[key]
			if !ok {
				row = &ObjectModel{
					ID:             uuid.New(),
					EndpointID:     info.id,
					ObjectSegment:  ref.Segment,
					IdentifierType: identifierTypeOf(ref.Shape),
					ExampleHash:    objectExampleHash(ref.Value),
					SampleCount:    1, // 与列 DEFAULT/插入语义一致
					FirstSeen:      ev.occurredAt,
					LastSeen:       ev.occurredAt,
				}
				m.objectModels[key] = row
			} else {
				row.SampleCount++
				row.IdentifierType = mergeIdentifierType(row.IdentifierType, identifierTypeOf(ref.Shape))
				if row.ExampleHash == "" {
					row.ExampleHash = objectExampleHash(ref.Value)
				}
				if ev.occurredAt.Before(row.FirstSeen) {
					row.FirstSeen = ev.occurredAt
				}
				if ev.occurredAt.After(row.LastSeen) {
					row.LastSeen = ev.occurredAt
				}
			}
			res.ModelsUpserted++
		}
	}
	last := candidates[len(candidates)-1].occurredAt
	res.Watermark = &last
	return res, nil
}
