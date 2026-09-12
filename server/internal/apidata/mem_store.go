// mem_store.go 敏感数据管理面内存仓储：与 SQL Store 相同业务语义，
// 供包内单测与无库环境驱动真实 Handler / SweepOnce / SensitiveOverview。
package apidata

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// sensitiveFieldRow 内存敏感字段行（api_sensitive_fields 镜像，sweep/overview 断言用）。
type sensitiveFieldRow struct {
	EndpointID      uuid.UUID
	Direction       string
	StructuredPath  string
	DataType        string
	Confidence      float64
	DetectionSource string
	FirstSeen       time.Time
	LastSeen        time.Time
	OccurrenceCount int
	SourceDetail    json.RawMessage
}

// memRuntimeEvent 内存运行时事件（api_runtime_events 镜像，仅保留 sweep/overview 所需列）。
type memRuntimeEvent struct {
	id          uuid.UUID
	endpointKey string
	details     []byte
	occurredAt  time.Time
}

// MemStore 进程内仓储。
type MemStore struct {
	mu        sync.Mutex
	types     map[uuid.UUID]*SensitiveDataType
	rules     map[uuid.UUID]*MaskingRule
	ruleSeq   map[uuid.UUID]int // 规则插入序号（模拟 created_at 稳定排序）
	seq       int
	endpoints map[string]uuid.UUID          // endpoint_key → 端点 ID（sweep 解析）
	events    []memRuntimeEvent             // 运行时事件（sweep/overview 数据源）
	fields    map[string]*sensitiveFieldRow // endpointID|direction|path → 字段行
}

// NewMemStore 创建空内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{
		types:     map[uuid.UUID]*SensitiveDataType{},
		rules:     map[uuid.UUID]*MaskingRule{},
		ruleSeq:   map[uuid.UUID]int{},
		endpoints: map[string]uuid.UUID{},
		fields:    map[string]*sensitiveFieldRow{},
	}
}

// cloneType / cloneRule 深拷贝（避免调用方改到内部状态）。
func cloneType(t *SensitiveDataType) *SensitiveDataType {
	c := *t
	c.Locations = append([]string{}, t.Locations...)
	c.Keywords = append([]string{}, t.Keywords...)
	c.ExcludeFields = append([]string{}, t.ExcludeFields...)
	return &c
}

func cloneRule(r *MaskingRule) *MaskingRule {
	c := *r
	if r.ApplicationID != nil {
		id := *r.ApplicationID
		c.ApplicationID = &id
	}
	if r.EndpointKey != nil {
		k := *r.EndpointKey
		c.EndpointKey = &k
	}
	if r.DataType != nil {
		d := *r.DataType
		c.DataType = &d
	}
	if r.CreatedBy != nil {
		cb := *r.CreatedBy
		c.CreatedBy = &cb
	}
	c.Params = append(json.RawMessage{}, r.Params...)
	c.Exclusions = append(json.RawMessage{}, r.Exclusions...)
	return &c
}

// normPage 分页参数归一（页码 ≥1，分页大小夹取 [1,100]）。
func normPage(page, pageSize int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

// paginateTypes 排序后的切片分页。
func paginateTypes(items []SensitiveDataType, page, pageSize int) []SensitiveDataType {
	start := (page - 1) * pageSize
	if start >= len(items) {
		return []SensitiveDataType{}
	}
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

// ---------- 敏感数据类型 ----------

// ListTypes 分页列表（过滤/排序语义与 SQL ListTypes 一致：内置优先、按名称）。
func (m *MemStore) ListTypes(_ context.Context, f TypeFilter) ([]SensitiveDataType, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f.Page, f.PageSize = normPage(f.Page, f.PageSize)
	matched := []SensitiveDataType{}
	kw := strings.ToLower(f.Keyword)
	for _, t := range m.types {
		if f.Status != "" && t.Status != f.Status {
			continue
		}
		if f.Level != "" && t.Level != f.Level {
			continue
		}
		if f.Category != "" && t.Category != f.Category {
			continue
		}
		if kw != "" && !strings.Contains(strings.ToLower(t.Name), kw) {
			continue
		}
		matched = append(matched, *cloneType(t))
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].IsBuiltin != matched[j].IsBuiltin {
			return matched[i].IsBuiltin
		}
		return matched[i].Name < matched[j].Name
	})
	total := int64(len(matched))
	return paginateTypes(matched, f.Page, f.PageSize), total, nil
}

// GetType 按 ID 读取。
func (m *MemStore) GetType(_ context.Context, id uuid.UUID) (*SensitiveDataType, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.types[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneType(t), nil
}

// nameExists 名称是否已被占用（exclude 自身更新场景）。
func (m *MemStore) nameExists(name string, exclude uuid.UUID) bool {
	for id, t := range m.types {
		if t.Name == name && id != exclude {
			return true
		}
	}
	return false
}

// CreateType 新增（名称唯一；is_builtin 恒 FALSE，内置仅由迁移种子产生，
// 单测需要内置行时直接改 m.types[id].IsBuiltin）。
func (m *MemStore) CreateType(_ context.Context, t *SensitiveDataType) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nameExists(t.Name, uuid.Nil) {
		return ErrNameConflict
	}
	now := time.Now().UTC()
	c := cloneType(t)
	c.ID = uuid.New()
	c.Version = 1
	c.IsBuiltin = false
	c.CreatedAt = now
	c.UpdatedAt = now
	m.types[c.ID] = c
	*t = *cloneType(c)
	return nil
}

// UpdateType 更新（version 自增；is_builtin 不可经此变更）。
func (m *MemStore) UpdateType(_ context.Context, t *SensitiveDataType) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.types[t.ID]
	if !ok {
		return ErrNotFound
	}
	if m.nameExists(t.Name, t.ID) {
		return ErrNameConflict
	}
	c := cloneType(t)
	c.Version = cur.Version + 1
	c.IsBuiltin = cur.IsBuiltin
	c.CreatedAt = cur.CreatedAt
	c.UpdatedAt = time.Now().UTC()
	m.types[c.ID] = c
	*t = *cloneType(c)
	return nil
}

// DeleteType 删除（内置保护在 handler 层）。
func (m *MemStore) DeleteType(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.types[id]; !ok {
		return ErrNotFound
	}
	delete(m.types, id)
	return nil
}

// ListAllTypes 全量（导出用；内置优先、按名称）。
// 不经分页接口（normPage 已夹取上限 100，全量导出不许被截断）。
func (m *MemStore) ListAllTypes(_ context.Context) ([]SensitiveDataType, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SensitiveDataType, 0, len(m.types))
	for _, t := range m.types {
		out = append(out, *cloneType(t))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsBuiltin != out[j].IsBuiltin {
			return out[i].IsBuiltin
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// ImportTypes 导入 upsert（按 name：存在更新 version+1、is_builtin 保持；不存在创建）。
func (m *MemStore) ImportTypes(_ context.Context, items []SensitiveDataType) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	created, updated := 0, 0
	for i := range items {
		t := &items[i]
		var existing *SensitiveDataType
		for _, cur := range m.types {
			if cur.Name == t.Name {
				existing = cur
				break
			}
		}
		now := time.Now().UTC()
		if existing != nil {
			c := cloneType(t)
			c.ID = existing.ID
			c.Version = existing.Version + 1
			c.IsBuiltin = existing.IsBuiltin
			c.CreatedAt = existing.CreatedAt
			c.UpdatedAt = now
			m.types[c.ID] = c
			updated++
			continue
		}
		c := cloneType(t)
		c.ID = uuid.New()
		c.Version = 1
		c.IsBuiltin = false
		c.CreatedAt = now
		c.UpdatedAt = now
		m.types[c.ID] = c
		created++
	}
	return created, updated, nil
}

// ---------- 脱敏规则 ----------

// ListMaskingRules 分页列表（过滤语义与 SQL 一致；按插入序倒序，模拟 created_at DESC）。
func (m *MemStore) ListMaskingRules(_ context.Context, f RuleFilter) ([]MaskingRule, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f.Page, f.PageSize = normPage(f.Page, f.PageSize)
	matched := []MaskingRule{}
	for _, r := range m.rules {
		if f.Scope != "" && r.Scope != f.Scope {
			continue
		}
		if f.ApplicationID != nil && (r.ApplicationID == nil || *r.ApplicationID != *f.ApplicationID) {
			continue
		}
		if f.EndpointKey != "" && (r.EndpointKey == nil || *r.EndpointKey != f.EndpointKey) {
			continue
		}
		if f.Enabled != nil && r.Enabled != *f.Enabled {
			continue
		}
		matched = append(matched, *cloneRule(r))
	}
	sort.Slice(matched, func(i, j int) bool { return m.ruleSeq[matched[i].ID] > m.ruleSeq[matched[j].ID] })
	total := int64(len(matched))
	start := (f.Page - 1) * f.PageSize
	if start >= len(matched) {
		return []MaskingRule{}, total, nil
	}
	end := start + f.PageSize
	if end > len(matched) {
		end = len(matched)
	}
	return matched[start:end], total, nil
}

// GetMaskingRule 按 ID 读取。
func (m *MemStore) GetMaskingRule(_ context.Context, id uuid.UUID) (*MaskingRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rules[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneRule(r), nil
}

// CreateMaskingRule 新增。
func (m *MemStore) CreateMaskingRule(_ context.Context, r *MaskingRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	c := cloneRule(r)
	c.ID = uuid.New()
	c.CreatedAt = now
	c.UpdatedAt = now
	m.seq++
	m.ruleSeq[c.ID] = m.seq
	m.rules[c.ID] = c
	*r = *cloneRule(c)
	return nil
}

// UpdateMaskingRule 更新（updated_at 刷新）。
func (m *MemStore) UpdateMaskingRule(_ context.Context, r *MaskingRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.rules[r.ID]
	if !ok {
		return ErrNotFound
	}
	c := cloneRule(r)
	c.CreatedAt = cur.CreatedAt
	c.UpdatedAt = time.Now().UTC()
	m.rules[c.ID] = c
	*r = *cloneRule(c)
	return nil
}

// DeleteMaskingRule 删除。
func (m *MemStore) DeleteMaskingRule(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rules[id]; !ok {
		return ErrNotFound
	}
	delete(m.rules, id)
	delete(m.ruleSeq, id)
	return nil
}

// ListEnabledMaskingRules 全量启用规则（按插入序升序，MaskPlan 求值输入顺序稳定）。
func (m *MemStore) ListEnabledMaskingRules(_ context.Context) ([]MaskingRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []MaskingRule{}
	for _, r := range m.rules {
		if r.Enabled {
			out = append(out, *cloneRule(r))
		}
	}
	sort.Slice(out, func(i, j int) bool { return m.ruleSeq[out[i].ID] < m.ruleSeq[out[j].ID] })
	return out, nil
}

// ---------- 敏感数据态势（内存聚合，语义同 SQL SensitiveOverview） ----------

// countSensitiveDetails 统计 details_json 中 detector=sensitive_data 的明细条数
// （overview 命中数口径：按明细条目计，与证据是否含 field 无关）。
func countSensitiveDetails(details []byte) int {
	var items []sweepDetail
	if err := json.Unmarshal(details, &items); err != nil {
		return 0
	}
	n := 0
	for _, d := range items {
		if d.Detector == "sensitive_data" {
			n++
		}
	}
	return n
}

// SensitiveOverview 内存聚合（日期锚 time.Now().UTC()，仅单测使用）。
func (m *MemStore) SensitiveOverview(_ context.Context, days int) (*SensitiveOverview, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	days = clampOverviewDays(days)
	out := &SensitiveOverview{TypeDistribution: []TypeDistItem{}, Trend: []TrendPoint{}, Days: days}

	endpoints := map[uuid.UUID]bool{}
	dist := map[string]*TypeDistItem{}
	for _, f := range m.fields {
		endpoints[f.EndpointID] = true
		d, ok := dist[f.DataType]
		if !ok {
			d = &TypeDistItem{DataType: f.DataType}
			dist[f.DataType] = d
		}
		d.FieldCount++
		d.OccurrenceCount += int64(f.OccurrenceCount)
	}
	out.SensitiveEndpointCount = int64(len(endpoints))
	out.SensitiveFieldCount = int64(len(m.fields))
	// 分布的端点去重
	epByType := map[string]map[uuid.UUID]bool{}
	for _, f := range m.fields {
		if epByType[f.DataType] == nil {
			epByType[f.DataType] = map[uuid.UUID]bool{}
		}
		epByType[f.DataType][f.EndpointID] = true
	}
	for k, d := range dist {
		d.EndpointCount = int64(len(epByType[k]))
	}
	keys := make([]string, 0, len(dist))
	for k := range dist {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if dist[keys[i]].FieldCount != dist[keys[j]].FieldCount {
			return dist[keys[i]].FieldCount > dist[keys[j]].FieldCount
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		out.TypeDistribution = append(out.TypeDistribution, *dist[k])
	}

	// 趋势（UTC 日期；事件数与明细命中数）
	anchor := time.Now().UTC().Truncate(24 * time.Hour)
	eventByDay := map[string]int64{}
	hitByDay := map[string]int64{}
	from := anchor.AddDate(0, 0, -(days - 1))
	for _, ev := range m.events {
		if ev.occurredAt.Before(from) {
			continue
		}
		hits := countSensitiveDetails(ev.details)
		if hits == 0 {
			continue
		}
		day := ev.occurredAt.UTC().Format("2006-01-02")
		eventByDay[day]++
		hitByDay[day] += int64(hits)
	}
	for i := days - 1; i >= 0; i-- {
		day := anchor.AddDate(0, 0, -i).Format("2006-01-02")
		out.Trend = append(out.Trend, TrendPoint{Date: day, EventCount: eventByDay[day], HitCount: hitByDay[day]})
	}
	return out, nil
}

// ---------- SweepOnce（内存实现，语义同 SQL） ----------

// addEndpoint 登记端点（单测辅助；模拟 api_endpoints 资产行）。
func (m *MemStore) addEndpoint(endpointKey string) uuid.UUID {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.endpoints[endpointKey]; ok {
		return id
	}
	id := uuid.New()
	m.endpoints[endpointKey] = id
	return id
}

// addRuntimeEvent 登记运行时事件（单测辅助；模拟 api_runtime_events 行）。
func (m *MemStore) addRuntimeEvent(endpointKey string, occurredAt time.Time, details []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, memRuntimeEvent{
		id:          uuid.New(),
		endpointKey: endpointKey,
		details:     details,
		occurredAt:  occurredAt,
	})
}

// fieldRows 字段行快照（单测断言用；按 path 排序输出稳定）。
func (m *MemStore) fieldRows() []sensitiveFieldRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []sensitiveFieldRow{}
	for _, f := range m.fields {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StructuredPath < out[j].StructuredPath })
	return out
}

// SweepOnce 内存清扫：水位 = 字段行 max(last_seen)；与 SQL 实现同一 upsert 语义。
func (m *MemStore) SweepOnce(_ context.Context) (*SweepResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := &SweepResult{}
	var wm *time.Time
	for _, f := range m.fields {
		if wm == nil || f.LastSeen.After(*wm) {
			t := f.LastSeen
			wm = &t
		}
	}
	candidates := []memRuntimeEvent{}
	for _, ev := range m.events {
		if wm != nil && !ev.occurredAt.After(*wm) {
			continue
		}
		if countSensitiveDetails(ev.details) == 0 {
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
		hits, err := extractSweepHits(ev.details)
		if err != nil {
			return nil, err
		}
		if len(hits) == 0 {
			continue
		}
		endpointID, ok := m.endpoints[ev.endpointKey]
		if !ok {
			res.SkippedNoEndpoint++
			continue
		}
		res.Hits += len(hits)
		for _, h := range hits {
			key := endpointID.String() + "|" + h.Direction + "|" + h.StructuredPath
			sourceDetail, err := json.Marshal(map[string]string{
				"location":  h.Location,
				"rule_id":   h.RuleID,
				"event_id":  ev.id.String(),
				"data_type": h.DataType,
			})
			if err != nil {
				return nil, err
			}
			row, ok := m.fields[key]
			if !ok {
				row = &sensitiveFieldRow{
					EndpointID:      endpointID,
					Direction:       h.Direction,
					StructuredPath:  h.StructuredPath,
					DataType:        h.DataType,
					Confidence:      h.Confidence,
					DetectionSource: "RUNTIME",
					FirstSeen:       ev.occurredAt,
					LastSeen:        ev.occurredAt,
					OccurrenceCount: 1, // 与列 DEFAULT 1 的插入语义一致
				}
				m.fields[key] = row
			} else {
				row.OccurrenceCount++
				if ev.occurredAt.Before(row.FirstSeen) {
					row.FirstSeen = ev.occurredAt
				}
				if ev.occurredAt.After(row.LastSeen) {
					row.LastSeen = ev.occurredAt
				}
				if h.DataType != "" {
					row.DataType = h.DataType
				}
				// 与 SQL GREATEST 语义一致：置信度只升不降
				if h.Confidence > row.Confidence {
					row.Confidence = h.Confidence
				}
			}
			row.SourceDetail = sourceDetail
			res.FieldsUpserted++
		}
	}
	last := candidates[len(candidates)-1].occurredAt
	res.Watermark = &last
	return res, nil
}
