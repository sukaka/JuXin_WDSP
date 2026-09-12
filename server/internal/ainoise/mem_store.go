// mem_store.go 内存降噪簇仓储：单测与降级场景使用，语义与 SQLStore 一致
// （事件关联幂等、首事件代表、状态流转约束、推荐去重标记）。
package ainoise

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemStore 内存 Store（测试用；不用于生产装配）。
type MemStore struct {
	mu       sync.Mutex
	byID     map[uuid.UUID]*Cluster
	byFP     map[string]uuid.UUID // source|fingerprint → cluster id
	links    map[uuid.UUID][]ClusterEvent
	linked   map[string]bool // clusterID|eventID|source
	runs     []SweepRun
	openRecs map[uuid.UUID]bool // 模拟 ai_recommendations 中 DRAFT/PENDING_REVIEW 推荐
}

// NewMemStore 创建内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{
		byID:     map[uuid.UUID]*Cluster{},
		byFP:     map[string]uuid.UUID{},
		links:    map[uuid.UUID][]ClusterEvent{},
		linked:   map[string]bool{},
		openRecs: map[uuid.UUID]bool{},
	}
}

func fpKey(source, fp string) string { return source + "|" + fp }
func linkKey(clusterID, eventID uuid.UUID, source string) string {
	return clusterID.String() + "|" + eventID.String() + "|" + source
}

// UpsertEvent 与 SQLStore 同语义：新建簇或幂等关联计数。
func (m *MemStore) UpsertEvent(_ context.Context, in EventInput) (bool, uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	norm := NormalizeURI(in.RawURI)
	fp := Fingerprint(in.Source, in.Host, norm, in.RuleID, in.DetectorCode, in.ClientIP)
	key := fpKey(in.Source, fp)
	id, ok := m.byFP[key]
	created := false
	now := time.Now().UTC()
	if !ok {
		created = true
		id = uuid.New()
		m.byID[id] = &Cluster{
			ID: id, Source: in.Source, FingerprintHash: fp, ApplicationID: in.ApplicationID,
			Host: in.Host, NormalizedURI: norm, RuleID: in.RuleID, DetectorCode: in.DetectorCode,
			ClientIP: in.ClientIP, EventCount: 1, FirstSeen: in.OccurredAt, LastSeen: in.OccurredAt,
			Status: StatusActive, AIVerdict: VerdictUnknown, CreatedAt: now, UpdatedAt: now,
		}
		m.byFP[key] = id
	}
	lk := linkKey(id, in.EventID, in.Source)
	if _, dup := m.linked[lk]; dup {
		return created, id, nil // 重复扫描：不重复计数
	}
	hasRep := false
	for _, e := range m.links[id] {
		if e.IsRepresentative {
			hasRep = true
			break
		}
	}
	m.links[id] = append(m.links[id], ClusterEvent{
		EventID: in.EventID, Source: in.Source, IsRepresentative: !hasRep, CreatedAt: now,
	})
	m.linked[lk] = true
	if !created {
		c := m.byID[id]
		c.EventCount++
		if in.OccurredAt.After(c.LastSeen) {
			c.LastSeen = in.OccurredAt
		}
		c.UpdatedAt = now
	}
	return created, id, nil
}

func matchFilter(c *Cluster, f ListFilter) bool {
	if f.Source != "" && c.Source != f.Source {
		return false
	}
	if f.Status != "" && c.Status != f.Status {
		return false
	}
	if f.Verdict != "" && c.AIVerdict != f.Verdict {
		return false
	}
	if f.Since != nil && c.LastSeen.Before(*f.Since) {
		return false
	}
	if f.Until != nil && !c.LastSeen.Before(*f.Until) {
		return false
	}
	return true
}

// List 分页筛选（last_seen 倒序）。
func (m *MemStore) List(_ context.Context, f ListFilter) ([]Cluster, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []Cluster
	for _, c := range m.byID {
		if matchFilter(c, f) {
			all = append(all, *c)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].LastSeen.After(all[j].LastSeen) })
	total := int64(len(all))
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	start := (f.Page - 1) * f.PageSize
	if start >= len(all) {
		return []Cluster{}, total, nil
	}
	end := start + f.PageSize
	if end > len(all) {
		end = len(all)
	}
	return all[start:end], total, nil
}

// Get 簇详情。
func (m *MemStore) Get(_ context.Context, id uuid.UUID) (*Cluster, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.byID[id]
	if !ok {
		return nil, ErrClusterNotFound
	}
	cp := *c
	return &cp, nil
}

// ListEvents 簇内事件（代表事件在前）。
func (m *MemStore) ListEvents(_ context.Context, clusterID uuid.UUID, limit int) ([]ClusterEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	out := []ClusterEvent{}
	for _, e := range m.links[clusterID] {
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].IsRepresentative && !out[j].IsRepresentative })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Transition 状态流转（与 SQLStore 相同约束）。
func (m *MemStore) Transition(_ context.Context, id uuid.UUID, action string) (*Cluster, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.byID[id]
	if !ok {
		return nil, ErrClusterNotFound
	}
	switch action {
	case "suppress":
		if c.Status != StatusActive {
			return nil, ErrClusterState
		}
		c.Status = StatusSuppressed
	case "resolve":
		if c.Status != StatusActive && c.Status != StatusSuppressed {
			return nil, ErrClusterState
		}
		c.Status = StatusResolved
	default:
		return nil, ErrClusterState
	}
	c.UpdatedAt = time.Now().UTC()
	cp := *c
	return &cp, nil
}

// Stats 面板统计。
func (m *MemStore) Stats(_ context.Context) (*Stats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := &Stats{}
	for _, c := range m.byID {
		switch c.Status {
		case StatusActive:
			st.ActiveClusters++
			st.FoldedEvents += int64(c.EventCount)
			if c.AIVerdict == VerdictLikelyFalsePositive {
				st.LikelyFalsePositiveClusters++
			}
		case StatusSuppressed:
			st.SuppressedClusters++
		}
	}
	return st, nil
}

// VerdictCandidates ACTIVE、超阈值、未判定。
func (m *MemStore) VerdictCandidates(_ context.Context, minEvents, limit int) ([]Cluster, error) {
	return m.candidates(minEvents, limit, VerdictUnknown)
}

// FalsePositiveCandidates 疑似误报且超阈值的活跃簇。
func (m *MemStore) FalsePositiveCandidates(_ context.Context, minEvents, limit int) ([]Cluster, error) {
	return m.candidates(minEvents, limit, VerdictLikelyFalsePositive)
}

func (m *MemStore) candidates(minEvents, limit int, verdict string) ([]Cluster, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	out := []Cluster{}
	for _, c := range m.byID {
		if c.Status == StatusActive && c.AIVerdict == verdict && c.EventCount >= minEvents {
			out = append(out, *c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EventCount > out[j].EventCount })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// UpdateVerdict 写回判定。
func (m *MemStore) UpdateVerdict(_ context.Context, id uuid.UUID, verdict string, confidence *float64, summary string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.byID[id]
	if !ok {
		return ErrClusterNotFound
	}
	switch verdict {
	case VerdictTruePositive, VerdictLikelyFalsePositive, VerdictUnknown:
	default:
		return ErrClusterState
	}
	c.AIVerdict = verdict
	c.AIConfidence = confidence
	c.AISummary = summary
	c.UpdatedAt = time.Now().UTC()
	return nil
}

// HasOpenRecommendation 是否已有未决降噪推荐（测试经 SetOpenRecommendation 模拟）。
func (m *MemStore) HasOpenRecommendation(_ context.Context, clusterID uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.openRecs[clusterID], nil
}

// SetOpenRecommendation 标记簇已有未决推荐（测试模拟 ai_recommendations）。
func (m *MemStore) SetOpenRecommendation(clusterID uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.openRecs[clusterID] = true
}

// Evidence 由簇属性与代表事件构造证据摘要。
func (m *MemStore) Evidence(_ context.Context, clusterID uuid.UUID) (*Evidence, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.byID[clusterID]
	if !ok {
		return nil, ErrClusterNotFound
	}
	ev := &Evidence{Cluster: *c, RuleHits: []string{}}
	minutes := c.LastSeen.Sub(c.FirstSeen).Minutes()
	if minutes < 1 {
		minutes = 1
	}
	ev.EventsPerMinute = float64(c.EventCount) / minutes
	for _, e := range m.links[clusterID] {
		if e.IsRepresentative {
			id := e.EventID
			ev.RepresentativeID = &id
			break
		}
	}
	if c.RuleID != nil {
		ev.RuleHits = append(ev.RuleHits, "rule "+itoa(*c.RuleID))
	} else if c.DetectorCode != "" {
		ev.RuleHits = append(ev.RuleHits, "detector "+c.DetectorCode)
	}
	return ev, nil
}

// RecordSweepRun 记录扫描运行。
func (m *MemStore) RecordSweepRun(_ context.Context, run *SweepRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if run.ID == uuid.Nil {
		run.ID = uuid.New()
	}
	m.runs = append(m.runs, *run)
	return nil
}

// ListSweepRuns 扫描历史（开始时间倒序）。
func (m *MemStore) ListSweepRuns(_ context.Context, page, pageSize int) ([]SweepRun, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	runs := append([]SweepRun{}, m.runs...)
	sort.Slice(runs, func(i, j int) bool { return runs[i].StartedAt.After(runs[j].StartedAt) })
	total := int64(len(runs))
	start := (page - 1) * pageSize
	if start >= len(runs) {
		return []SweepRun{}, total, nil
	}
	end := start + pageSize
	if end > len(runs) {
		end = len(runs)
	}
	return runs[start:end], total, nil
}

// itoa 小整数转字符串（避免仅为 MemStore 引入 strconv 依赖说明：保持包内自足）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

var _ Store = (*MemStore)(nil)
