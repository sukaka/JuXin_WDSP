// mem_store.go 暴露面引擎内存仓储：与 SQL Store 相同业务语义
// （条件 upsert / MANUAL·锁定不覆盖 / 留存清理），供包内单测与无库环境
// 驱动真实 Handler / Sweeper.SweepOnce。
package apiexposure

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// memEndpoint 内存端点上下文（镜像 api_endpoints + 归属域名/部署模式 + 现存维度）。
type memEndpoint struct {
	key            string
	hostname       string
	httpPort       *int
	httpsPort      *int
	deploymentMode string
	locked         bool
	existingValue  string
	existingSource string
	existingConf   float64
}

// seenRow 内存去重明细行。
type seenRow struct {
	firstSeen time.Time
	lastSeen  time.Time
	count     int64
}

// MemStore 进程内仓储（实现 Repository）。
type MemStore struct {
	mu          sync.Mutex
	now         func() time.Time
	endpoints   map[uuid.UUID]*memEndpoint
	buckets     map[uuid.UUID]map[string]int64   // endpoint → date|scope → count
	seen        map[uuid.UUID]map[string]seenRow // endpoint → date|scope|fingerprint → row
	assessments map[uuid.UUID][]AssessmentRecord // endpoint → 评估历史（写入序）
	applied     map[uuid.UUID]int                // endpoint → 维度 upsert 生效次数（测试断言用）
}

// SetClock 注入时钟（单测与 Sweeper.SetClock 对齐，避免墙钟与固定测试时间偏离导致 Prune 误删）。
func (m *MemStore) SetClock(fn func() time.Time) *MemStore {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = fn
	return m
}

// NewMemStore 创建空内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{
		endpoints:   map[uuid.UUID]*memEndpoint{},
		buckets:     map[uuid.UUID]map[string]int64{},
		seen:        map[uuid.UUID]map[string]seenRow{},
		assessments: map[uuid.UUID][]AssessmentRecord{},
		applied:     map[uuid.UUID]int{},
	}
}

var _ Repository = (*MemStore)(nil)

// ---------- 测试造数辅助（包内单测使用） ----------

// addEndpoint 登记端点（hostname/部署模式/锁定/现存维度可空）。
func (m *MemStore) addEndpoint(id uuid.UUID, key, hostname, deploymentMode string,
	locked bool, existingValue, existingSource string, existingConf float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.endpoints[id] = &memEndpoint{
		key: key, hostname: hostname, deploymentMode: deploymentMode, locked: locked,
		existingValue: existingValue, existingSource: existingSource, existingConf: existingConf,
	}
}

// applyCount 维度 upsert 生效次数（测试断言用）。
func (m *MemStore) applyCount(id uuid.UUID) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applied[id]
}

// bucketCount 读桶计数（测试断言用）。
func (m *MemStore) bucketCount(id uuid.UUID, day time.Time, scope string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buckets[id][bucketKey(day, scope)]
}

// ---------- Repository 实现 ----------

func bucketKey(day time.Time, scope string) string {
	return day.UTC().Truncate(24*time.Hour).Format("2006-01-02") + "|" + scope
}

// RecordSource 来源聚合（与 SQL 同语义：桶计数 + 指纹去重明细；空/超限指纹只计桶）。
func (m *MemStore) RecordSource(_ context.Context, endpointID uuid.UUID, scope, fingerprint string, ts time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	day := ts.UTC().Truncate(24 * time.Hour)
	if m.buckets[endpointID] == nil {
		m.buckets[endpointID] = map[string]int64{}
	}
	m.buckets[endpointID][bucketKey(day, scope)]++
	if fingerprint == "" || len(fingerprint) > sourceFingerprintMaxLen {
		return nil
	}
	if m.seen[endpointID] == nil {
		m.seen[endpointID] = map[string]seenRow{}
	}
	k := bucketKey(day, scope) + "|" + fingerprint
	row := m.seen[endpointID][k]
	if row.count == 0 {
		row.firstSeen = ts
	}
	row.lastSeen = ts
	row.count++
	m.seen[endpointID][k] = row
	return nil
}

// WindowStats 观察窗聚合（scope 升序，与 SQL ORDER BY 同口径）。
func (m *MemStore) WindowStats(_ context.Context, endpointID uuid.UUID, sinceDay time.Time) ([]ScopeBucket, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	since := sinceDay.UTC().Truncate(24 * time.Hour)
	days := map[string]map[string]bool{}         // scope → date set
	requests := map[string]int64{}               // scope → total
	fingerprints := map[string]map[string]bool{} // scope → fingerprint set
	for key, n := range m.buckets[endpointID] {
		day, scope := splitBucketKey(key)
		if day.Before(since) {
			continue
		}
		if days[scope] == nil {
			days[scope] = map[string]bool{}
		}
		days[scope][day.Format("2006-01-02")] = true
		requests[scope] += n
	}
	for key := range m.seen[endpointID] {
		parts := splitSeenKey(key)
		day, scope, fp := parts[0], parts[1], parts[2]
		d, _ := time.Parse("2006-01-02", day)
		if d.Before(since) {
			continue
		}
		if fingerprints[scope] == nil {
			fingerprints[scope] = map[string]bool{}
		}
		fingerprints[scope][fp] = true
	}
	out := []ScopeBucket{}
	for scope := range days {
		out = append(out, ScopeBucket{
			Scope:         scope,
			Days:          len(days[scope]),
			Requests:      requests[scope],
			UniqueSources: len(fingerprints[scope]),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scope < out[j].Scope })
	return out, nil
}

func splitBucketKey(key string) (time.Time, string) {
	day, _ := time.Parse("2006-01-02", key[:10])
	return day, key[11:]
}

func splitSeenKey(key string) [3]string {
	// date|scope|fingerprint
	day := key[:10]
	rest := key[11:]
	idx := 0
	for i, c := range rest {
		if c == '|' {
			idx = i
			break
		}
	}
	return [3]string{day, rest[:idx], rest[idx+1:]}
}

// EndpointContext 端点归属上下文（未登记返回 ErrNotFound）。
func (m *MemStore) EndpointContext(_ context.Context, endpointID uuid.UUID) (*EndpointContext, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ep, ok := m.endpoints[endpointID]
	if !ok {
		return nil, ErrNotFound
	}
	return &EndpointContext{
		ID: endpointID, EndpointKey: ep.key, Hostname: ep.hostname,
		HTTPPort: ep.httpPort, HTTPSPort: ep.httpsPort, DeploymentMode: ep.deploymentMode,
		Locked: ep.locked, ExistingValue: ep.existingValue, ExistingSource: ep.existingSource,
		ExistingConfidence: ep.existingConf,
	}, nil
}

// ListCandidates 待评估端点（窗口内有流量 或 从未评估 或 评估早于 staleBefore；id 升序限量）。
func (m *MemStore) ListCandidates(_ context.Context, sinceDay, staleBefore time.Time, limit int) ([]uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	since := sinceDay.UTC().Truncate(24 * time.Hour)
	out := []uuid.UUID{}
	for id := range m.endpoints {
		hasTraffic := false
		for key := range m.buckets[id] {
			day, _ := splitBucketKey(key)
			if !day.Before(since) {
				hasTraffic = true
				break
			}
		}
		history := m.assessments[id]
		stale := len(history) == 0 || history[len(history)-1].AssessedAt.Before(staleBefore)
		if hasTraffic || stale {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// LatestAssessment 最近一次评估（写入序末尾；无返回 nil）。
func (m *MemStore) LatestAssessment(_ context.Context, endpointID uuid.UUID) (*AssessmentRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	history := m.assessments[endpointID]
	if len(history) == 0 {
		return nil, nil
	}
	rec := history[len(history)-1]
	return &rec, nil
}

// WriteAssessment 写评估明细（内存追加；ID 生成）。
func (m *MemStore) WriteAssessment(_ context.Context, endpointID uuid.UUID, a Assessment, assessedAt time.Time) (uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	evidence := a.Evidence
	if evidence == nil {
		evidence = []EvidenceItem{}
	}
	id := uuid.New()
	m.assessments[endpointID] = append(m.assessments[endpointID], AssessmentRecord{
		ID: id, EndpointID: endpointID, Verdict: a.Verdict, Source: a.Source,
		Confidence: a.Confidence, Evidence: evidence, AssessedAt: assessedAt,
	})
	return id, nil
}

// ApplyVerdict 条件 upsert（与 SQL 同语义：锁定或现存 MANUAL 不覆盖）。
func (m *MemStore) ApplyVerdict(_ context.Context, endpointID uuid.UUID, a Assessment) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ep, ok := m.endpoints[endpointID]
	if !ok {
		return false, ErrNotFound
	}
	if ep.locked || ep.existingSource == SourceManual {
		return false, nil
	}
	ep.existingValue = a.Verdict
	ep.existingSource = a.Source
	ep.existingConf = ConfidenceScore(a.Confidence)
	m.applied[endpointID]++
	return true, nil
}

// Prune 留存清理（删除 retentionDays 天前的桶/明细/评估）。
func (m *MemStore) Prune(_ context.Context, retentionDays int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if retentionDays <= 0 {
		retentionDays = 30
	}
	now := time.Now().UTC()
	if m.now != nil {
		now = m.now().UTC()
	}
	cutoffDay := now.Add(-time.Duration(retentionDays) * 24 * time.Hour).Truncate(24 * time.Hour)
	cutoffTs := now.Add(-time.Duration(retentionDays) * 24 * time.Hour)
	var total int64
	for _, rows := range m.buckets {
		for key := range rows {
			day, _ := splitBucketKey(key)
			if day.Before(cutoffDay) {
				total++
				delete(rows, key)
			}
		}
	}
	for _, rows := range m.seen {
		for key := range rows {
			day, _ := time.Parse("2006-01-02", key[:10])
			if day.Before(cutoffDay) {
				total++
				delete(rows, key)
			}
		}
	}
	for id, history := range m.assessments {
		kept := history[:0]
		for _, rec := range history {
			if rec.AssessedAt.Before(cutoffTs) {
				total++
				continue
			}
			kept = append(kept, rec)
		}
		m.assessments[id] = kept
	}
	return total, nil
}
