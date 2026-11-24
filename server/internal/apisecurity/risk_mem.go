// risk_mem.go 进程内风险仓储：与 SQL Store 相同业务语义，供单测与无库环境驱动真实 Handler。
package apisecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// riskMemEvent 关联请求预置事件（等价 SQL 的 api_runtime_events 点查列）。
type riskMemEvent struct {
	EndpointKey         string
	IdentityFingerprint string
	RequestID           string
	OccurredAt          time.Time
}

// RiskMemStore 进程内风险仓储。
type RiskMemStore struct {
	mu           sync.Mutex
	byID         map[uuid.UUID]*RiskFinding
	endpointKeys map[uuid.UUID]string // 测试预置：endpoint_id → endpoint_key
	events       []riskMemEvent       // 测试预置：运行时事件（关联 request_id 来源）
}

// NewRiskMemStore 创建空内存仓储。
func NewRiskMemStore() *RiskMemStore {
	return &RiskMemStore{
		byID:         map[uuid.UUID]*RiskFinding{},
		endpointKeys: map[uuid.UUID]string{},
	}
}

// SetEndpointKey 预置端点键（等价 SQL 的 LEFT JOIN api_endpoints 带出）。
func (m *RiskMemStore) SetEndpointKey(endpointID uuid.UUID, key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.endpointKeys[endpointID] = key
}

// SeedFinding 预置风险发现（等价采集器物化写入；EndpointID 非空时带出预置端点键）。
func (m *RiskMemStore) SeedFinding(f *RiskFinding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := cloneRiskFinding(f)
	if cp.ID == uuid.Nil {
		cp.ID = uuid.New()
	}
	if cp.EndpointID != nil {
		cp.EndpointKey = m.endpointKeys[*cp.EndpointID]
	}
	if cp.Detail == nil {
		cp.Detail = json.RawMessage(`{}`)
	}
	if cp.Evidence == nil {
		cp.Evidence = json.RawMessage(`{}`)
	}
	m.byID[cp.ID] = cp
}

// SeedEvent 预置运行时事件（ListRelatedRequestIDs 数据源）。
func (m *RiskMemStore) SeedEvent(endpointKey, identityFingerprint, requestID string, occurredAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, riskMemEvent{
		EndpointKey: endpointKey, IdentityFingerprint: identityFingerprint,
		RequestID: requestID, OccurredAt: occurredAt,
	})
}

// cloneRiskFinding 拷贝风险发现（避免调用方持有内部指针）。
func cloneRiskFinding(f *RiskFinding) *RiskFinding {
	cp := *f
	if f.EndpointID != nil {
		id := *f.EndpointID
		cp.EndpointID = &id
	}
	if f.RiskScore != nil {
		sc := *f.RiskScore
		cp.RiskScore = &sc
	}
	if f.UpdatedAt != nil {
		t := *f.UpdatedAt
		cp.UpdatedAt = &t
	}
	if f.Detail != nil {
		cp.Detail = append(json.RawMessage(nil), f.Detail...)
	}
	if f.Evidence != nil {
		cp.Evidence = append(json.RawMessage(nil), f.Evidence...)
	}
	return &cp
}

// GetFinding 风险详情（不存在返回 ErrNotFound）。
func (m *RiskMemStore) GetFinding(ctx context.Context, id uuid.UUID) (*RiskFinding, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := cloneRiskFinding(f)
	cp.Title = localizeFindingTitle(cp.FindingType, cp.Title, cp.Detail)
	return cp, nil
}

// TransitionFinding 状态机流转（语义与 SQL Store 一致：校验状态机 + 更新 +
// detail.handling 处置记录；非法迁移返回 ErrInvalidRiskTransition）。
func (m *RiskMemStore) TransitionFinding(ctx context.Context, id uuid.UUID, action string, in RiskHandleInput) (*RiskFinding, error) {
	_ = ctx
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	to, ok := ResolveRiskTransition(action, f.Status)
	if !ok {
		return nil, fmt.Errorf("%w: %s 状态不允许 %s", ErrInvalidRiskTransition, f.Status, action)
	}
	// detail JSONB 浅合并 detail.handling（与 SQL jsonb || 同语义：同键覆盖，保留其余键）
	detail := map[string]any{}
	if len(f.Detail) > 0 {
		if err := json.Unmarshal(f.Detail, &detail); err != nil {
			return nil, fmt.Errorf("finding detail 反序列化失败: %w", err)
		}
	}
	detail["handling"] = map[string]any{
		"action": action, "actor": in.Actor, "note": in.Note, "at": in.Now,
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		return nil, fmt.Errorf("finding detail 序列化失败: %w", err)
	}
	f.Detail = raw
	f.Status = to
	f.UpdatedAt = &in.Now
	cp := cloneRiskFinding(f)
	cp.Title = localizeFindingTitle(cp.FindingType, cp.Title, cp.Detail)
	return cp, nil
}

// riskBucketAgg 聚合中间态（count/hits/max severity/last_seen）。
type riskBucketAgg struct {
	count    int64
	hits     int64
	maxRank  int
	lastSeen time.Time
}

// add 累计一条发现。
func (a *riskBucketAgg) add(f *RiskFinding) {
	a.count++
	a.hits += int64(f.Count)
	if r := riskSeverityRank(f.Severity); r > a.maxRank {
		a.maxRank = r
	}
	if f.LastSeenAt.After(a.lastSeen) {
		a.lastSeen = f.LastSeenAt
	}
}

// SummarizeFindings 降噪聚合（语义与 SQL Store 一致：三视图各取头部 riskSummaryLimit 桶，
// 排序 最高严重度 DESC + 累计命中 DESC + 维度键 ASC）。
func (m *RiskMemStore) SummarizeFindings(ctx context.Context) (*RiskSummary, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()

	bySubject := map[string]*RiskSummaryBucket{}
	subjectAgg := map[string]*riskBucketAgg{}
	byEndpoint := map[string]*RiskSummaryBucket{}
	endpointAgg := map[string]*riskBucketAgg{}
	byType := map[string]*RiskSummaryBucket{}
	typeAgg := map[string]*riskBucketAgg{}

	for _, f := range m.byID {
		// 主体视图
		sk := f.SubjectType + "\x1f" + f.SubjectID
		b, ok := bySubject[sk]
		if !ok {
			b = &RiskSummaryBucket{SubjectType: f.SubjectType, SubjectID: f.SubjectID}
			bySubject[sk] = b
			subjectAgg[sk] = &riskBucketAgg{}
		}
		subjectAgg[sk].add(f)
		// 端点视图（endpoint_id 为 NULL 的发现聚为 "" 桶）
		ek := ""
		if f.EndpointID != nil {
			ek = f.EndpointID.String()
		}
		eb, ok := byEndpoint[ek]
		if !ok {
			eb = &RiskSummaryBucket{EndpointKey: f.EndpointKey}
			if f.EndpointID != nil {
				id := *f.EndpointID
				eb.EndpointID = &id
			}
			byEndpoint[ek] = eb
			endpointAgg[ek] = &riskBucketAgg{}
		}
		endpointAgg[ek].add(f)
		// 类型视图
		tb, ok := byType[f.FindingType]
		if !ok {
			tb = &RiskSummaryBucket{FindingType: f.FindingType}
			byType[f.FindingType] = tb
			typeAgg[f.FindingType] = &riskBucketAgg{}
		}
		typeAgg[f.FindingType].add(f)
	}

	fill := func(buckets map[string]*RiskSummaryBucket, aggs map[string]*riskBucketAgg, keyOf func(RiskSummaryBucket) string) []RiskSummaryBucket {
		out := make([]RiskSummaryBucket, 0, len(buckets))
		for k, b := range buckets {
			a := aggs[k]
			b.Count, b.Hits = a.count, a.hits
			b.MaxSeverity = riskSeverityFromRank(a.maxRank)
			b.LastSeenAt = a.lastSeen
			out = append(out, *b)
		}
		sort.Slice(out, func(i, j int) bool {
			ri, rj := riskSeverityRank(out[i].MaxSeverity), riskSeverityRank(out[j].MaxSeverity)
			if ri != rj {
				return ri > rj
			}
			if out[i].Hits != out[j].Hits {
				return out[i].Hits > out[j].Hits
			}
			return keyOf(out[i]) < keyOf(out[j])
		})
		if len(out) > riskSummaryLimit {
			out = out[:riskSummaryLimit]
		}
		return out
	}

	return &RiskSummary{
		BySubject:     fill(bySubject, subjectAgg, func(b RiskSummaryBucket) string { return b.SubjectType + "\x1f" + b.SubjectID }),
		ByEndpoint:    fill(byEndpoint, endpointAgg, func(b RiskSummaryBucket) string { return b.EndpointKey }),
		ByFindingType: fill(byType, typeAgg, func(b RiskSummaryBucket) string { return b.FindingType }),
	}, nil
}

// ListRelatedRequestIDs 关联请求 ID（语义与 SQL Store 一致：同端点，IDENTITY 主体
// 附带身份指纹过滤，occurred_at 倒序，上限 riskRelatedLimit）。
func (m *RiskMemStore) ListRelatedRequestIDs(ctx context.Context, endpointKey, subjectType, subjectID string, limit int) ([]string, error) {
	_ = ctx
	if limit <= 0 || limit > riskRelatedLimit {
		limit = riskRelatedLimit
	}
	identity := ""
	if subjectType == "IDENTITY" {
		identity = subjectID
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	matched := []riskMemEvent{}
	for _, ev := range m.events {
		if ev.EndpointKey != endpointKey {
			continue
		}
		if identity != "" && ev.IdentityFingerprint != identity {
			continue
		}
		matched = append(matched, ev)
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].OccurredAt.After(matched[j].OccurredAt) })
	out := []string{}
	for _, ev := range matched {
		if len(out) >= limit {
			break
		}
		out = append(out, ev.RequestID)
	}
	return out, nil
}
