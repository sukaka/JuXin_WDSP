// mem_store.go LLM 观测内存仓储：与 SQL Store 相同业务语义，
// 供包内单测与无库环境驱动真实 Handler。
package apillm

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemStore 进程内仓储（实现 Repository）。
type MemStore struct {
	mu   sync.Mutex
	rows []Observation
}

// NewMemStore 创建空内存仓储。
func NewMemStore() *MemStore { return &MemStore{} }

var _ Repository = (*MemStore)(nil)

// addObservation 追加一条观测行（包内单测造数辅助）。
func (m *MemStore) addObservation(o Observation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows = append(m.rows, o)
}

// ListObservations 明细分页（内存镜像；窗口语义同 SQL 的 CURRENT_DATE 口径，
// 内存实现以 now 为锚——单测造数均用相对时间，口径差异不影响断言）。
func (m *MemStore) ListObservations(_ context.Context, f ObservationFilter) ([]Observation, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	since := time.Now().UTC().AddDate(0, 0, -(clampDays(f.Days) - 1)).Truncate(24 * time.Hour)
	matched := []Observation{}
	for _, o := range m.rows {
		if o.OccurredAt.Before(since) {
			continue
		}
		if f.Model != "" && o.Model != f.Model {
			continue
		}
		if f.EndpointKey != "" && o.EndpointKey != f.EndpointKey {
			continue
		}
		if f.FindingsOnly && len(o.Findings) == 0 {
			continue
		}
		matched = append(matched, o)
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].OccurredAt.Equal(matched[j].OccurredAt) {
			return matched[i].ID.String() > matched[j].ID.String()
		}
		return matched[i].OccurredAt.After(matched[j].OccurredAt)
	})
	total := int64(len(matched))
	start := (f.Page - 1) * f.PageSize
	if start >= len(matched) {
		return []Observation{}, total, nil
	}
	end := start + f.PageSize
	if end > len(matched) {
		end = len(matched)
	}
	return matched[start:end], total, nil
}

// Stats 统计聚合（内存镜像，语义同 SQL：汇总 + 模型分布 + 按天趋势 + 规则分布）。
func (m *MemStore) Stats(_ context.Context, days int) (*StatsData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	days = clampDays(days)
	out := &StatsData{
		Days:           days,
		ByModel:        []ModelStat{},
		TokenTrend:     []TokenTrendPoint{},
		FindingsByRule: []FindingRuleStat{},
	}
	since := time.Now().UTC().AddDate(0, 0, -(days - 1)).Truncate(24 * time.Hour)
	type modelAgg struct {
		observations, tokens, findings int64
	}
	models := map[string]*modelAgg{}
	modelSeen := map[string]bool{}
	trend := map[string]*modelAgg{} // day → observations/tokens
	rules := map[string]int64{}
	for _, o := range m.rows {
		if o.OccurredAt.Before(since) {
			continue
		}
		out.Summary.Observations++
		if len(o.Findings) > 0 {
			out.Summary.WithFindings++
		}
		out.Summary.TotalTokens += int64(o.TotalTokens)
		if o.Stream {
			out.Summary.StreamCalls++
		}
		if !modelSeen[o.Model] {
			modelSeen[o.Model] = true
		}
		ma := models[o.Model]
		if ma == nil {
			ma = &modelAgg{}
			models[o.Model] = ma
		}
		ma.observations++
		ma.tokens += int64(o.TotalTokens)
		ma.findings += int64(len(o.Findings))
		day := o.OccurredAt.Format("2006-01-02")
		ta := trend[day]
		if ta == nil {
			ta = &modelAgg{}
			trend[day] = ta
		}
		ta.observations++
		ta.tokens += int64(o.TotalTokens)
		for _, f := range o.Findings {
			rules[f.RuleID]++
		}
	}
	out.Summary.DistinctModels = int64(len(modelSeen))

	modelKeys := make([]string, 0, len(models))
	for k := range models {
		modelKeys = append(modelKeys, k)
	}
	sort.Slice(modelKeys, func(i, j int) bool {
		if models[modelKeys[i]].observations != models[modelKeys[j]].observations {
			return models[modelKeys[i]].observations > models[modelKeys[j]].observations
		}
		return modelKeys[i] < modelKeys[j]
	})
	for i, k := range modelKeys {
		if i >= topLimit {
			break
		}
		out.ByModel = append(out.ByModel, ModelStat{
			Model: k, Observations: models[k].observations,
			TotalTokens: models[k].tokens, Findings: models[k].findings,
		})
	}
	days2 := make([]string, 0, len(trend))
	for d := range trend {
		days2 = append(days2, d)
	}
	sort.Strings(days2)
	for _, d := range days2 {
		out.TokenTrend = append(out.TokenTrend, TokenTrendPoint{
			Day: d, Observations: trend[d].observations, TotalTokens: trend[d].tokens,
		})
	}
	ruleKeys := make([]string, 0, len(rules))
	for k := range rules {
		ruleKeys = append(ruleKeys, k)
	}
	sort.Slice(ruleKeys, func(i, j int) bool {
		if rules[ruleKeys[i]] != rules[ruleKeys[j]] {
			return rules[ruleKeys[i]] > rules[ruleKeys[j]]
		}
		return ruleKeys[i] < ruleKeys[j]
	})
	for i, k := range ruleKeys {
		if i >= topLimit {
			break
		}
		out.FindingsByRule = append(out.FindingsByRule, FindingRuleStat{RuleID: k, Count: rules[k]})
	}
	return out, nil
}
