// mem_store.go 数据出境内存仓储：与 SQL Store 相同业务语义，
// 供包内单测与无库环境驱动真实 Handler / Sweeper.SweepOnce。
package apigeo

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemStore 进程内仓储（实现 Repository + sweepStore）。
type MemStore struct {
	mu        sync.Mutex
	events    []runtimeEventRow  // 运行时事件（sweep 数据源；镜像 api_runtime_events 子集）
	rows      []CrossBorderEvent // 已落库观察行
	rowKeys   map[string]bool    // sourceEventID|direction 幂等键（镜像唯一约束）
	watermark *time.Time         // 单行水位（镜像 api_cross_border_state）
	levels    map[string]string  // 数据类型→敏感等级（镜像 api_sensitive_data_types）
}

// NewMemStore 创建空内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{
		rowKeys: map[string]bool{},
		levels:  map[string]string{},
	}
}

// 确保 *MemStore 同时实现只读与生产写入侧接口。
var (
	_ Repository = (*MemStore)(nil)
	_ sweepStore = (*MemStore)(nil)
)

// ---------- 测试造数辅助（包内单测使用） ----------

// addRuntimeEvent 追加一条运行时事件（sweep 数据源）。
func (m *MemStore) addRuntimeEvent(endpointKey, clientIP, identity string, occurredAt time.Time, details []byte) uuid.UUID {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := uuid.New()
	m.events = append(m.events, runtimeEventRow{
		id:          id,
		endpointKey: endpointKey,
		clientIP:    clientIP,
		identity:    identity,
		details:     details,
		occurredAt:  occurredAt,
	})
	return id
}

// setDataTypeLevels 设置数据类型→等级映射。
func (m *MemStore) setDataTypeLevels(levels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.levels = levels
}

// crossBorderRows 已落库观察行快照（断言用；occurred_at 升序）。
func (m *MemStore) crossBorderRows() []CrossBorderEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]CrossBorderEvent, len(m.rows))
	copy(out, m.rows)
	sort.Slice(out, func(i, j int) bool {
		if out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].Direction < out[j].Direction
		}
		return out[i].OccurredAt.Before(out[j].OccurredAt)
	})
	return out
}

// ---------- sweepStore 实现 ----------

// Watermark 当前水位（内存镜像）。
func (m *MemStore) Watermark(_ context.Context) (*time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.watermark == nil {
		return nil, nil
	}
	wm := *m.watermark
	return &wm, nil
}

// FetchSensitiveEvents 水位之后含敏感明细且带 client_ip 的事件（语义同 SQL：
// @> 命中按「任一明细 detector=sensitive_data」判定；occurred_at 升序限量）。
func (m *MemStore) FetchSensitiveEvents(_ context.Context, after *time.Time, limit int) ([]runtimeEventRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	matched := []runtimeEventRow{}
	for _, ev := range m.events {
		if ev.clientIP == "" {
			continue
		}
		if after != nil && !ev.occurredAt.After(*after) {
			continue
		}
		hits, err := extractSensitiveTypes(ev.details)
		if err != nil || len(hits) == 0 {
			continue // 无敏感明细（含脏 details，SweepOnce 不会见到这批行，与 SQL @> 口径一致）
		}
		matched = append(matched, ev)
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].occurredAt.Equal(matched[j].occurredAt) {
			return matched[i].id.String() < matched[j].id.String()
		}
		return matched[i].occurredAt.Before(matched[j].occurredAt)
	})
	if limit > 0 && len(matched) > limit {
		matched = matched[:limit]
	}
	return matched, nil
}

// DataTypeLevels 数据类型→等级映射（内存镜像）。
func (m *MemStore) DataTypeLevels(_ context.Context) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]string, len(m.levels))
	for k, v := range m.levels {
		out[k] = v
	}
	return out, nil
}

// RecordCrossBorder 幂等写入（sourceEventID|direction 去重）并推进水位。
func (m *MemStore) RecordCrossBorder(_ context.Context, rows []crossBorderRow, watermark time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inserted := 0
	for _, r := range rows {
		key := r.sourceEventID.String() + "|" + r.direction
		if m.rowKeys[key] {
			continue // ON CONFLICT DO NOTHING
		}
		m.rowKeys[key] = true
		m.rows = append(m.rows, CrossBorderEvent{
			ID:                  uuid.New(),
			OccurredAt:          r.occurredAt,
			ClientIP:            r.clientIP,
			Country:             r.country,
			EndpointKey:         r.endpointKey,
			IdentityFingerprint: r.identity,
			DataTypes:           r.dataTypes,
			Direction:           r.direction,
			RiskLevel:           r.riskLevel,
			SourceEventID:       r.sourceEventID,
			CreatedAt:           time.Now().UTC(),
		})
		inserted++
	}
	wm := watermark
	m.watermark = &wm
	return inserted, nil
}

// ---------- Repository 实现 ----------

// ListEvents 明细分页（内存镜像；窗口过滤语义同 SQL 的 CURRENT_DATE 口径，
// 内存实现以 now 为锚——单测造数均用相对时间，口径差异不影响断言）。
func (m *MemStore) ListEvents(_ context.Context, f EventFilter) ([]CrossBorderEvent, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	since := time.Now().UTC().AddDate(0, 0, -(clampDays(f.Days) - 1)).Truncate(24 * time.Hour)
	matched := []CrossBorderEvent{}
	for _, ev := range m.rows {
		if ev.OccurredAt.Before(since) {
			continue
		}
		if f.Country != "" && ev.Country != f.Country {
			continue
		}
		if f.Direction != "" && ev.Direction != f.Direction {
			continue
		}
		if f.RiskLevel != "" && ev.RiskLevel != f.RiskLevel {
			continue
		}
		if f.EndpointKey != "" && ev.EndpointKey != f.EndpointKey {
			continue
		}
		matched = append(matched, ev)
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
		return []CrossBorderEvent{}, total, nil
	}
	end := start + f.PageSize
	if end > len(matched) {
		end = len(matched)
	}
	return matched[start:end], total, nil
}

// Dashboard 看板聚合（内存镜像，语义同 SQL：同窗口汇总/国家×类型/端点/趋势零值补齐）。
func (m *MemStore) Dashboard(_ context.Context, days int) (*DashboardData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	days = clampDays(days)
	out := &DashboardData{
		Days:          days,
		ByCountry:     []CountryStat{},
		ByCountryType: []CountryTypeStat{},
		ByEndpoint:    []EndpointStat{},
		Trend:         []TrendPoint{},
	}
	anchor := time.Now().UTC().Truncate(24 * time.Hour)
	since := anchor.AddDate(0, 0, -(days - 1))

	type countryAgg struct {
		events    int64
		endpoints map[string]bool
		types     map[string]int64
	}
	type endpointAgg struct {
		events    int64
		countries map[string]bool
	}
	countries := map[string]*countryAgg{}
	endpoints := map[string]*endpointAgg{}
	byDay := map[string]int64{}
	for _, ev := range m.rows {
		if ev.OccurredAt.Before(since) {
			continue
		}
		out.Summary.TotalEvents++
		if ev.RiskLevel == RiskHigh {
			out.Summary.HighRiskCount++
		}
		ca := countries[ev.Country]
		if ca == nil {
			ca = &countryAgg{endpoints: map[string]bool{}, types: map[string]int64{}}
			countries[ev.Country] = ca
		}
		ca.events++
		ca.endpoints[ev.EndpointKey] = true
		for _, dt := range ev.DataTypes {
			ca.types[dt]++
		}
		ea := endpoints[ev.EndpointKey]
		if ea == nil {
			ea = &endpointAgg{countries: map[string]bool{}}
			endpoints[ev.EndpointKey] = ea
		}
		ea.events++
		ea.countries[ev.Country] = true
		byDay[ev.OccurredAt.Format("2006-01-02")]++
	}
	out.Summary.CountryCount = int64(len(countries))
	out.Summary.EndpointCount = int64(len(endpoints))

	countryKeys := make([]string, 0, len(countries))
	for c := range countries {
		countryKeys = append(countryKeys, c)
	}
	sort.Slice(countryKeys, func(i, j int) bool {
		ci, cj := countries[countryKeys[i]], countries[countryKeys[j]]
		if ci.events != cj.events {
			return ci.events > cj.events
		}
		return countryKeys[i] < countryKeys[j]
	})
	for _, c := range countryKeys {
		ca := countries[c]
		dts := make([]string, 0, len(ca.types))
		for dt := range ca.types {
			dts = append(dts, dt)
		}
		sort.Strings(dts)
		out.ByCountry = append(out.ByCountry, CountryStat{
			Country: c, EventCount: ca.events, EndpointCount: int64(len(ca.endpoints)), DataTypes: dts,
		})
		for _, dt := range dts {
			out.ByCountryType = append(out.ByCountryType, CountryTypeStat{
				Country: c, DataType: dt, EventCount: ca.types[dt],
			})
		}
	}
	// 国家×类型按事件数降序（与 SQL ORDER BY count(*) DESC 口径一致）
	sort.Slice(out.ByCountryType, func(i, j int) bool {
		if out.ByCountryType[i].EventCount != out.ByCountryType[j].EventCount {
			return out.ByCountryType[i].EventCount > out.ByCountryType[j].EventCount
		}
		if out.ByCountryType[i].Country != out.ByCountryType[j].Country {
			return out.ByCountryType[i].Country < out.ByCountryType[j].Country
		}
		return out.ByCountryType[i].DataType < out.ByCountryType[j].DataType
	})

	epKeys := make([]string, 0, len(endpoints))
	for k := range endpoints {
		epKeys = append(epKeys, k)
	}
	sort.Slice(epKeys, func(i, j int) bool {
		ei, ej := endpoints[epKeys[i]], endpoints[epKeys[j]]
		if ei.events != ej.events {
			return ei.events > ej.events
		}
		return epKeys[i] < epKeys[j]
	})
	for i, k := range epKeys {
		if i >= dashboardEndpointLimit {
			break
		}
		ea := endpoints[k]
		out.ByEndpoint = append(out.ByEndpoint, EndpointStat{
			EndpointKey: k, EventCount: ea.events, CountryCount: int64(len(ea.countries)),
		})
	}

	for i := days - 1; i >= 0; i-- {
		day := anchor.AddDate(0, 0, -i).Format("2006-01-02")
		out.Trend = append(out.Trend, TrendPoint{Date: day, EventCount: byDay[day]})
	}
	return out, nil
}
