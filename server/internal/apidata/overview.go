// overview.go 敏感数据态势聚合（api_sensitive_fields + api_runtime_events）。
package apidata

import (
	"context"
	"fmt"
	"time"
)

// OverviewDefaultDays 趋势默认天数（近 7 天）；上限防过宽聚合。
const (
	OverviewDefaultDays = 7
	OverviewMaxDays     = 30
)

// SensitiveOverview 敏感数据态势。
type SensitiveOverview struct {
	SensitiveEndpointCount int64          `json:"sensitive_endpoint_count"` // 涉敏 API 数（去重端点）
	SensitiveFieldCount    int64          `json:"sensitive_field_count"`    // 敏感字段行数
	TypeDistribution       []TypeDistItem `json:"type_distribution"`        // 按数据类型分布
	Trend                  []TrendPoint   `json:"trend"`                    // 近 days 天敏感检测趋势（零值日补齐）
	Days                   int            `json:"days"`
}

// TypeDistItem 数据类型分布项。
type TypeDistItem struct {
	DataType        string `json:"data_type"`
	FieldCount      int64  `json:"field_count"`      // 该类型字段行数
	EndpointCount   int64  `json:"endpoint_count"`   // 该类型涉敏端点数
	OccurrenceCount int64  `json:"occurrence_count"` // 该类型累计命中次数
}

// TrendPoint 单日趋势点。
type TrendPoint struct {
	Date       string `json:"date"`        // YYYY-MM-DD（库会话时区 CURRENT_DATE 口径）
	EventCount int64  `json:"event_count"` // 含敏感明细的运行时事件数
	HitCount   int64  `json:"hit_count"`   // 敏感证据条目数
}

// clampOverviewDays 归一天数（1..OverviewMaxDays，默认 OverviewDefaultDays）。
func clampOverviewDays(days int) int {
	if days <= 0 {
		return OverviewDefaultDays
	}
	if days > OverviewMaxDays {
		return OverviewMaxDays
	}
	return days
}

// SensitiveOverview 聚合敏感数据态势（SQL 实现）。
// 趋势日期以数据库 CURRENT_DATE 为锚（与 occurred_at::date 分组同会话时区），
// 零值日在 Go 侧补齐，返回天数固定为 days。
func (s *Store) SensitiveOverview(ctx context.Context, days int) (*SensitiveOverview, error) {
	days = clampOverviewDays(days)
	out := &SensitiveOverview{TypeDistribution: []TypeDistItem{}, Trend: []TrendPoint{}, Days: days}

	// 汇总：涉敏端点数 + 字段行数
	if err := s.db.QueryRow(ctx, `
SELECT count(DISTINCT endpoint_id), count(*) FROM api_sensitive_fields`).
		Scan(&out.SensitiveEndpointCount, &out.SensitiveFieldCount); err != nil {
		return nil, fmt.Errorf("overview summary: %w", err)
	}

	// 类型分布（字段数降序）
	rows, err := s.db.Query(ctx, `
SELECT data_type, count(*), count(DISTINCT endpoint_id), COALESCE(sum(occurrence_count), 0)
FROM api_sensitive_fields GROUP BY data_type ORDER BY count(*) DESC, data_type`)
	if err != nil {
		return nil, fmt.Errorf("overview type distribution: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var it TypeDistItem
		if err := rows.Scan(&it.DataType, &it.FieldCount, &it.EndpointCount, &it.OccurrenceCount); err != nil {
			return nil, err
		}
		out.TypeDistribution = append(out.TypeDistribution, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 日期锚（库会话时区，与 occurred_at::date 分组口径一致）
	var anchor time.Time
	if err := s.db.QueryRow(ctx, `SELECT CURRENT_DATE`).Scan(&anchor); err != nil {
		return nil, fmt.Errorf("overview date anchor: %w", err)
	}

	// 趋势：事件数（含敏感明细的事件）与证据条目数（明细条数）分两查合并
	eventRows, err := s.db.Query(ctx, `
SELECT occurred_at::date, count(*) FROM api_runtime_events
WHERE occurred_at >= CURRENT_DATE - ($1::int - 1) * interval '1 day'
  AND details_json @> '[{"detector":"sensitive_data"}]'::jsonb
GROUP BY 1`, days)
	if err != nil {
		return nil, fmt.Errorf("overview trend events: %w", err)
	}
	eventByDay := map[string]int64{}
	for eventRows.Next() {
		var d time.Time
		var n int64
		if err := eventRows.Scan(&d, &n); err != nil {
			eventRows.Close()
			return nil, err
		}
		eventByDay[d.Format("2006-01-02")] = n
	}
	eventRows.Close()
	if err := eventRows.Err(); err != nil {
		return nil, err
	}

	hitRows, err := s.db.Query(ctx, `
SELECT occurred_at::date, count(*) FROM api_runtime_events, jsonb_array_elements(details_json) AS item
WHERE occurred_at >= CURRENT_DATE - ($1::int - 1) * interval '1 day'
  AND item->>'detector' = 'sensitive_data'
GROUP BY 1`, days)
	if err != nil {
		return nil, fmt.Errorf("overview trend hits: %w", err)
	}
	hitByDay := map[string]int64{}
	for hitRows.Next() {
		var d time.Time
		var n int64
		if err := hitRows.Scan(&d, &n); err != nil {
			hitRows.Close()
			return nil, err
		}
		hitByDay[d.Format("2006-01-02")] = n
	}
	hitRows.Close()
	if err := hitRows.Err(); err != nil {
		return nil, err
	}

	// 零值日补齐（升序）
	for i := days - 1; i >= 0; i-- {
		day := anchor.AddDate(0, 0, -i).Format("2006-01-02")
		out.Trend = append(out.Trend, TrendPoint{
			Date:       day,
			EventCount: eventByDay[day],
			HitCount:   hitByDay[day],
		})
	}
	return out, nil
}
