// Package analytics 阶段6统计分析接口：请求/WAF/CC/访问控制/处置统计。
// 数据分层：≤24h 查 metric_minute_aggregates，>24h 查 metric_hour_aggregates；
// 实时分布与排行直接查业务表（security_events / access_control_events）。
package analytics

import (
	"errors"
	"fmt"
	"net/url"
	"time"
)

const (
	// MaxRange 查询时间范围上限（366 天）。
	MaxRange = 366 * 24 * time.Hour
	// defaultRange 缺省查询最近 24 小时。
	defaultRange = 24 * time.Hour
	// minuteTierLimit 不超过该时长的范围查询分钟聚合表。
	minuteTierLimit = 24 * time.Hour
)

// Range 是已校验的查询时间范围（UTC，[Start, End)）。
type Range struct {
	Start time.Time
	End   time.Time
}

// Table 按数据分层规则选择聚合表：≤24h 分钟表，>24h 小时表。
func (r Range) Table() string {
	if r.End.Sub(r.Start) <= minuteTierLimit {
		return "metric_minute_aggregates"
	}
	return "metric_hour_aggregates"
}

// Granularity 返回当前范围对应的聚合粒度描述（minute / hour）。
func (r Range) Granularity() string {
	if r.Table() == "metric_minute_aggregates" {
		return "minute"
	}
	return "hour"
}

// TrendBucket 直接查事件表时的 date_trunc 桶粒度。
func (r Range) TrendBucket() string {
	d := r.End.Sub(r.Start)
	switch {
	case d <= time.Hour:
		return "minute"
	case d <= 7*24*time.Hour:
		return "hour"
	default:
		return "day"
	}
}

var errInvalidRange = errors.New("无效的时间范围")

// ParseRange 解析 start_time/end_time（RFC3339）。两者均缺省时取最近 24 小时；
// 仅给 end_time 时 start 取 end 前 24 小时。
func ParseRange(q url.Values, now time.Time) (Range, error) {
	now = now.UTC()
	end := now
	start := now.Add(-defaultRange)
	endGiven := false
	if v := q.Get("end_time"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return Range{}, fmt.Errorf("%w: end_time 必须为 RFC3339 格式", errInvalidRange)
		}
		end = t.UTC()
		endGiven = true
	}
	if v := q.Get("start_time"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return Range{}, fmt.Errorf("%w: start_time 必须为 RFC3339 格式", errInvalidRange)
		}
		start = t.UTC()
	} else if endGiven {
		start = end.Add(-defaultRange)
	}
	if !start.Before(end) {
		return Range{}, fmt.Errorf("%w: start_time 必须早于 end_time", errInvalidRange)
	}
	if end.Sub(start) > MaxRange {
		return Range{}, fmt.Errorf("%w: 时间跨度不能超过 366 天", errInvalidRange)
	}
	return Range{Start: start, End: end}, nil
}

// IsInvalidRange 判断是否为时间范围校验错误（用于 400 映射）。
func IsInvalidRange(err error) bool { return errors.Is(err, errInvalidRange) }
