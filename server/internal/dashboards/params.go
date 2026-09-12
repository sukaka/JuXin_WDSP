// Package dashboards 阶段6态势首页数据：安全态势 / 运行态势 / 审计态势。
// 数据分层：≤24h 查 metric_minute_aggregates，>24h 查 metric_hour_aggregates；
// 实时状态直接查业务表（security_events / temporary_blocks / applications 等）。
package dashboards

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// trendRangeNames 合法的趋势范围参数 → 时长。
var trendRangeNames = map[string]time.Duration{
	"1h":  time.Hour,
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
}

// ParseTrendRange 解析 range 参数（1h/24h/7d/30d，空为默认 24h）。
func ParseTrendRange(s string) (time.Duration, error) {
	if s == "" {
		return 24 * time.Hour, nil
	}
	d, ok := trendRangeNames[s]
	if !ok {
		return 0, fmt.Errorf("无效的 range 参数（支持 1h/24h/7d/30d）")
	}
	return d, nil
}

// AggTableFor 按数据分层规则选择聚合表：≤24h 分钟表，>24h 小时表。
func AggTableFor(d time.Duration) string {
	if d <= 24*time.Hour {
		return "metric_minute_aggregates"
	}
	return "metric_hour_aggregates"
}

// TrendStep 趋势图取桶步长：1h→分钟，24h/7d→小时，30d→天。
func TrendStep(d time.Duration) time.Duration {
	switch {
	case d <= time.Hour:
		return time.Minute
	case d <= 7*24*time.Hour:
		return time.Hour
	default:
		return 24 * time.Hour
	}
}

// StepTrunc 返回 date_trunc 粒度字符串（事件表直接分桶用）。
func StepTrunc(step time.Duration) string {
	switch step {
	case time.Minute:
		return "minute"
	case time.Hour:
		return "hour"
	default:
		return "day"
	}
}

// TodayWindowUTC 返回 UTC 当日窗口 [当日零点, now]。
func TodayWindowUTC(now time.Time) (time.Time, time.Time) {
	now = now.UTC()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	return start, now
}

// BucketTimes 生成 [start, end) 内按 step 对齐的桶时间序列（起点截断到 step）。
func BucketTimes(start, end time.Time, step time.Duration) []time.Time {
	out := []time.Time{}
	if !start.Before(end) {
		return out
	}
	for t := start.Truncate(step); t.Before(end); t = t.Add(step) {
		out = append(out, t)
	}
	return out
}

// SeriesInto 把任意粒度的时间点序列聚合进固定桶（同桶求和），返回与 buckets 等长的数组。
func SeriesInto(buckets, times []time.Time, values []float64, step time.Duration) []float64 {
	idx := make(map[time.Time]int, len(buckets))
	for i, b := range buckets {
		idx[b] = i
	}
	out := make([]float64, len(buckets))
	for i, t := range times {
		if j, ok := idx[t.Truncate(step)]; ok {
			out[j] += values[i]
		}
	}
	return out
}

// SeriesMapInto 多维度序列（键 → 点序列）聚合进固定桶。
func SeriesMapInto(buckets []time.Time, series map[string][]struct {
	T time.Time
	V float64
}, step time.Duration,
) map[string][]float64 {
	keys := make([]string, 0, len(series))
	for k := range series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string][]float64, len(series))
	for _, k := range keys {
		var times []time.Time
		var values []float64
		for _, p := range series[k] {
			times = append(times, p.T)
			values = append(values, p.V)
		}
		out[k] = SeriesInto(buckets, times, values, step)
	}
	return out
}

// ParseInfoUsedMemory 解析 Valkey/Redis INFO memory 输出中的 used_memory 字节数。
func ParseInfoUsedMemory(info string) (int64, bool) {
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimRight(line, "\r")
		k, v, ok := strings.Cut(line, ":")
		if !ok || k != "used_memory" {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
