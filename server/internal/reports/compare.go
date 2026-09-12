package reports

import "fmt"

// 环比对比：本期与上一等长周期同口径指标对照，变化方向与幅度确定性计算。
// Tone 语义：bad=恶化（HTML 红 / PDF/Word 标红行）、good=改善（HTML 绿）、""=中性。

// ComparisonData 上一等长周期对照数据（采集层填充）。
type ComparisonData struct {
	PrevRangeStart    int64 `json:"prev_range_start"` // 上一周期起点（Unix 秒，0 表示未采集）
	PrevRangeEnd      int64 `json:"prev_range_end"`
	PrevTotalRequests int64 `json:"prev_total_requests"`
	PrevEventsTotal   int64 `json:"prev_events_total"`
	PrevEventsBlocked int64 `json:"prev_events_blocked"`
	PrevHighSeverity  int64 `json:"prev_high_severity"`
}

// Available 是否已采集到对照数据。
func (c ComparisonData) Available() bool {
	return c.PrevRangeEnd > 0
}

// ComparisonRow 环比展示行。
type ComparisonRow struct {
	Name     string `json:"name"`
	Current  string `json:"current"`
	Previous string `json:"previous"`
	Delta    string `json:"delta"`
	Tone     string `json:"tone"` // bad / good / ""
}

// deltaText 变化幅度文本：+12.3% / -5.1% / 持平；上期为 0 时本期>0 记「新增」，双 0 记「-」。
func deltaText(cur, prev int64) string {
	if prev <= 0 {
		if cur > 0 {
			return "新增"
		}
		return "-"
	}
	if cur == prev {
		return "持平"
	}
	d := float64(cur-prev) * 100 / float64(prev)
	if d > 0 {
		return fmt.Sprintf("+%.1f%%", d)
	}
	return fmt.Sprintf("%.1f%%", d)
}

// deltaTone 变化方向语义：上升且 badWhenUp 为恶化，反之为改善；阻断率类反向。
func deltaTone(cur, prev int64, badWhenUp bool) string {
	if prev <= 0 {
		if cur > 0 && badWhenUp {
			return "bad"
		}
		return ""
	}
	if cur == prev {
		return ""
	}
	up := cur > prev
	if up == badWhenUp {
		return "bad"
	}
	return "good"
}

// deltaPpText 比率变化（百分点）：+3.2pp / -1.5pp / 持平。
func deltaPpText(cur, prev float64) string {
	d := cur - prev
	switch {
	case d > 0.05:
		return fmt.Sprintf("+%.1fpp", d)
	case d < -0.05:
		return fmt.Sprintf("%.1fpp", d)
	default:
		return "持平"
	}
}

// BuildComparisonRows 构建环比展示行（数据未采集返回 nil）。
// 行顺序固定：总请求数 / 安全事件 / 阻断事件 / 高危及以上 / 阻断率。
func BuildComparisonRows(d *ReportData) []ComparisonRow {
	if d == nil || !d.Comparison.Available() {
		return nil
	}
	c := d.Comparison
	rate := pct(d.EventsBlocked, d.EventsTotal)
	prevRate := pct(c.PrevEventsBlocked, c.PrevEventsTotal)
	rateTone := ""
	if d.EventsTotal > 0 && c.PrevEventsTotal > 0 && rate != prevRate {
		if rate < prevRate {
			rateTone = "bad"
		} else {
			rateTone = "good"
		}
	}
	return []ComparisonRow{
		{"总请求数", fmt.Sprint(d.TotalRequests), fmt.Sprint(c.PrevTotalRequests),
			deltaText(d.TotalRequests, c.PrevTotalRequests), ""},
		{"安全事件总数", fmt.Sprint(d.EventsTotal), fmt.Sprint(c.PrevEventsTotal),
			deltaText(d.EventsTotal, c.PrevEventsTotal), deltaTone(d.EventsTotal, c.PrevEventsTotal, true)},
		{"阻断事件", fmt.Sprint(d.EventsBlocked), fmt.Sprint(c.PrevEventsBlocked),
			deltaText(d.EventsBlocked, c.PrevEventsBlocked), deltaTone(d.EventsBlocked, c.PrevEventsBlocked, true)},
		{"高危及以上事件", fmt.Sprint(d.HighSeverity), fmt.Sprint(c.PrevHighSeverity),
			deltaText(d.HighSeverity, c.PrevHighSeverity), deltaTone(d.HighSeverity, c.PrevHighSeverity, true)},
		{"阻断率", fmt.Sprintf("%.1f%%", rate), fmt.Sprintf("%.1f%%", prevRate),
			deltaPpText(rate, prevRate), rateTone},
	}
}

// comparisonMarks 环比表标红行（Tone=bad）。
func comparisonMarks(rows []ComparisonRow) []bool {
	marks := make([]bool, len(rows))
	for i, r := range rows {
		marks[i] = r.Tone == "bad"
	}
	return marks
}

// cnNumeral 中文数字（1-99，章节编号用）。
func cnNumeral(n int) string {
	digits := []string{"零", "一", "二", "三", "四", "五", "六", "七", "八", "九", "十"}
	if n >= 1 && n <= 10 {
		return digits[n]
	}
	if n < 20 {
		return "十" + digits[n-10]
	}
	if n < 100 {
		s := digits[n/10] + "十"
		if n%10 > 0 {
			s += digits[n%10]
		}
		return s
	}
	return fmt.Sprint(n)
}
