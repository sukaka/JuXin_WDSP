package aiorchestrator

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// QueryTimeRange 是从用户问题中解析出的查询时间窗口。
type QueryTimeRange struct {
	Start    time.Time
	End      time.Time
	Label    string
	Explicit bool
}

var relativeTimeRangePattern = regexp.MustCompile(`(?:最近|近|过去)?\s*(\d{1,3})\s*(分钟|小时|天|日|周|个月|月)`)

// ParseQueryTimeRange 解析常用中文时间表达。追问里显式给出的时间优先于历史问题。
func ParseQueryTimeRange(message string, now time.Time) QueryTimeRange {
	if now.IsZero() {
		now = time.Now()
	}
	if index := strings.LastIndex(message, "当前追问："); index >= 0 {
		if parsed, ok := parseExplicitTimeRange(message[index+len("当前追问："):], now); ok {
			return parsed
		}
	}
	if parsed, ok := parseExplicitTimeRange(message, now); ok {
		return parsed
	}
	return QueryTimeRange{Start: now.Add(-24 * time.Hour), End: now, Label: "最近 24 小时"}
}

func parseExplicitTimeRange(message string, now time.Time) (QueryTimeRange, bool) {
	text := strings.TrimSpace(message)
	location := now.Location()
	startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, location)

	switch {
	case strings.Contains(text, "昨天") || strings.Contains(text, "昨日"):
		return explicitRange(startOfToday.AddDate(0, 0, -1), startOfToday, "昨天"), true
	case strings.Contains(text, "今天") || strings.Contains(text, "今日"):
		return explicitRange(startOfToday, now, "今天"), true
	case strings.Contains(text, "上周"):
		thisWeek := startOfWeek(startOfToday)
		return explicitRange(thisWeek.AddDate(0, 0, -7), thisWeek, "上周"), true
	case strings.Contains(text, "本周") || strings.Contains(text, "这周"):
		return explicitRange(startOfWeek(startOfToday), now, "本周"), true
	case strings.Contains(text, "上个月") || strings.Contains(text, "上月"):
		thisMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, location)
		return explicitRange(thisMonth.AddDate(0, -1, 0), thisMonth, "上个月"), true
	case strings.Contains(text, "本月") || strings.Contains(text, "这个月"):
		return explicitRange(time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, location), now, "本月"), true
	}

	match := relativeTimeRangePattern.FindStringSubmatch(text)
	if len(match) != 3 {
		return QueryTimeRange{}, false
	}
	amount, err := strconv.Atoi(match[1])
	if err != nil || amount <= 0 {
		return QueryTimeRange{}, false
	}

	var duration time.Duration
	unitLabel := match[2]
	switch match[2] {
	case "分钟":
		duration = time.Duration(amount) * time.Minute
	case "小时":
		duration = time.Duration(amount) * time.Hour
	case "天", "日":
		duration = time.Duration(amount) * 24 * time.Hour
		unitLabel = "天"
	case "周":
		duration = time.Duration(amount) * 7 * 24 * time.Hour
	case "个月", "月":
		duration = time.Duration(amount) * 30 * 24 * time.Hour
		unitLabel = "个月"
	}
	const maximumRange = 90 * 24 * time.Hour
	if duration > maximumRange {
		duration = maximumRange
		return explicitRange(now.Add(-duration), now, "最近 90 天"), true
	}
	return explicitRange(now.Add(-duration), now, fmt.Sprintf("最近 %d %s", amount, unitLabel)), true
}

func explicitRange(start, end time.Time, label string) QueryTimeRange {
	return QueryTimeRange{Start: start, End: end, Label: label, Explicit: true}
}

func startOfWeek(day time.Time) time.Time {
	daysSinceMonday := (int(day.Weekday()) + 6) % 7
	return day.AddDate(0, 0, -daysSinceMonday)
}
