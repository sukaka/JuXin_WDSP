package reports

import (
	"errors"
	"fmt"
	"time"
)

// ErrInvalidRange 时间范围非法。
var ErrInvalidRange = errors.New("invalid report time range")

// ComputeTimeRange 按报告类型计算统计时间范围（UTC，左闭右开）。
//   - DAILY：昨天全天 [今日0点-1天, 今日0点)
//   - WEEKLY：上周（周一0点 到 本周一0点）
//   - MONTHLY：上月（本月1号0点 到 上月1号0点的前一月区间）
//   - CUSTOM：必须显式给出起止，end > start，跨度 ≤ 366 天
func ComputeTimeRange(reportType string, start, end *time.Time, now time.Time) (time.Time, time.Time, error) {
	now = now.UTC()
	switch reportType {
	case TypeDaily:
		today := now.Truncate(24 * time.Hour)
		return today.AddDate(0, 0, -1), today, nil
	case TypeWeekly:
		// 本周一 0 点（UTC）
		today := now.Truncate(24 * time.Hour)
		offset := (int(today.Weekday()) + 6) % 7 // 周一=0
		thisMonday := today.AddDate(0, 0, -offset)
		return thisMonday.AddDate(0, 0, -7), thisMonday, nil
	case TypeMonthly:
		firstOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		return firstOfMonth.AddDate(0, -1, 0), firstOfMonth, nil
	case TypeCustom:
		if start == nil || end == nil {
			return time.Time{}, time.Time{}, fmt.Errorf("%w: 自定义报告必须提供起止时间", ErrInvalidRange)
		}
		s := start.UTC()
		e := end.UTC()
		if !e.After(s) {
			return time.Time{}, time.Time{}, fmt.Errorf("%w: 结束时间必须晚于开始时间", ErrInvalidRange)
		}
		if e.Sub(s) > MaxCustomRangeHours*time.Hour {
			return time.Time{}, time.Time{}, fmt.Errorf("%w: 自定义时间跨度不能超过%d天", ErrInvalidRange, MaxCustomRangeHours/24)
		}
		return s, e, nil
	default:
		return time.Time{}, time.Time{}, fmt.Errorf("%w: 未知的报告类型 %q", ErrInvalidRange, reportType)
	}
}
