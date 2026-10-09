// sitetraffic_test.go 站点流量日聚合窗口纯逻辑单测（不依赖数据库；
// upsert/清理的窗口覆盖语义由 SQL 与 aggregation_jobs 记录保证）。
package aggregations

import (
	"testing"
	"time"
)

func TestSiteTrafficDailyWindow(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 34, 56, 0, time.UTC)
	start, end := siteTrafficDailyWindow(now)
	wantStart := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	wantEnd := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	if !start.Equal(wantStart) || !end.Equal(wantEnd) {
		t.Errorf("window: %v ~ %v, want %v ~ %v", start, end, wantStart, wantEnd)
	}
	// 跨月边界：9-01 的昨天是 8-31
	now = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	start, end = siteTrafficDailyWindow(now)
	if !start.Equal(time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)) ||
		!end.Equal(time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("month boundary window: %v ~ %v", start, end)
	}
	// 非 UTC 输入按 UTC 天取窗口（+08:00 07:30 仍是 UTC 前一天）
	loc := time.FixedZone("CST", 8*3600)
	now = time.Date(2026, 9, 19, 7, 30, 0, 0, loc) // UTC 2026-09-18 23:30
	start, end = siteTrafficDailyWindow(now)
	if !start.Equal(time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)) ||
		!end.Equal(time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("tz conversion window: %v ~ %v", start, end)
	}
}

func TestSiteTrafficDailyRetentionCutoff(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	cutoff := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -SiteTrafficDailyRetentionDays)
	want := time.Date(2025, 8, 15, 0, 0, 0, 0, time.UTC) // 400 个日历日前
	if !cutoff.Equal(want) {
		t.Errorf("cutoff = %v, want %v", cutoff, want)
	}
}
