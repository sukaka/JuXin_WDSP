// sitetraffic.go 站点流量日聚合：access_logs → site_traffic_daily（迁移 000165，
// 站点流量分析 >7 天视图数据源；access_logs 留存约 7 天，30 天视图必须走日聚合）。
// 幂等：以 UTC 天为单位重算今天+昨天（ON CONFLICT 主键 upsert，覆盖式重算），
// 随小时任务执行；末尾顺带清理 400 天前的桶。执行结果记 aggregation_jobs
// （SITE_TRAFFIC_DAILY），失败不静默。
package aggregations

import (
	"context"
	"fmt"
	"time"
)

// SiteTrafficDailyRetentionDays 日聚合桶留存天数（30 天视图之外保留回看余量）。
const SiteTrafficDailyRetentionDays = 400

// siteTrafficDailyWindow 重算窗口：[昨天 00:00 UTC, 明天 00:00 UTC)，覆盖今天与昨天。
func siteTrafficDailyWindow(now time.Time) (start, end time.Time) {
	day := now.UTC().Truncate(24 * time.Hour)
	return day.AddDate(0, 0, -1), day.AddDate(0, 0, 1)
}

// RunSiteTrafficDaily 重算今天与昨天的站点流量日聚合（幂等可重跑）。
func (j *Jobs) RunSiteTrafficDaily(ctx context.Context, now time.Time) error {
	start, end := siteTrafficDailyWindow(now)
	// 整窗重算：application_id 为 NULL 的日志行不入桶（无归属站点）；
	// bytes_in/out 为 NOT NULL 列，COALESCE 仅兜底空组防御。
	res, err := j.store.db.Exec(ctx, `
INSERT INTO site_traffic_daily
  (bucket_date, application_id, requests, bytes_in, bytes_out, unique_ips, blocked_requests, updated_at)
SELECT (l.occurred_at AT TIME ZONE 'UTC')::date, l.application_id,
  count(*),
  COALESCE(sum(l.bytes_in), 0),
  COALESCE(sum(l.bytes_out), 0),
  count(DISTINCT l.client_ip)::integer,
  count(*) FILTER (WHERE l.waf_action = 'BLOCK'),
  now()
FROM access_logs l
WHERE l.occurred_at >= $1 AND l.occurred_at < $2 AND l.application_id IS NOT NULL
GROUP BY 1, 2
ON CONFLICT (bucket_date, application_id) DO UPDATE SET
  requests = EXCLUDED.requests,
  bytes_in = EXCLUDED.bytes_in,
  bytes_out = EXCLUDED.bytes_out,
  unique_ips = EXCLUDED.unique_ips,
  blocked_requests = EXCLUDED.blocked_requests,
  updated_at = now()`, start, end)
	if err != nil {
		_ = j.store.recordJob(ctx, "SITE_TRAFFIC_DAILY", start, end, "FAILED", 0, err.Error())
		return fmt.Errorf("site traffic daily upsert: %w", err)
	}
	n := int(res.RowsAffected())
	// 留存清理：删除 400 天前的桶。
	cutoff := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -SiteTrafficDailyRetentionDays)
	if _, err := j.store.db.Exec(ctx,
		`DELETE FROM site_traffic_daily WHERE bucket_date < $1::date`, cutoff); err != nil {
		_ = j.store.recordJob(ctx, "SITE_TRAFFIC_DAILY", start, end, "FAILED", n, err.Error())
		return fmt.Errorf("site traffic daily cleanup: %w", err)
	}
	return j.store.recordJob(ctx, "SITE_TRAFFIC_DAILY", start, end, "SUCCESS", n, "")
}
