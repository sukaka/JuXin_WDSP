// traffic.go API 接口流量趋势桶留存清理（WDSP 接口访问趋势波形图，迁移 000034）。
// api_endpoint_traffic_buckets 由采集器按端点 × 5 分钟桶持续自增，趋势查询最长
// range=7d，超出留存窗口的桶随小时任务删除；执行结果记 aggregation_jobs
// （TRAFFIC_CLEANUP），失败不静默。
package aggregations

import (
	"context"
	"time"
)

// TrafficBucketRetention 流量桶留存窗口（趋势查询最长 range=7d）。
const TrafficBucketRetention = 7 * 24 * time.Hour

// RunTrafficBucketCleanup 删除 7 天前的接口流量桶（随小时任务执行，幂等可重跑）。
func (j *Jobs) RunTrafficBucketCleanup(ctx context.Context, now time.Time) error {
	cutoff := now.UTC().Add(-TrafficBucketRetention)
	res, err := j.store.db.Exec(ctx,
		`DELETE FROM api_endpoint_traffic_buckets WHERE bucket_start < $1`, cutoff)
	n := 0
	if err == nil {
		n = int(res.RowsAffected())
	}
	if err != nil {
		_ = j.store.recordJob(ctx, "TRAFFIC_CLEANUP", cutoff, now.UTC(), "FAILED", n, err.Error())
		return err
	}
	return j.store.recordJob(ctx, "TRAFFIC_CLEANUP", cutoff, now.UTC(), "SUCCESS", n, "")
}
