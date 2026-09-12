// traffic.go API 接口流量趋势桶（WDSP 接口访问趋势波形图，迁移 000034）。
//
// 写入侧：apiruntime.Collector 端点发现 upsert 成功拿到 endpoint_id 后，
// 对 (endpoint_id, 5 分钟桶) ON CONFLICT 自增（RecordTrafficBucket）；
// 查询侧：GET /api/v1/api-security/endpoints/{id}/traffic-trend 读窗口内桶，
// 服务端补零（FillTrafficPoints）输出连续时间升序点列。
package apiassets

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TrafficBucketSeconds 流量桶宽（秒）：5 分钟，UTC 对齐。
const TrafficBucketSeconds = 300

// TrafficBucketStart 返回 t 所属流量桶起点（UTC 5 分钟对齐；剥离单调时钟，
// 返回值可直接做 map 键）。
func TrafficBucketStart(t time.Time) time.Time {
	return t.UTC().Truncate(TrafficBucketSeconds * time.Second)
}

// ParseTrafficRange 解析 range 查询参数：1h / 24h / 7d；空或非法值回落默认 24h。
func ParseTrafficRange(s string) (name string, dur time.Duration) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1h":
		return "1h", time.Hour
	case "7d":
		return "7d", 7 * 24 * time.Hour
	default:
		return "24h", 24 * time.Hour
	}
}

// TrafficPoint 单个流量桶点（time 为桶起点，UTC）。
type TrafficPoint struct {
	Time  time.Time `json:"time"`
	Count int64     `json:"count"`
}

// TrafficTrend 接口流量趋势（traffic-trend 响应 data 层）。
type TrafficTrend struct {
	EndpointID    string         `json:"endpoint_id"`
	BucketSeconds int            `json:"bucket_seconds"`
	Range         string         `json:"range"`
	Total         int64          `json:"total"`
	Points        []TrafficPoint `json:"points"`
}

// FillTrafficPoints 服务端补零：从 from 所属桶到 now 所属桶输出连续 5 分钟桶
// （counts 无数据的桶 count=0），时间升序；同时返回窗口内请求总量。
// counts 的键必须是 UTC 对齐桶起点（TrafficBucketStart）。
func FillTrafficPoints(from, now time.Time, counts map[time.Time]int64) ([]TrafficPoint, int64) {
	start := TrafficBucketStart(from)
	last := TrafficBucketStart(now)
	points := make([]TrafficPoint, 0, int(last.Sub(start)/(TrafficBucketSeconds*time.Second))+1)
	var total int64
	for b := start; !b.After(last); b = b.Add(TrafficBucketSeconds * time.Second) {
		c := counts[b]
		points = append(points, TrafficPoint{Time: b, Count: c})
		total += c
	}
	return points, total
}

// RecordTrafficBucket 端点流量桶自增（采集链路写入；按 (endpoint_id, bucket_start) 幂等累加）。
func (s *Store) RecordTrafficBucket(ctx context.Context, endpointID uuid.UUID, bucketStart time.Time) error {
	_, err := s.db.Exec(ctx, `
INSERT INTO api_endpoint_traffic_buckets (endpoint_id, bucket_start, request_count)
VALUES ($1, $2, 1)
ON CONFLICT (endpoint_id, bucket_start) DO UPDATE SET
  request_count = api_endpoint_traffic_buckets.request_count + 1`,
		endpointID, TrafficBucketStart(bucketStart))
	return err
}

// TrafficBuckets 读取 [from, to) 窗口内流量桶（键为 UTC 对齐桶起点，供 FillTrafficPoints 补零）。
func (s *Store) TrafficBuckets(ctx context.Context, endpointID uuid.UUID, from, to time.Time) (map[time.Time]int64, error) {
	rows, err := s.db.Query(ctx, `
SELECT bucket_start, request_count FROM api_endpoint_traffic_buckets
WHERE endpoint_id = $1 AND bucket_start >= $2 AND bucket_start < $3
ORDER BY bucket_start`, endpointID, TrafficBucketStart(from), to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[time.Time]int64{}
	for rows.Next() {
		var b time.Time
		var c int64
		if err := rows.Scan(&b, &c); err != nil {
			return nil, err
		}
		out[TrafficBucketStart(b)] = c
	}
	return out, rows.Err()
}
