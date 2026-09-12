// traffic.go 接口流量趋势桶计数挂点（WDSP 接口访问趋势波形图，迁移 000034）。
// Collector 每条记录端点发现 upsert 成功拿到 endpoint_id 后，对
// (endpoint_id, 5 分钟 UTC 桶) 自增计数——采集器能看到全量请求
// （api_runtime_events 只落 notable），流量桶是全量口径。
// 未注入 recorder（nil）时零开销跳过；写失败只记日志不中断采集。
package apiruntime

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

// TrafficRecorder 流量趋势桶计数接口（*apiassets.Store 实现，可为 nil）。
type TrafficRecorder interface {
	RecordTrafficBucket(ctx context.Context, endpointID uuid.UUID, bucketStart time.Time) error
}

// recordTrafficBucket 端点发现成功后的流量桶自增（错误仅记录日志，不影响采集主流程，
// 与端点发现/样本落库同一纪律）。occurred_at 缺失（零值）时回落采集时刻。
func (c *Collector) recordTrafficBucket(ctx context.Context, rec *Record, ep *apiassets.Endpoint) {
	if c.traffic == nil || ep == nil {
		return
	}
	at := rec.OccurredAt
	if at.IsZero() {
		at = time.Now()
	}
	if err := c.traffic.RecordTrafficBucket(ctx, ep.ID, apiassets.TrafficBucketStart(at)); err != nil {
		slog.Error("record traffic bucket failed",
			"collector", c.collectorID, "endpoint_key", rec.EndpointKey, "error", err)
	}
}
