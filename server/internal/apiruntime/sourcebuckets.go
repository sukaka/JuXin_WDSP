// sourcebuckets.go 暴露面来源聚合挂点（WDSP 暴露面判定引擎，迁移 000190）。
// Collector 每条记录端点发现 upsert 成功拿到 endpoint_id 后，对
// (endpoint_id, 自然日, 内网/公网/合作方范围) 计数并登记盐化来源指纹——采集器
// 能看到全量请求（api_runtime_events 只落 notable），来源桶是全量口径。
// 接口定义在本包（避免 apiexposure ↔ apiruntime 循环依赖），apiexposure.SourceRecorder
// 实现由装配层注入；nil 时零开销跳过；写失败只记日志不中断采集（与流量桶同一纪律）。
// partner CIDR 分类在 apiexposure 侧完成（读 settings 缓存），采集器不感知 settings。
package apiruntime

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

// SourceRecorder 暴露面来源聚合写入接口（apiexposure.SourceRecorder 实现，可为 nil）。
type SourceRecorder interface {
	RecordSource(ctx context.Context, endpointID uuid.UUID, clientIP, fingerprint string, ts time.Time) error
}

// SetSourceRecorder 设置暴露面来源聚合写入（应用装配时使用；未设置时跳过）。
func (c *Collector) SetSourceRecorder(r SourceRecorder) { c.sourceRec = r }

// recordSourceBucket 端点发现成功后的来源聚合（错误仅记录日志，不影响采集主流程，
// 与端点发现/流量桶同一纪律）。client_ip 为空（旧版网关未上报）时跳过；
// occurred_at 缺失（零值）时回落采集时刻。
func (c *Collector) recordSourceBucket(ctx context.Context, rec *Record, ep *apiassets.Endpoint) {
	if c.sourceRec == nil || ep == nil || rec.ClientIP == "" {
		return
	}
	at := rec.OccurredAt
	if at.IsZero() {
		at = time.Now()
	}
	if err := c.sourceRec.RecordSource(ctx, ep.ID, rec.ClientIP, rec.SourceFingerprint, at); err != nil {
		slog.Error("record exposure source bucket failed",
			"collector", c.collectorID, "endpoint_key", rec.EndpointKey, "error", err)
	}
}
