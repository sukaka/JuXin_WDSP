-- 000034 API 接口流量趋势桶（WDSP 接口访问趋势波形图数据源）。
--
-- 背景：api_runtime_events 只落 notable 记录（含检测明细或动作非 ALLOW），
-- 全量请求计数此前只有 api_endpoints.hit_count 单调总数，无时间维度，
-- 管理端「单个接口访问趋势波形图」无数据源。采集器（apiruntime.Collector）
-- 每条记录都会做端点发现 upsert，能看到全量请求，故在发现成功拿到
-- endpoint_id 后对端点 × 5 分钟桶（UTC 对齐）自增计数。
-- 留存 7 天（趋势查询最长 range=7d），由 aggregations 小时任务清理。
BEGIN;

CREATE TABLE IF NOT EXISTS api_endpoint_traffic_buckets (
    endpoint_id   UUID        NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    bucket_start  TIMESTAMPTZ NOT NULL,           -- 桶起点（UTC，5 分钟对齐）
    request_count BIGINT      NOT NULL DEFAULT 0,
    PRIMARY KEY (endpoint_id, bucket_start)
);

COMMIT;
