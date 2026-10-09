-- 000165 站点流量日聚合表（站点流量分析 30 天视图数据源）：
--   access_logs 受 logging.retention_days（默认 7 天）限制，>7 天的站点流量视图
--   改查本表；由 aggregations.RunSiteTrafficDaily 随小时任务重算当天+昨天（UTC 天，
--   ON CONFLICT upsert 幂等），并清理 400 天前的桶。
--   unique_ips 为单日 count(DISTINCT client_ip)，跨天不可加和（接口层 >7 天时
--   summary.unique_ips 返回 null）。
-- access_logs 索引无需新增：(application_id, occurred_at) 已由
--   000088 idx_access_logs_app_occurred 覆盖，(occurred_at) 由 000023 覆盖。
BEGIN;

CREATE TABLE IF NOT EXISTS site_traffic_daily (
    bucket_date       DATE        NOT NULL,           -- UTC 天
    application_id    UUID        NOT NULL REFERENCES applications(id),
    requests          BIGINT      NOT NULL DEFAULT 0,
    bytes_in          BIGINT      NOT NULL DEFAULT 0,
    bytes_out         BIGINT      NOT NULL DEFAULT 0,
    unique_ips        INTEGER     NOT NULL DEFAULT 0, -- 当日去重客户端 IP 数
    blocked_requests  BIGINT      NOT NULL DEFAULT 0, -- waf_action = 'BLOCK'
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_date, application_id)
);

COMMENT ON TABLE site_traffic_daily IS '站点流量日聚合（UTC 天 × 应用）：站点流量分析 >7 天视图的数据源，随小时聚合任务重算当天+昨天';

COMMIT;
