-- 000144 回滚：移除 access_logs / access_control_events 的真实 IP 识别日志三列
-- （采集端缺失容忍，回滚不影响既有数据读写；网关新字段在旧表上无落点，仅不持久化）。
BEGIN;

ALTER TABLE access_logs
    DROP COLUMN IF EXISTS client_ip_source,
    DROP COLUMN IF EXISTS trusted_proxy_used,
    DROP COLUMN IF EXISTS forwarded_chain_summary;

ALTER TABLE access_control_events
    DROP COLUMN IF EXISTS client_ip_source,
    DROP COLUMN IF EXISTS trusted_proxy_used,
    DROP COLUMN IF EXISTS forwarded_chain_summary;

COMMIT;
