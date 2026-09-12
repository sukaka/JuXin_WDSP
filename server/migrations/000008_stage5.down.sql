-- 阶段5 回滚：删除访问控制与CC防护相关表

BEGIN;

DROP TABLE IF EXISTS rate_limit_runtime_summaries CASCADE;
DROP TABLE IF EXISTS access_control_versions CASCADE;
DROP TABLE IF EXISTS access_control_events CASCADE;
DROP TABLE IF EXISTS temporary_blocks CASCADE;
DROP TABLE IF EXISTS rate_limit_policies CASCADE;
DROP TABLE IF EXISTS ip_access_rules CASCADE;
DROP TABLE IF EXISTS protected_addresses CASCADE;
DROP TABLE IF EXISTS trusted_proxies CASCADE;

COMMIT;
