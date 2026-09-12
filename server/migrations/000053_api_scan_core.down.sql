-- 000053 回滚：删除主动扫描核心表（任务 → 授权 → 目标，外键依赖逆序）。
BEGIN;

DROP TABLE IF EXISTS api_scan_jobs;
DROP TABLE IF EXISTS api_scan_authorizations;
DROP TABLE IF EXISTS api_scan_targets;

COMMIT;
