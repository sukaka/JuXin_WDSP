-- 回滚 000190：API 网络暴露面判定引擎三表 + exposure_engine 设置种子（幂等）。
BEGIN;

DROP TABLE IF EXISTS api_exposure_assessments;
DROP TABLE IF EXISTS api_endpoint_source_seen;
DROP TABLE IF EXISTS api_endpoint_source_buckets;

DELETE FROM system_settings WHERE setting_group = 'exposure_engine';

COMMIT;
