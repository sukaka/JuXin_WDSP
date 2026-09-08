-- 000040 回滚：删除敏感数据管理面两张表与 api_sensitive_fields 新增列。
BEGIN;

DROP TABLE IF EXISTS api_masking_rules;
DROP TABLE IF EXISTS api_sensitive_data_types;
ALTER TABLE api_sensitive_fields
    DROP COLUMN IF EXISTS source_detail,
    DROP COLUMN IF EXISTS occurrence_count,
    DROP COLUMN IF EXISTS last_seen,
    DROP COLUMN IF EXISTS first_seen;
-- 建在既有列上的索引不随列删除，显式回收
DROP INDEX IF EXISTS idx_api_sensitive_fields_data_type;
DROP INDEX IF EXISTS idx_api_sensitive_fields_last_seen;

COMMIT;
