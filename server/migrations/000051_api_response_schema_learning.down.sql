-- 000051 回滚：移除 api_response_schemas 运行时学习列，恢复 model_version_id NOT NULL。
-- 运行时学习行（model_version_id 为空）必须先清除才能恢复约束；版本快照行
-- （model_version_id 关联版本）符合原表语义，保留。
BEGIN;

DELETE FROM api_response_schemas WHERE model_version_id IS NULL;

DROP INDEX IF EXISTS ux_api_response_schemas_runtime;

ALTER TABLE api_response_schemas
    DROP COLUMN IF EXISTS updated_at,
    DROP COLUMN IF EXISTS sample_count,
    DROP COLUMN IF EXISTS last_seen,
    DROP COLUMN IF EXISTS first_seen,
    DROP COLUMN IF EXISTS endpoint_key,
    ALTER COLUMN model_version_id SET NOT NULL;

COMMIT;
