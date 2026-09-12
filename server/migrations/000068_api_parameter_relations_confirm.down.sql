-- 000068 回滚：移除参数条件关系确认列与词表 CHECK。
BEGIN;

DROP INDEX IF EXISTS idx_api_parameter_relations_confirmed;

ALTER TABLE api_parameter_relations
    DROP CONSTRAINT IF EXISTS chk_api_parameter_relations_type;

ALTER TABLE api_parameter_relations
    DROP COLUMN IF EXISTS confirmed,
    DROP COLUMN IF EXISTS confirmed_by,
    DROP COLUMN IF EXISTS confirmed_at;

COMMIT;
