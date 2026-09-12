-- 000154 回滚：relation_type 词表 CHECK 恢复 000147 九值口径。
-- 注意：若已存在 NOT_EQUALS 关系行，恢复旧 CHECK 会失败，需先清理这些行再回滚。
BEGIN;

ALTER TABLE api_parameter_relations
    DROP CONSTRAINT IF EXISTS chk_api_parameter_relations_type;

ALTER TABLE api_parameter_relations
    ADD CONSTRAINT chk_api_parameter_relations_type
    CHECK (relation_type IN ('REQUIRES', 'EXCLUDES', 'MUTEX', 'CO_OCCURS',
                             'EQUALS', 'GREATER_THAN', 'LESS_THAN', 'TIME_BEFORE', 'TIME_AFTER'));

COMMIT;
