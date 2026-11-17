-- 000216: object sharing and the canonical OWNER/SHARED_WITH ANY_OF model pair.
-- Existing rows keep required_relations=NULL; no delegation or tenant hierarchy is introduced.
BEGIN;

ALTER TABLE api_object_models
    ADD COLUMN IF NOT EXISTS required_relations TEXT[];

ALTER TABLE api_object_models
    DROP CONSTRAINT IF EXISTS ck_api_object_models_required_relation;
ALTER TABLE api_object_models
    ADD CONSTRAINT ck_api_object_models_required_relation
    CHECK (required_relation IS NULL OR required_relation IN ('OWNER', 'ANY_OF'));

ALTER TABLE api_object_models
    DROP CONSTRAINT IF EXISTS ck_api_object_models_required_relations;
ALTER TABLE api_object_models
    ADD CONSTRAINT ck_api_object_models_required_relations
    CHECK (
        (required_relation IS NULL AND required_relations IS NULL)
        OR (
            required_relation IS NOT NULL AND required_relation = 'OWNER'
            AND (required_relations IS NULL OR required_relations = '{}'::TEXT[])
        )
        OR (
            required_relation IS NOT NULL AND required_relation = 'ANY_OF'
            AND required_relations IS NOT NULL
            AND required_relations = ARRAY['OWNER', 'SHARED_WITH']::TEXT[]
        )
    );

COMMENT ON COLUMN api_object_models.required_relations IS 'ANY_OF 的规范化关系数组；本切片恰为 [OWNER,SHARED_WITH]，OWNER/未声明模型保持 NULL';

COMMIT;
