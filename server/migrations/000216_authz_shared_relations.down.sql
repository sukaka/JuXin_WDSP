-- Downgrade refuses to silently reinterpret ANY_OF rows as OWNER: the restored
-- legacy CHECK fails the transaction until complex models are explicitly changed back.
BEGIN;

ALTER TABLE api_object_models
    DROP CONSTRAINT IF EXISTS ck_api_object_models_required_relations;
ALTER TABLE api_object_models
    DROP COLUMN IF EXISTS required_relations;

ALTER TABLE api_object_models
    DROP CONSTRAINT IF EXISTS ck_api_object_models_required_relation;
ALTER TABLE api_object_models
    ADD CONSTRAINT ck_api_object_models_required_relation
    CHECK (required_relation IS NULL OR required_relation IN ('OWNER'));

COMMIT;
