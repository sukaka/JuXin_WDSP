BEGIN;

ALTER TABLE ai_model_providers
    DROP COLUMN IF EXISTS allowed_targets,
    DROP COLUMN IF EXISTS canonical_origin;

COMMIT;
