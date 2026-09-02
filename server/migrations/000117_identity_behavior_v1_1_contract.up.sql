BEGIN;

ALTER TABLE security_behavior_policy
    ADD COLUMN IF NOT EXISTS account_enum_threshold INT NOT NULL DEFAULT 20,
    ADD COLUMN IF NOT EXISTS object_enum_threshold INT NOT NULL DEFAULT 20,
    ADD COLUMN IF NOT EXISTS account_identifier_fields JSONB NOT NULL DEFAULT '["account","account_id","username","user_id","email"]'::jsonb,
    ADD COLUMN IF NOT EXISTS object_identifier_fields JSONB NOT NULL DEFAULT '["object_id","resource_id","record_id"]'::jsonb;

ALTER TABLE identity_behavior_events
    ADD COLUMN IF NOT EXISTS identity_confidence SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS identity_evidence JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE identity_behavior_events
    DROP CONSTRAINT IF EXISTS identity_behavior_events_identity_confidence_check;
ALTER TABLE identity_behavior_events
    ADD CONSTRAINT identity_behavior_events_identity_confidence_check
    CHECK (identity_confidence BETWEEN 0 AND 100);

COMMIT;
