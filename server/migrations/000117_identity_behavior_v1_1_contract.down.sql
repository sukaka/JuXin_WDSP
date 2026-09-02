BEGIN;

ALTER TABLE identity_behavior_events
    DROP CONSTRAINT IF EXISTS identity_behavior_events_identity_confidence_check;
ALTER TABLE identity_behavior_events
    DROP COLUMN IF EXISTS identity_confidence,
    DROP COLUMN IF EXISTS identity_evidence;

ALTER TABLE security_behavior_policy
    DROP COLUMN IF EXISTS account_enum_threshold,
    DROP COLUMN IF EXISTS object_enum_threshold,
    DROP COLUMN IF EXISTS account_identifier_fields,
    DROP COLUMN IF EXISTS object_identifier_fields;

COMMIT;
