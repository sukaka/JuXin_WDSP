BEGIN;

ALTER TABLE behavior_statistics
  DROP COLUMN IF EXISTS window_ended_at,
  DROP COLUMN IF EXISTS account_enum_count,
  DROP COLUMN IF EXISTS object_enum_count;

ALTER TABLE client_identity
  DROP CONSTRAINT IF EXISTS client_identity_identity_type_valid,
  DROP CONSTRAINT IF EXISTS client_identity_identity_confidence_range,
  DROP COLUMN IF EXISTS confidence_source,
  DROP COLUMN IF EXISTS identity_confidence;

COMMIT;
