-- Preserve the V1.1 identity contract. This migration is intentionally
-- idempotent for databases where 000116 has already created the constraint;
-- it must not rewrite MACHINE identities to UNKNOWN.
BEGIN;

ALTER TABLE client_identity
  DROP CONSTRAINT IF EXISTS client_identity_identity_type_valid;
ALTER TABLE client_identity
  ADD CONSTRAINT client_identity_identity_type_valid
  CHECK (identity_type IN ('HUMAN','BOT','APPLICATION','SERVICE','MACHINE','AGENT','UNKNOWN'));

COMMIT;
