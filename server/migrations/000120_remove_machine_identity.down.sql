-- Keep the V1.1 identity contract on rollback as well; MACHINE is a supported
-- identity type and no data rewrite is required.
BEGIN;

ALTER TABLE client_identity
  DROP CONSTRAINT IF EXISTS client_identity_identity_type_valid;
ALTER TABLE client_identity
  ADD CONSTRAINT client_identity_identity_type_valid
  CHECK (identity_type IN ('HUMAN','BOT','APPLICATION','SERVICE','MACHINE','AGENT','UNKNOWN'));

COMMIT;
