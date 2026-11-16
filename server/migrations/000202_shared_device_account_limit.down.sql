BEGIN;

ALTER TABLE security_risk_policy_overrides
    DROP CONSTRAINT IF EXISTS chk_risk_override_shared_device_limit,
    DROP COLUMN IF EXISTS shared_device_account_limit;

COMMIT;
