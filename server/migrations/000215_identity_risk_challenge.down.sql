BEGIN;

ALTER TABLE security_risk_policy
    DROP CONSTRAINT IF EXISTS chk_risk_policy_challenge_threshold,
    DROP COLUMN IF EXISTS challenge_threshold;
ALTER TABLE security_risk_policy_overrides
    DROP CONSTRAINT IF EXISTS chk_risk_override_challenge_threshold,
    DROP COLUMN IF EXISTS challenge_threshold;

COMMIT;
