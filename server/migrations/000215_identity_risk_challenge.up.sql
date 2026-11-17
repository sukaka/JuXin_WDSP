-- 000215 身份风险 CHALLENGE 阈值；0 保持关闭，启用时必须位于限速与阻断阈值之间。
BEGIN;

ALTER TABLE security_risk_policy
    ADD COLUMN IF NOT EXISTS challenge_threshold INTEGER NOT NULL DEFAULT 0;
ALTER TABLE security_risk_policy_overrides
    ADD COLUMN IF NOT EXISTS challenge_threshold INTEGER NOT NULL DEFAULT 0;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_risk_policy_challenge_threshold'
          AND conrelid = 'security_risk_policy'::regclass
    ) THEN
        ALTER TABLE security_risk_policy
            ADD CONSTRAINT chk_risk_policy_challenge_threshold
            CHECK (challenge_threshold = 0 OR (
                challenge_threshold BETWEEN 1 AND 100
                AND rate_limit_threshold < challenge_threshold
                AND challenge_threshold < block_threshold
            ));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_risk_override_challenge_threshold'
          AND conrelid = 'security_risk_policy_overrides'::regclass
    ) THEN
        ALTER TABLE security_risk_policy_overrides
            ADD CONSTRAINT chk_risk_override_challenge_threshold
            CHECK (challenge_threshold = 0 OR (
                challenge_threshold BETWEEN 1 AND 100
                AND rate_limit_threshold < challenge_threshold
                AND challenge_threshold < block_threshold
            ));
    END IF;
END $$;

COMMENT ON COLUMN security_risk_policy.challenge_threshold IS
    '身份风险挑战阈值；0=关闭，1-100 启用且必须大于限速阈值、小于阻断阈值';
COMMENT ON COLUMN security_risk_policy_overrides.challenge_threshold IS
    '按应用身份风险挑战阈值；0=关闭，1-100 启用且必须大于限速阈值、小于阻断阈值';

COMMIT;
