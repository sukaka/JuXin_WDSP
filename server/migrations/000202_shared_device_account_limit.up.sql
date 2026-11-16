-- 000202 按应用配置同设备可信账号群控观察阈值；0 保持引擎默认值 3。
BEGIN;

ALTER TABLE security_risk_policy_overrides
    ADD COLUMN IF NOT EXISTS shared_device_account_limit INTEGER NOT NULL DEFAULT 0;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_risk_override_shared_device_limit'
          AND conrelid = 'security_risk_policy_overrides'::regclass
    ) THEN
        ALTER TABLE security_risk_policy_overrides
            ADD CONSTRAINT chk_risk_override_shared_device_limit
            CHECK (shared_device_account_limit = 0 OR shared_device_account_limit BETWEEN 2 AND 1000);
    END IF;
END $$;

COMMENT ON COLUMN security_risk_policy_overrides.shared_device_account_limit IS
    '同应用同被动设备指纹的可信账号观察阈值；0=默认3，自定义2-1000，仅影响 OBSERVE 信号';

COMMIT;
