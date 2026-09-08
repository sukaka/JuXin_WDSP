-- 回滚 000055_api_security_alerts：删除 system_alerts.silenced_until 静默列。
BEGIN;

ALTER TABLE system_alerts
    DROP COLUMN IF EXISTS silenced_until;

COMMIT;
