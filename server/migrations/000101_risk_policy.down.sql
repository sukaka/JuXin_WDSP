-- 000101 回滚：删除 security_risk_policy 表与 access_control_events.details 列
BEGIN;

DROP TABLE IF EXISTS security_risk_policy;
ALTER TABLE access_control_events DROP COLUMN IF EXISTS details;

COMMIT;
