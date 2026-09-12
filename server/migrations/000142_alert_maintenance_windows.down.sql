-- 回滚 000142_alert_maintenance_windows：删除告警维护窗口表。
BEGIN;

DROP TABLE IF EXISTS system_alert_maintenance_windows;

COMMIT;
