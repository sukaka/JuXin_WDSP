-- 000094 回滚：删除 apm_alert.ingest_lag_seconds 设置种子
-- （仅删种子行；消费侧带默认值读取，删键后回退默认 300 秒，不影响引擎行为）
BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'apm_alert' AND setting_key = 'ingest_lag_seconds';

COMMIT;
