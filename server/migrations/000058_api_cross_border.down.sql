-- 000058 API 数据出境基础回滚： drop 观察事件表与水位状态表，移除本土地区设置种子。
BEGIN;

DROP TABLE IF EXISTS api_cross_border_events;
DROP TABLE IF EXISTS api_cross_border_state;

DELETE FROM system_settings
WHERE setting_group = 'api_data' AND setting_key = 'home_regions';

COMMIT;
