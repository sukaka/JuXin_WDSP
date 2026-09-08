-- 000094 APM 数据面容量/健康告警：apm_alert 组采集滞后阈值种子
-- （设计 docs/BUSINESS_PERFORMANCE_APM_DESIGN.md §18.1 数据质量 / §20「ClickHouse 不可用 →
--   存储不可用/采集滞后」）。
--
--   apm_alert.ingest_lag_seconds：systemalerts/ingest_lag.go 消费（ClickHouse
--   otel_traces 最新遥测距当前时间超该值触发 APM_INGEST_LAG，MEDIUM，
--   component=clickhouse）；消费侧带默认值读取（300 秒）与区间校验 [30,86400]，
--   非法值回退默认；接口修改白名单登记于 settings.AllowedSettingKeys。
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('apm_alert', 'ingest_lag_seconds', '300', 'integer', FALSE, 'APM数据面采集滞后告警阈值（秒）：ClickHouse otel_traces最新遥测距当前时间超该值触发APM_INGEST_LAG')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
