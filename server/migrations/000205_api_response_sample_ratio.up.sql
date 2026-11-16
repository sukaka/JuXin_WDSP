-- 000205 阶段8 §7.2 响应体采样比例设置；既有用户配置保持原值。
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('gateway_runtime', 'api_response_sample_ratio', '"1"', 'string', FALSE,
 '响应体采样比例（0~1）：1=全量解析，0=不解析，(0,1) 仅对超大响应做确定性前缀采样；留空使用网关默认值 1；保存后需发布配置')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
