-- 000208：可信租户每分钟限速；空串或 0 不启用，正数随发布下发。
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('gateway_runtime', 'tenant_rate_per_minute', '""', 'string', FALSE, '同一可信租户每分钟请求上限（留空或 0 不启用；保存后需发布配置）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
