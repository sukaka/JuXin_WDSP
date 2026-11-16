-- 000211：按真实业务分组每分钟限速；空串或 0 不启用，正数随发布加载 000210 分组成员映射。
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('gateway_runtime', 'group_rate_per_minute', '""', 'string', FALSE, '同一业务分组每分钟请求上限（留空或 0 不启用；启用后随发布加载真实接口组成员映射）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
