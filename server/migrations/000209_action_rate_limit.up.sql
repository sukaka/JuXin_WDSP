-- 000209：按操作动作每分钟限速；空串或 0 不启用，正数随发布下发并加载真实 ACTION 映射。
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('gateway_runtime', 'action_rate_per_minute', '""', 'string', FALSE, '同一操作动作每分钟请求上限（留空或 0 不启用；启用后随发布加载接口 ACTION 分类映射）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
