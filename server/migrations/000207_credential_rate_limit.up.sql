-- 000207 阶段8 §36：按凭据自然分钟限速；空串或 0 不启用，正数随发布下发。
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('gateway_runtime', 'credential_rate_per_minute', '""', 'string', FALSE, '同一凭据每分钟请求上限（自然分钟窗口；留空或 0 不启用；超限产 ratelimit.credential_rate，PROTECT 映射 429）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
