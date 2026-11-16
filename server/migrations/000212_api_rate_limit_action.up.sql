-- 000212：API 限速处置与临时封禁时长；默认与网关行为一致，空值回退网关默认。
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('gateway_runtime', 'api_rate_limit_action', '"RATE_LIMIT"', 'string', FALSE, 'API 限速处置（RATE_LIMIT/BLOCK/TEMP_BLOCK；留空使用网关默认 RATE_LIMIT）'),
('gateway_runtime', 'api_temp_block_seconds', '"60"', 'string', FALSE, 'API 限速 TEMP_BLOCK 秒数（1~86400；留空使用网关默认 60）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
