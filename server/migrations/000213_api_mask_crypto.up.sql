-- 000213：ENCRYPT/MAP 脱敏算法及运行时加密密钥设置（密钥值为密文）。
BEGIN;

ALTER TABLE api_masking_rules DROP CONSTRAINT IF EXISTS api_masking_rules_algorithm_check;
ALTER TABLE api_masking_rules
    ADD CONSTRAINT api_masking_rules_algorithm_check
    CHECK (algorithm IN ('MASK','HASH','REMOVE','ENCRYPT','MAP'));

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('gateway_runtime', 'api_mask_encryption_kid', '""', 'string', FALSE, '脱敏加密密钥标识（enc_<kid>_<base64> 中的 kid）'),
('gateway_runtime', 'api_mask_encryption_key', '""', 'string', TRUE, '脱敏加密密钥（密文；解密后为 32 字节 hex）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
