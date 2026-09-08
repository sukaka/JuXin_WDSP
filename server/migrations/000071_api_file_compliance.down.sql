-- 000071 回滚：drop 文件合规规则表，移除签名有效期设置种子。
-- 注意：gateway_runtime.api_file_signature_key / *_kid 为运行期由轮换接口写入，
-- 不属于本迁移种子，回滚不清理（密钥材料生命周期由轮换接口管理）。
BEGIN;

DROP TABLE IF EXISTS api_file_compliance_rules;

DELETE FROM system_settings
WHERE setting_group = 'api_data' AND setting_key = 'file_signature_max_age_days';

COMMIT;
