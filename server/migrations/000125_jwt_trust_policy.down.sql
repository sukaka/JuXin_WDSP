-- 000125 回滚：删除 JWT 信任策略表与 remote_jwks_allowlist 设置种子。
-- 注意：jwt_trust_policy_versions 为不可变版本记录，回滚迁移会删除用户配置历史；
-- 按任务书 §11，数据库降级前须先导出策略版本（不含敏感信息），本脚本不自动导出。
BEGIN;

DROP TABLE IF EXISTS jwt_trust_policy_versions;
DROP TABLE IF EXISTS jwt_trust_policies;
DELETE FROM system_settings
WHERE setting_group = 'jwt_trust' AND setting_key = 'remote_jwks_allowlist';

COMMIT;
