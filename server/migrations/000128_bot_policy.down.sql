-- 000128 回滚：删除 Bot 策略表。
-- 注意：bot_policy_versions 为不可变版本记录，回滚迁移会删除用户配置历史；
-- 数据库降级前须先导出策略版本（不含敏感信息），本脚本不自动导出。
BEGIN;

DROP TABLE IF EXISTS bot_policy_versions;
DROP TABLE IF EXISTS bot_policies;

COMMIT;
