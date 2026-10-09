-- 000175 回滚：移除确认单表（确认单为历史事实，回滚即全表删除——仅迁移回滚场景使用）。
BEGIN;

DROP TABLE IF EXISTS api_authz_enforcement_confirmations;

COMMIT;
