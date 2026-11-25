-- 回滚 000239：移除域名级 WAF 防护策略字段
BEGIN;

DROP INDEX IF EXISTS idx_app_domains_policy;
ALTER TABLE application_domains DROP COLUMN IF EXISTS policy_id;

COMMIT;
