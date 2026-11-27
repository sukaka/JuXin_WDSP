-- 000252 回滚：移除 waf_rules.raw_rule 列。
BEGIN;

ALTER TABLE waf_rules
    DROP COLUMN IF EXISTS raw_rule;

COMMIT;
