-- 000226 回滚：移除 waf_rule_descriptions 表与 waf_rules.parsed_spec 列。
BEGIN;

DROP TABLE IF EXISTS waf_rule_descriptions;

ALTER TABLE waf_rules
    DROP COLUMN IF EXISTS parsed_spec;

COMMIT;
