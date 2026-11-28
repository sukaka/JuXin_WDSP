-- 000255 回滚：移除纯离线 WAF 规则包表结构、增量列与权限种子
BEGIN;

DELETE FROM role_permissions
WHERE permission_id IN (
    SELECT id FROM permissions WHERE code = 'waf_rules.pack.manage'
);

DELETE FROM permissions WHERE code = 'waf_rules.pack.manage';

ALTER TABLE gateway_config_versions
    DROP COLUMN IF EXISTS rulepack_version;

DROP INDEX IF EXISTS idx_waf_rules_active_attack;

ALTER TABLE waf_rules
    DROP COLUMN IF EXISTS last_rulepack_version,
    DROP COLUMN IF EXISTS is_active;

DROP TABLE IF EXISTS waf_rule_pack_node_states;
DROP TABLE IF EXISTS waf_rule_pack_jobs;
DROP TABLE IF EXISTS waf_rule_packs;

COMMIT;
