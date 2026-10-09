-- 000167 回滚：移除 CNNVD 兼容字段、vuln_refs 表与权限种子。
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('waf_rule.vuln_ref.edit')
);
DELETE FROM permissions WHERE code IN ('waf_rule.vuln_ref.edit');

DROP TABLE IF EXISTS vuln_refs;

DROP INDEX IF EXISTS idx_waf_rules_cve_ids;
DROP INDEX IF EXISTS idx_waf_rules_cnnvd_ids;
DROP INDEX IF EXISTS idx_custom_rules_cve_ids;
DROP INDEX IF EXISTS idx_custom_rules_cnnvd_ids;

ALTER TABLE waf_rules    DROP COLUMN IF EXISTS cve_ids;
ALTER TABLE waf_rules    DROP COLUMN IF EXISTS cnnvd_ids;
ALTER TABLE custom_rules DROP COLUMN IF EXISTS cve_ids;
ALTER TABLE custom_rules DROP COLUMN IF EXISTS cnnvd_ids;

COMMIT;
