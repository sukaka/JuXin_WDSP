-- 回滚漏洞情报提醒（VULN_INTEL MVP）：清除权限种子与本功能四张表。
-- 只删除 vuln_intel.* 权限与其授权，不触碰其他迁移的表与权限。

BEGIN;

DELETE FROM role_permissions
WHERE permission_id IN (SELECT id FROM permissions WHERE code IN ('vuln_intel.read','vuln_intel.manage'));

DELETE FROM permissions WHERE code IN ('vuln_intel.read','vuln_intel.manage');

DROP TABLE IF EXISTS vuln_alerted;
DROP TABLE IF EXISTS application_technologies;
DROP TABLE IF EXISTS vuln_intel_sync_state;
DROP TABLE IF EXISTS vuln_advisories;

COMMIT;
