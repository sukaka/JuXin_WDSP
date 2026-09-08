-- 000084 种子：reports.delete_all 权限点（删除任意用户创建的报告）。
-- 背景：报表删除原为「仅本人」（reports.delete_own，000011）；安全管理员作为报表域
-- 最高权限角色，需要可清理任意用户报告的管理能力（与下载侧 reports.download_audit
-- 的「本人或特许权限」升级模式一致，此处升级为 delete_all）。
-- 授予范围：仅 SECURITY_ADMIN（报表域归安全管理员，见 000011；SYSTEM_ADMIN/AUDIT_ADMIN 不授）。

BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('reports.delete_all', '删除全部报告', 'reports', '删除任意用户创建的报告（管理）')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('reports.delete_all')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
