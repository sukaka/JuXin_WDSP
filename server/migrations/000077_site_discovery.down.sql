-- 000077 回滚：删除站点发现权限点与角色映射，drop site_asset_discoveries 表
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('site_discovery.read','site_discovery.manage')
);
DELETE FROM permissions WHERE code IN ('site_discovery.read','site_discovery.manage');

DROP TABLE IF EXISTS site_asset_discoveries;

COMMIT;
