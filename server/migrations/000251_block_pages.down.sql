-- 000251 回滚：移除自定义拦截页面表结构与权限种子
BEGIN;

DELETE FROM role_permissions
WHERE permission_id IN (
    SELECT id FROM permissions WHERE code IN ('block_pages.read', 'block_pages.manage')
);

DELETE FROM permissions WHERE code IN ('block_pages.read', 'block_pages.manage');

DROP TABLE IF EXISTS block_page_bindings;
DROP TABLE IF EXISTS block_page_versions;
DROP TABLE IF EXISTS block_pages;

COMMIT;
