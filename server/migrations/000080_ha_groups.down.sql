-- 000080 回滚：删除 ha_groups / ha_group_members 与 ha.* 权限点。
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
    SELECT id FROM permissions WHERE code IN ('ha.read','ha.manage'));
DELETE FROM permissions WHERE code IN ('ha.read','ha.manage');

DROP TABLE IF EXISTS ha_group_members;
DROP TABLE IF EXISTS ha_groups;

COMMIT;
