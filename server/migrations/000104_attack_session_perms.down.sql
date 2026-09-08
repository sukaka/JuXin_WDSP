-- 000104 down：回收攻击活动会话权限点（先删角色授权，再删权限）。
BEGIN;

DELETE FROM role_permissions
WHERE permission_id IN (SELECT id FROM permissions WHERE code = 'attack_sessions.read');

DELETE FROM permissions WHERE code = 'attack_sessions.read';

COMMIT;
