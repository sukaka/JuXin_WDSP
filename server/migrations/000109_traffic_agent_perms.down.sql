-- 000109 回滚：删除流量采集 Agent 2 个权限点及其角色关联
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('traffic.agents.view', 'traffic.agents.manage')
);
DELETE FROM permissions WHERE code IN ('traffic.agents.view', 'traffic.agents.manage');

COMMIT;
