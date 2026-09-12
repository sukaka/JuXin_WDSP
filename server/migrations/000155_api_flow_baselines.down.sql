-- 回滚 000155：移除流程基线表与 api_flow.* 权限点。
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
    SELECT id FROM permissions WHERE code IN ('api_flow.read', 'api_flow.manage')
);
DELETE FROM permissions WHERE code IN ('api_flow.read', 'api_flow.manage');

DROP TABLE IF EXISTS api_flow_baseline_steps;
DROP TABLE IF EXISTS api_flow_baselines;

COMMIT;
