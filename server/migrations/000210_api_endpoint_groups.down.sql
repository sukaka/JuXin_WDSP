BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
    SELECT id FROM permissions
    WHERE code IN ('api_endpoint_group.read', 'api_endpoint_group.manage')
);
DELETE FROM permissions
WHERE code IN ('api_endpoint_group.read', 'api_endpoint_group.manage');

DROP TABLE IF EXISTS api_endpoint_group_members;
DROP TABLE IF EXISTS api_endpoint_groups;

COMMIT;
