-- 回滚 000156：移除已吊销凭据清单表与 api_credential.* 权限点。
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
    SELECT id FROM permissions WHERE code IN ('api_credential.read', 'api_credential.manage')
);
DELETE FROM permissions WHERE code IN ('api_credential.read', 'api_credential.manage');

DROP TABLE IF EXISTS api_revoked_credentials;

COMMIT;
