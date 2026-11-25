-- 回滚 000241：移除 events.read 权限种子、tls_handshake_events 表及 access_logs 加密会话分析扩展列
BEGIN;

DELETE FROM role_permissions
WHERE permission_id IN (SELECT id FROM permissions WHERE code = 'events.read');

DELETE FROM permissions WHERE code = 'events.read';

DROP TABLE IF EXISTS tls_handshake_events;

ALTER TABLE access_logs
    DROP COLUMN IF EXISTS client_hello_version,
    DROP COLUMN IF EXISTS tls_ja3,
    DROP COLUMN IF EXISTS tls_is_gm,
    DROP COLUMN IF EXISTS tls_cipher_suite,
    DROP COLUMN IF EXISTS tls_protocol;

COMMIT;
