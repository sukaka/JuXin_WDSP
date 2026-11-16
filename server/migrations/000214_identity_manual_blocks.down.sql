BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code = 'security_identities.block');
DELETE FROM permissions WHERE code = 'security_identities.block';

ALTER TABLE client_identity DROP CONSTRAINT IF EXISTS client_identity_status_check;
ALTER TABLE client_identity
    DROP COLUMN IF EXISTS blocked_reason,
    DROP COLUMN IF EXISTS blocked_by,
    DROP COLUMN IF EXISTS blocked_at,
    DROP COLUMN IF EXISTS unblocked_by,
    DROP COLUMN IF EXISTS unblocked_at;

COMMIT;
