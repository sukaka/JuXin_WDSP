-- 000214 client_identity 手工封禁/解封与最小权限。
BEGIN;

ALTER TABLE client_identity
    ADD COLUMN IF NOT EXISTS blocked_reason TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS blocked_by UUID,
    ADD COLUMN IF NOT EXISTS blocked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS unblocked_by UUID,
    ADD COLUMN IF NOT EXISTS unblocked_at TIMESTAMPTZ;

ALTER TABLE client_identity DROP CONSTRAINT IF EXISTS client_identity_status_check;
ALTER TABLE client_identity
    ADD CONSTRAINT client_identity_status_check CHECK (status IN ('NORMAL','BLOCKED'));

INSERT INTO permissions (code, name, module, description) VALUES
('security_identities.block', '封禁和解封客户身份', 'security', '手工封禁或解封客户身份并触发整站发布')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code IN ('SYSTEM_ADMIN','SECURITY_ADMIN') AND p.code = 'security_identities.block'
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
