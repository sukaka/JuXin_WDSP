-- 回滚 000046：移除 api_spec.manage 权限点与 api_import_specs 版本状态机列。
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
    SELECT id FROM permissions WHERE code = 'api_spec.manage'
);
DELETE FROM permissions WHERE code = 'api_spec.manage';

DROP INDEX IF EXISTS idx_api_import_specs_status;
DROP INDEX IF EXISTS idx_api_import_specs_active_name;
DROP INDEX IF EXISTS idx_api_import_specs_name_version;

ALTER TABLE api_import_specs DROP CONSTRAINT IF EXISTS chk_api_import_specs_status;
ALTER TABLE api_import_specs
    DROP COLUMN IF EXISTS activated_at,
    DROP COLUMN IF EXISTS parent_id,
    DROP COLUMN IF EXISTS status,
    DROP COLUMN IF EXISTS version_no,
    DROP COLUMN IF EXISTS name;

COMMIT;
