-- 回滚 000052：删除 applications.deployment_mode 列及其 CHECK 约束。
BEGIN;

ALTER TABLE applications DROP CONSTRAINT IF EXISTS chk_applications_deployment_mode;
ALTER TABLE applications DROP COLUMN IF EXISTS deployment_mode;

COMMIT;
