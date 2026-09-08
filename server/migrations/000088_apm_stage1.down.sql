-- 000088 回滚：删除 APM 权限种子、新增索引与 access_logs 新列
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('apm.overview.read', 'apm.services.read', 'apm.traces.read')
);
DELETE FROM permissions WHERE code IN ('apm.overview.read', 'apm.services.read', 'apm.traces.read');

DROP INDEX IF EXISTS idx_access_logs_trace_id;
DROP INDEX IF EXISTS idx_access_logs_app_occurred;

ALTER TABLE access_logs
    DROP COLUMN IF EXISTS trace_id,
    DROP COLUMN IF EXISTS span_id,
    DROP COLUMN IF EXISTS endpoint_key,
    DROP COLUMN IF EXISTS path_template,
    DROP COLUMN IF EXISTS ttfb_ms;

COMMIT;
