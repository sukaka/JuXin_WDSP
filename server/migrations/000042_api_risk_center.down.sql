-- 000042 回滚：恢复四态词表（OPEN/ACKNOWLEDGED/RESOLVED/FALSE_POSITIVE）。
-- 新词表中旧词表无对应的状态按语义最近值回退（如实记录，非无损）：
--   NEW→OPEN、CONFIRMED/IN_PROGRESS→ACKNOWLEDGED、IGNORED→ACKNOWLEDGED、
--   ARCHIVED→RESOLVED；RESOLVED/FALSE_POSITIVE 同名保留。
BEGIN;

-- 1. 权限点回滚
DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('api_risk.read','api_risk.handle')
);
DELETE FROM permissions WHERE code IN ('api_risk.read','api_risk.handle');

-- 2. 索引回滚
DROP INDEX IF EXISTS idx_api_runtime_findings_subject;
DROP INDEX IF EXISTS idx_api_runtime_findings_status_last_seen;

-- 3. CHECK 与默认值回滚（先放宽约束再改写数据）
ALTER TABLE api_runtime_findings DROP CONSTRAINT IF EXISTS chk_api_runtime_findings_status;
UPDATE api_runtime_findings SET status = 'OPEN' WHERE status = 'NEW';
UPDATE api_runtime_findings SET status = 'ACKNOWLEDGED' WHERE status IN ('CONFIRMED','IN_PROGRESS','IGNORED');
UPDATE api_runtime_findings SET status = 'RESOLVED' WHERE status = 'ARCHIVED';
ALTER TABLE api_runtime_findings ALTER COLUMN status SET DEFAULT 'OPEN';
COMMENT ON COLUMN api_runtime_findings.status IS 'OPEN / ACKNOWLEDGED / RESOLVED / FALSE_POSITIVE';

COMMIT;
