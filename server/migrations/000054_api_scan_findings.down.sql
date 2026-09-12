-- 000054 回滚：删除主动扫描发现表。
BEGIN;

DROP TABLE IF EXISTS api_scan_findings;

COMMIT;
