-- 000114 down：删除 Phase 4 定向采集规则表（随表删除其索引）。
BEGIN;

DROP TABLE IF EXISTS agent_capture_overrides;

COMMIT;
