-- 000067 调用边身份计数回滚：去唯一索引、去 identity_count 列。
-- 已按自然键合并的重复行不还原（去重是不可逆的数据收敛，回滚只还原结构）。
BEGIN;

DROP INDEX IF EXISTS uq_api_call_edges_caller_source_target;
ALTER TABLE api_call_edges DROP COLUMN IF EXISTS identity_count;

COMMIT;
