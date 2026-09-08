-- 000039 回滚：删除 API 弱点中心两表（先删依赖方）。
BEGIN;

DROP TABLE IF EXISTS api_weakness_actions;
DROP TABLE IF EXISTS api_weaknesses;

COMMIT;
