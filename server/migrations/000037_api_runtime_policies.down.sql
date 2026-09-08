-- 000037 回滚：API 端点级运行时策略版本表 + 索引
BEGIN;

DROP TABLE IF EXISTS api_runtime_policies;

COMMIT;
