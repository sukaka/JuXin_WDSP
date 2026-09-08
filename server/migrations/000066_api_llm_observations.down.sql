-- 000066 LLM API 观测回滚：drop 观测表（无设置种子，无额外清理）。
BEGIN;

DROP TABLE IF EXISTS api_llm_observations;

COMMIT;
