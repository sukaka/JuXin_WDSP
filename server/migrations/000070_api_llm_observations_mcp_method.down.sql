-- 000070 LLM 观测 MCP 方法列回滚：drop mcp_method 列（无数据迁移，列直接废弃）。
BEGIN;

ALTER TABLE api_llm_observations
    DROP COLUMN IF EXISTS mcp_method;

COMMIT;
