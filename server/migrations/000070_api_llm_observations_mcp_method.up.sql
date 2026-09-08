-- 000070 LLM 观测扩展 MCP 方法列（W12-GW / P2-04 续，任务书 §154）：
-- api_llm_observations（迁移 000066 建立）加 mcp_method 列——MCP JSON-RPC 方法名
-- （tools/call、resources/read 等；截断 128；空串 = 非 MCP 端点或 JSON-RPC 响应对象），
-- 供 MCP 调用面观测与异常调用（词表外方法/敏感参数）归属。
--
-- 语义边界：生产方仍为 apillm.ObsStore.RecordLLMObservation（消费网关统一主事件
-- llm_observation.mcp_method，每请求至多一行）；词表外方法同样如实记录（观测口径）。
-- 数据最小化纪律不变：方法名为协议标识符，全表仍无 Prompt/Response 原文列。
--
-- 迁移内容仅加列（带默认值，存量行回填空串），无设置种子、无数据改写。
BEGIN;

ALTER TABLE api_llm_observations
    ADD COLUMN IF NOT EXISTS mcp_method VARCHAR(128) NOT NULL DEFAULT '';

COMMENT ON COLUMN api_llm_observations.mcp_method IS
    'MCP JSON-RPC 方法名（W12-GW；空串 = 非 MCP 端点或响应对象；词表外方法如实记录）';

COMMIT;
