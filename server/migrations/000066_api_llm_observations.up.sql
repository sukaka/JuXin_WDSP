-- 000066 LLM API 观测（W10-LLM / P2-04 首批，任务书 §152-154）：
-- 网关 llm_observation（OpenAI 兼容/MCP 形态识别后的数据最小化观测）落地表。
--
-- 编号说明：000065 已由同波另一分片占用（000065_node_network_configs，
-- 迁移执行器按整数版本号唯一存储，同号两文件会互相覆盖），本分片顺延 000066。
--
-- 语义边界：
--   生产方为 apillm.ObsStore.RecordLLMObservation：消费网关统一主事件
--   llm_observation（model/prompt 存在性/体量桶/token 用量/流式标记）+
--   details 中 llm.* 明细（findings 口径），每请求至多一行。
--
-- 数据最小化纪律（任务书：高敏感 Prompt/Response 不落原文）：
--   model                模型标识（截断 128；空串 = 未声明/未采集到）；
--   prompt_len_bucket    prompt 体量桶（XS/S/M/L/XL，由请求体大小推导的近似口径；
--                        不逐字统计原文长度）；
--   findings             llm.* 检测明细（Prompt Injection 词表命中/未授权模型；
--                        证据只含规则名/消息序号/角色/模型名，不落原文）；
--   全表无 prompt/response 原文列。
--
-- 幂等设计：id 由采集端按 request_id 确定性派生（sha256 截断置版本位 UUID），
-- ON CONFLICT (id) DO NOTHING——采集重放/断点回退不产生重复行；
-- request_id 缺失时退化随机 UUID（防御路径，正常事件必带 request_id）。
BEGIN;

CREATE TABLE IF NOT EXISTS api_llm_observations (
    id                   UUID PRIMARY KEY,
    occurred_at          TIMESTAMPTZ  NOT NULL,
    endpoint_key         VARCHAR(560) NOT NULL DEFAULT '',
    model                VARCHAR(128) NOT NULL DEFAULT '',
    identity_fingerprint VARCHAR(128) NOT NULL DEFAULT '', -- 匿名流量为空串（口径同 api_runtime_events）
    prompt_len_bucket    VARCHAR(16)  NOT NULL DEFAULT '',
    total_tokens         INTEGER      NOT NULL DEFAULT 0,  -- 0 = 流式/缺失未采集到（缺失容忍口径）
    stream               BOOLEAN      NOT NULL DEFAULT false,
    findings             JSONB        NOT NULL DEFAULT '[]',
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_llm_observations_occurred
    ON api_llm_observations (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_llm_observations_model
    ON api_llm_observations (model, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_llm_observations_endpoint
    ON api_llm_observations (endpoint_key, occurred_at DESC);
-- 涉敏/异常命中口径：findings 非空（部分索引避免全表扫）
CREATE INDEX IF NOT EXISTS idx_api_llm_observations_findings
    ON api_llm_observations (occurred_at DESC) WHERE findings <> '[]'::jsonb;

COMMENT ON TABLE api_llm_observations IS
    'LLM API 观测（P2-04）：模型/prompt 存在性/体量桶/token 用量/流式标记 + llm.* 命中，数据最小化不落原文';

COMMIT;
