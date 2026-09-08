-- 000069 API 网关节点版本校验 v1（W12-NODE，任务书 §200-201 遥测路径）。
--
-- 语义边界（如实说明）：这是「经事件遥测的节点版本校验」，不是多节点同步协议。
-- 节点注册/心跳/主动同步/配置推送的全量协议（任务书 §200）为后续工程；
-- 本迁移只支撑从统一主事件流聚合出节点版本视图（api_gateway_nodes）。
--
-- 本迁移两件事：
--   1) api_runtime_events 补 gateway_node 列：任务书背景假定该列已存在，实际
--      采集端镜像 Record.GatewayNode（json: gateway_node_id）早已透传，但
--      SavePrimary 从未落列（000016 建表至 000035 补审计列均未含）。补列后
--      存量行为 NULL；新事件落列需集成方在 SavePrimary/PrimaryEvent 接入该字段
--      （一行列 + 一行参数，装配片段见交接报告），未接线前节点视图为空属预期。
--   2) api_gateway_nodes 节点版本视图：由 apinodes.Sweeper 周期聚合维护
--      （按 gateway_node 分组：max(occurred_at)/最新非空 policy_version/
--      model_version/count），供节点列表与版本一致性校验只读接口使用。
BEGIN;

-- 1) 事件表补节点列（可空；存量行/旧版网关/未接线采集均为 NULL，
--    与 000035 审计列「缺失容忍」口径一致，不伪造空串占位）
ALTER TABLE api_runtime_events
    ADD COLUMN IF NOT EXISTS gateway_node TEXT;
CREATE INDEX IF NOT EXISTS idx_api_runtime_events_node
    ON api_runtime_events (gateway_node, occurred_at DESC);

-- 2) 节点版本视图（每轮聚合全量重算 upsert，绝对值口径，重扫幂等不产生叠加）
CREATE TABLE IF NOT EXISTS api_gateway_nodes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_name           VARCHAR(128) NOT NULL UNIQUE,           -- 事件 gateway_node（网关节点标识）
    first_seen_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),    -- 聚合口径下最早事件时间
    last_seen_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),    -- 最近事件时间（状态判定基准）
    last_policy_version TEXT         NOT NULL DEFAULT '',       -- 最新非空策略版本；'' = 未上报（旧版网关）
    last_model_version  TEXT         NOT NULL DEFAULT '',       -- 最新非空模型版本；'' = 未上报
    event_count         BIGINT       NOT NULL DEFAULT 0,        -- 事件表内该节点事件总数（绝对值口径）
    status              VARCHAR(16)  NOT NULL DEFAULT 'SILENT', -- ACTIVE(≤5min)/STALE(≤1h)/SILENT(>1h)
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_gateway_nodes_status
    ON api_gateway_nodes (status);

COMMENT ON TABLE api_gateway_nodes IS
    'API 网关节点版本视图（W12-NODE v1）：由 api_runtime_events 遥测聚合维护，非节点注册/同步协议';

COMMIT;
