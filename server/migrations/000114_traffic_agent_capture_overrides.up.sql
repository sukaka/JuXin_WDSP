-- 000114 WDSP 流量采集 Agent Phase 4 智能采集：定向采集规则表
-- （契约 docs/agents/WDSP_AGENT_PHASE4_CONTRACT.md §2.1）。
--
-- agent_capture_overrides：管理端按 Agent 下发的动态采集规则——匹配条件（match JSONB，
-- §2.2：dst_ip/dst_port/host/uri_prefix 全部可选、多字段 AND、至少一字段，由应用层
-- fail-closed 校验）+ 目标采集等级（L0|L1|L2|L3，规则只升不降）+ TTL（expires_at）。
-- Agent 经 GET /api/v1/agents/{id}/config 的顶层 overrides 字段（未过期全量）拉取；
-- 创建/删除联动 agents.config_version+1 驱动重拉（应用层同一事务）。
-- 过期规则不主动删除（Agent 按 expires_at 忽略，管理端列表标注 inactive），
-- expires_at 早于 30 天后由 http sweeper 同周期顺带清理（契约 §2.3）。
BEGIN;

CREATE TABLE IF NOT EXISTS agent_capture_overrides (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id      UUID         NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    match         JSONB        NOT NULL,                -- §2.2 匹配条件（dst_ip/dst_port/host/uri_prefix）
    capture_level VARCHAR(2)   NOT NULL
                  CHECK (capture_level IN ('L0', 'L1', 'L2', 'L3')),
    note          TEXT         NOT NULL DEFAULT '',
    created_by    VARCHAR(255) NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ  NOT NULL
);
-- config 拉取（agent_id + expires_at 过滤未过期全量）与管理端列表共用索引（契约 §2.1）
CREATE INDEX IF NOT EXISTS idx_agent_capture_overrides_agent_expires
    ON agent_capture_overrides (agent_id, expires_at);

COMMIT;
