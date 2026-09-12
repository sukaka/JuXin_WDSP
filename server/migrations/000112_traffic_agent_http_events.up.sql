-- 000112 WDSP 分布式流量采集 Agent Phase 3（HTTP Sensor 服务端侧，
-- 契约 docs/agents/WDSP_AGENT_PHASE3_CONTRACT.md §6）。
--
-- agent_http_events：Full HTTP 事件（L1/L2 采集等级下 Agent 完成请求/响应关联后上报，
-- 机器端点 POST /api/v1/agents/{agent_id}/http）：
--   - ts = request_ts（Agent 上报 Unix 秒浮点，毫秒精度）；response 未捕获/超时（可为 null）
--     时 status/latency_ms/response_headers/response_body 同步为 NULL；
--   - headers/body 均为 Agent 离主机前脱敏后的内容（契约 §5，服务端不二次脱敏）；
--     body 超限截断由 req_truncated/resp_truncated 标记，原始长度记 req/resp_original_size；
--   - 保留清理：sweeper 每日删除 created_at 早于 7 天的记录（设计 §68.9 硬上限防无限增长；
--     retention 常量与 sweeper 见 server/internal/agents/http_sweeper.go）；
--   - 随 Agent 删除级联清理（同 agent_flow_events 生命周期口径，迁移 000108）。
--
-- uri 应用层上限 2048 字节（server/internal/agents/http_events.go maxHTTPURILen）：
-- (host, uri) 复合索引受 btree 索引行宽约 2704 字节硬限制，超长 URI 在机器端点校验期
-- 拒绝（400），避免插入期索引行宽错误放大为整批 500 重传。
BEGIN;

CREATE TABLE IF NOT EXISTS agent_http_events (
    id                 BIGSERIAL PRIMARY KEY,
    agent_id           UUID         NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    flow_id            VARCHAR(255) NOT NULL DEFAULT '',
    ts                 TIMESTAMPTZ  NOT NULL,            -- request_ts（请求时间，毫秒精度）
    latency_ms         INT,                              -- response 未捕获为 NULL
    src_ip             VARCHAR(64)  NOT NULL DEFAULT '',
    src_port           INT          NOT NULL DEFAULT 0,
    dst_ip             VARCHAR(64)  NOT NULL DEFAULT '',
    dst_port           INT          NOT NULL DEFAULT 0,
    direction          VARCHAR(16)  NOT NULL
                       CHECK (direction IN ('ingress', 'egress', 'both')),
    tls_visibility     VARCHAR(16)  NOT NULL DEFAULT 'PLAINTEXT'
                       CHECK (tls_visibility IN ('PLAINTEXT', 'ENCRYPTED', 'UNKNOWN')),
    method             VARCHAR(16)  NOT NULL DEFAULT '',
    scheme             VARCHAR(8)   NOT NULL DEFAULT 'http',
    host               VARCHAR(255) NOT NULL DEFAULT '',
    uri                TEXT         NOT NULL DEFAULT '',
    status             INT,                              -- response 未捕获为 NULL
    request_headers    JSONB        NOT NULL DEFAULT '{}'::jsonb,  -- 脱敏后
    response_headers   JSONB,                            -- response 未捕获为 NULL
    request_body       TEXT,                             -- 未采集/内容类型跳过/解压失败为 NULL
    response_body      TEXT,
    req_truncated      BOOLEAN      NOT NULL DEFAULT false,
    resp_truncated     BOOLEAN      NOT NULL DEFAULT false,
    req_original_size  BIGINT       NOT NULL DEFAULT 0,
    resp_original_size BIGINT      NOT NULL DEFAULT 0,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);
-- 管理端按 Agent 时间倒序分页（契约 §6）
CREATE INDEX IF NOT EXISTS idx_agent_http_events_agent_ts
    ON agent_http_events (agent_id, ts DESC);
-- API 资产联动/按站点检索（契约 §6）
CREATE INDEX IF NOT EXISTS idx_agent_http_events_host_uri
    ON agent_http_events (host, uri);

COMMIT;
