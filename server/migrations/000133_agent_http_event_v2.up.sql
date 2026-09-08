-- 000133 WDSP Agent HTTP 事件 schema v2（契约 docs/agents/WDSP_AGENT_HTTP_EVENT_V2_CONTRACT.md；
-- 任务书 docs/tasks/wdsp-p1/P1-03_AGENT_GATEWAY_PROTOCOLS.md §4.1/§4.2，G0+G1）。
--
-- 三部分：
-- 1) agent_http_events 增加 v2 列：全部 NULL 或带默认值，存量行零改写、语义不受影响
--    （v1 行 schema_version=1 / source_type=PASSIVE_HTTP1 / observed=UNKNOWN，如实表达
--    "旧采集无来源/协议观测信息"，不回填伪造）。tls_visibility CHECK 扩展 DECRYPTED
--    （v2 枚举；v1 端点仍 fail-closed 只收 PLAINTEXT——应用层口径不变）。
-- 2) (agent_id, event_id) 幂等去重：用部分唯一索引（WHERE event_id IS NOT NULL）而非
--    唯一约束——PostgreSQL 唯一约束不支持部分谓词，且存量行 event_id 全 NULL，部分索引
--    天然兼容存量数据，无添加失败风险；ON CONFLICT 以同谓词推断该索引。
-- 3) agent_http_asset_sources 资产来源关系表（契约 §5）：endpoint、Agent、来源实例、
--    绑定版本、首/末次观测、关联状态；多来源各自成行，不覆盖既有资产所有权。
-- 4) agents.http_event_schemas：能力协商生效集（注册/心跳扩展，契约 §3），默认 {1}。
BEGIN;

ALTER TABLE agent_http_events
    ADD COLUMN IF NOT EXISTS schema_version    SMALLINT     NOT NULL DEFAULT 1
        CHECK (schema_version IN (1, 2)),
    ADD COLUMN IF NOT EXISTS event_id          VARCHAR(128) NULL,
    ADD COLUMN IF NOT EXISTS source_type       VARCHAR(16)  NOT NULL DEFAULT 'PASSIVE_HTTP1'
        CHECK (source_type IN ('PASSIVE_HTTP1', 'NGINX_MIRROR', 'ENVOY_TAP')),
    ADD COLUMN IF NOT EXISTS source_instance   VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_epoch      BIGINT       NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS source_capabilities_version VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS observed_http_version VARCHAR(8) NOT NULL DEFAULT 'UNKNOWN'
        CHECK (observed_http_version IN ('1.0', '1.1', '2', '3', 'UNKNOWN')),
    ADD COLUMN IF NOT EXISTS original_http_version VARCHAR(8) NULL
        CHECK (original_http_version IN ('1.0', '1.1', '2', '3', 'UNKNOWN')),
    ADD COLUMN IF NOT EXISTS association_state VARCHAR(16)  NULL
        CHECK (association_state IN ('COMPLETE', 'REQUEST_ONLY', 'PARTIAL', 'UNCORRELATED')),
    ADD COLUMN IF NOT EXISTS association_reason VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS capture_stream_id VARCHAR(255) NULL,
    ADD COLUMN IF NOT EXISTS application_binding_id UUID    NULL,
    ADD COLUMN IF NOT EXISTS binding_version   BIGINT       NULL,
    ADD COLUMN IF NOT EXISTS grpc              JSONB        NULL,
    ADD COLUMN IF NOT EXISTS request_trailers  JSONB        NULL,
    ADD COLUMN IF NOT EXISTS response_trailers JSONB        NULL,
    ADD COLUMN IF NOT EXISTS req_body_quality  JSONB        NULL,
    ADD COLUMN IF NOT EXISTS resp_body_quality JSONB        NULL,
    ADD COLUMN IF NOT EXISTS collection_ts     TIMESTAMPTZ  NULL,
    ADD COLUMN IF NOT EXISTS ingestion_ts      TIMESTAMPTZ  NULL;

-- tls_visibility 枚举扩展 DECRYPTED（000112 既有 CHECK 为 PLAINTEXT/ENCRYPTED/UNKNOWN；
-- 约束名为 PostgreSQL 自动命名，先查后替换，保持幂等）。
DO $$
DECLARE
    conname TEXT;
BEGIN
    SELECT con.conname INTO conname
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
    WHERE rel.relname = 'agent_http_events'
      AND con.contype = 'c'
      AND pg_get_constraintdef(con.oid) ILIKE '%tls_visibility%';
    IF conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE agent_http_events DROP CONSTRAINT %I', conname);
    END IF;
END $$;
ALTER TABLE agent_http_events
    ADD CONSTRAINT agent_http_events_tls_visibility_check
    CHECK (tls_visibility IN ('PLAINTEXT', 'ENCRYPTED', 'DECRYPTED', 'UNKNOWN'));

-- (agent_id, event_id) 幂等去重：部分唯一索引（存量行 event_id 全 NULL 不受影响）；
-- 服务端 v2 入库 ON CONFLICT (agent_id, event_id) WHERE event_id IS NOT NULL DO NOTHING。
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_http_events_event_id
    ON agent_http_events (agent_id, event_id) WHERE event_id IS NOT NULL;

-- 资产来源关系（契约 §5）：关联失败/配额拒绝/未绑定均可查询，不只 Warn。
CREATE TABLE IF NOT EXISTS agent_http_asset_sources (
    id                BIGSERIAL PRIMARY KEY,
    agent_id          UUID         NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    endpoint_id       UUID         NULL REFERENCES api_endpoints(id) ON DELETE SET NULL,
    host              VARCHAR(255) NOT NULL DEFAULT '',
    method            VARCHAR(16)  NOT NULL,
    path_template     TEXT         NOT NULL,
    source_type       VARCHAR(16)  NOT NULL
                      CHECK (source_type IN ('PASSIVE_HTTP1', 'NGINX_MIRROR', 'ENVOY_TAP')),
    source_instance   VARCHAR(255) NOT NULL DEFAULT '',
    source_epoch      BIGINT       NOT NULL DEFAULT 0,
    application_binding_id UUID    NULL,
    binding_version   BIGINT       NULL,
    association_state VARCHAR(16)  NOT NULL
                      CHECK (association_state IN ('LINKED', 'UNASSIGNED', 'QUOTA_REJECTED', 'FAILED')),
    last_error        VARCHAR(255) NOT NULL DEFAULT '',
    first_seen_at     TIMESTAMPTZ  NOT NULL,
    last_seen_at      TIMESTAMPTZ  NOT NULL,
    UNIQUE (agent_id, host, method, path_template, source_type, source_instance)
);
CREATE INDEX IF NOT EXISTS idx_agent_http_asset_sources_agent_state
    ON agent_http_asset_sources (agent_id, association_state);

-- 能力协商生效集（契约 §3；缺省 {1}=仅 v1，注册/心跳声明 ∩ 服务端支持集 {1,2}）。
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS http_event_schemas SMALLINT[] NOT NULL DEFAULT '{1}';

COMMIT;
