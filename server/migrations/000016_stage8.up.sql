-- 阶段8：API 资产、学习版本、运行时主事件
BEGIN;

CREATE TABLE IF NOT EXISTS api_endpoints (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id  UUID,
    method          VARCHAR(16)  NOT NULL,
    path_template   VARCHAR(512) NOT NULL,
    endpoint_key    VARCHAR(560) NOT NULL,
    confidence      DOUBLE PRECISION NOT NULL DEFAULT 0,
    status          VARCHAR(32)  NOT NULL DEFAULT 'DISCOVERED', -- DISCOVERED / CONFIRMED / DEPRECATED
    is_api          BOOLEAN      NOT NULL DEFAULT TRUE,
    hit_count       BIGINT       NOT NULL DEFAULT 0,
    first_seen_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    confirmed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_endpoints_key ON api_endpoints (endpoint_key);
CREATE INDEX IF NOT EXISTS idx_api_endpoints_status ON api_endpoints (status);

CREATE TABLE IF NOT EXISTS api_model_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id     UUID         NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    endpoint_key    VARCHAR(560) NOT NULL,
    status          VARCHAR(32)  NOT NULL DEFAULT 'CANDIDATE', -- CANDIDATE / FORMAL / SUPERSEDED
    schema_json     JSONB        NOT NULL DEFAULT '{}',
    content_hash    VARCHAR(128) NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    frozen_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_model_versions_endpoint ON api_model_versions (endpoint_id, status);

CREATE TABLE IF NOT EXISTS api_runtime_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id      VARCHAR(64)  NOT NULL,
    endpoint_key    VARCHAR(560) NOT NULL DEFAULT '',
    risk_score      INTEGER      NOT NULL DEFAULT 0,
    risk_level      VARCHAR(32)  NOT NULL DEFAULT 'NONE',
    final_action    VARCHAR(32)  NOT NULL DEFAULT 'ALLOW',
    details_json    JSONB        NOT NULL DEFAULT '[]',
    occurred_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_runtime_events_request ON api_runtime_events (request_id);
CREATE INDEX IF NOT EXISTS idx_api_runtime_events_time ON api_runtime_events (occurred_at DESC);

COMMIT;
