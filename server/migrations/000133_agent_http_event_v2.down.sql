-- 000133 down：回滚 HTTP 事件 schema v2（契约 §6）。
-- 注意：回滚会删除 v2 专有列与来源关系表——schema_version=2 的事件行随之丢失 v2 维度
-- （v1 兼容列保留）；先停 v2 Agent 采集再回滚，与任务书回退顺序一致。
BEGIN;

ALTER TABLE agents DROP COLUMN IF EXISTS http_event_schemas;

DROP TABLE IF EXISTS agent_http_asset_sources;

DROP INDEX IF EXISTS uq_agent_http_events_event_id;

ALTER TABLE agent_http_events
    DROP CONSTRAINT IF EXISTS agent_http_events_tls_visibility_check;
ALTER TABLE agent_http_events
    ADD CONSTRAINT agent_http_events_tls_visibility_check
    CHECK (tls_visibility IN ('PLAINTEXT', 'ENCRYPTED', 'UNKNOWN'));

ALTER TABLE agent_http_events
    DROP COLUMN IF EXISTS ingestion_ts,
    DROP COLUMN IF EXISTS collection_ts,
    DROP COLUMN IF EXISTS resp_body_quality,
    DROP COLUMN IF EXISTS req_body_quality,
    DROP COLUMN IF EXISTS response_trailers,
    DROP COLUMN IF EXISTS request_trailers,
    DROP COLUMN IF EXISTS grpc,
    DROP COLUMN IF EXISTS binding_version,
    DROP COLUMN IF EXISTS application_binding_id,
    DROP COLUMN IF EXISTS capture_stream_id,
    DROP COLUMN IF EXISTS association_reason,
    DROP COLUMN IF EXISTS association_state,
    DROP COLUMN IF EXISTS original_http_version,
    DROP COLUMN IF EXISTS observed_http_version,
    DROP COLUMN IF EXISTS source_capabilities_version,
    DROP COLUMN IF EXISTS source_epoch,
    DROP COLUMN IF EXISTS source_instance,
    DROP COLUMN IF EXISTS source_type,
    DROP COLUMN IF EXISTS event_id,
    DROP COLUMN IF EXISTS schema_version;

COMMIT;
