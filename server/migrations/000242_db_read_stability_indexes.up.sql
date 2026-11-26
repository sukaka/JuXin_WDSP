-- 000242 数据库读稳定性与索引体系优化（阶段 1）：
--   1) 补齐热路径缺失索引（attacksessions 身份关联 / access_logs / api_runtime_events /
--      api_endpoints / api_model_versions / api_call_edges / api_schema_violations）；
--   2) 补齐留存清理时间前导索引与高风险大表未索引外键；
--   3) 精简单列低基数/重复/被 UNIQUE 约束完全前缀覆盖的冗余索引，降低写放大与内存占用；
--   4) 为高频 UPDATE 表设置 fillfactor=80 提升 HOT 更新比例；
--   5) 防御式启用 pg_trgm 并为高频模糊搜索列建立 GIN trigram 索引（权限不足或扩展缺失时告警跳过，不阻断迁移）。
BEGIN;

-- ==================== 1. 攻击会话与身份关联热路径（消除逐行全表扫描） ====================
CREATE INDEX IF NOT EXISTS idx_identity_behavior_events_request_id
    ON identity_behavior_events (request_id, occurred_at DESC)
    WHERE request_id IS NOT NULL AND request_id <> '';

CREATE INDEX IF NOT EXISTS idx_identity_ip_history_ip
    ON identity_ip_history (ip, identity_id);

-- ==================== 2. access_logs 索引重构（配合 SQL 去 host() 恢复索引命中） ====================
CREATE INDEX IF NOT EXISTS idx_access_logs_client_ip_occurred
    ON access_logs (client_ip, occurred_at DESC)
    WHERE client_ip IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_access_logs_endpoint_occurred
    ON access_logs (endpoint_key, occurred_at DESC)
    WHERE endpoint_key IS NOT NULL AND endpoint_key <> '';

CREATE INDEX IF NOT EXISTS idx_access_logs_waf_action_occurred
    ON access_logs (waf_action, occurred_at DESC)
    WHERE waf_action <> '' AND waf_action <> 'ALLOW';

CREATE INDEX IF NOT EXISTS idx_access_logs_status_err_occurred
    ON access_logs (response_status, occurred_at DESC)
    WHERE response_status >= 400;

DROP INDEX IF EXISTS idx_access_logs_client_ip;
DROP INDEX IF EXISTS idx_access_logs_response_status;
DROP INDEX IF EXISTS idx_access_logs_domain;

-- ==================== 3. api_runtime_events 关键查询与 JSONB 索引 ====================
CREATE INDEX IF NOT EXISTS idx_api_runtime_events_endpoint_occurred
    ON api_runtime_events (endpoint_key, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_api_runtime_events_identity_occurred
    ON api_runtime_events (identity_fingerprint, occurred_at DESC)
    WHERE identity_fingerprint <> '';

CREATE INDEX IF NOT EXISTS idx_api_runtime_events_final_action_occurred
    ON api_runtime_events (final_action, occurred_at DESC)
    WHERE final_action <> '' AND final_action <> 'ALLOW';

CREATE INDEX IF NOT EXISTS idx_api_runtime_events_details_gin
    ON api_runtime_events USING GIN (details_json jsonb_path_ops);

DROP INDEX IF EXISTS idx_api_runtime_events_identity;

-- ==================== 4. API 资产 / 模型版本 / 调用边 / Schema 违例 ====================
-- 4a) api_endpoints：新增独立资产价值评分时间戳列，消除 JSONB 强转扫描
ALTER TABLE api_endpoints
    ADD COLUMN IF NOT EXISTS asset_value_computed_at TIMESTAMPTZ;

COMMENT ON COLUMN api_endpoints.asset_value_computed_at IS
    '资产价值最近一次评分时间（冗余自 asset_value_explain.computed_at，供定时回填索引扫描）';

DO $$
DECLARE
    rfc3339_re CONSTANT TEXT := '^(([1-9]\d{3}|0[1-9]\d{2}|00[1-9]\d|000[1-9])-((0[13578]|1[02])-(0[1-9]|[12]\d|3[01])|(0[469]|11)-(0[1-9]|[12]\d|30)|02-(0[1-9]|1\d|2[0-8]))|((0[48]|[2468][048]|[13579][26])00|\d{2}(0[48]|[2468][048]|[13579][26]))-02-29)T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d+)?(Z|[+-](0\d|1[0-5]):?[0-5]\d)$';
BEGIN
    IF current_setting('server_version_num')::int >= 160000 THEN
        UPDATE api_endpoints
        SET asset_value_computed_at = (asset_value_explain->>'computed_at')::timestamptz
        WHERE asset_value_computed_at IS NULL
          AND asset_value_explain IS NOT NULL
          AND COALESCE(asset_value_explain->>'computed_at', '') ~ rfc3339_re
          AND pg_input_is_valid(COALESCE(asset_value_explain->>'computed_at', ''), 'timestamptz');
    ELSE
        UPDATE api_endpoints
        SET asset_value_computed_at = (asset_value_explain->>'computed_at')::timestamptz
        WHERE asset_value_computed_at IS NULL
          AND asset_value_explain IS NOT NULL
          AND COALESCE(asset_value_explain->>'computed_at', '') ~ rfc3339_re;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_api_endpoints_is_api_last_seen
    ON api_endpoints (last_seen_at DESC)
    WHERE is_api = TRUE;

CREATE INDEX IF NOT EXISTS idx_api_endpoints_app_is_api_last_seen
    ON api_endpoints (application_id, last_seen_at DESC)
    WHERE is_api = TRUE;

CREATE INDEX IF NOT EXISTS idx_api_endpoints_app_confirmed_key
    ON api_endpoints (application_id, endpoint_key)
    WHERE asset_status = 'CONFIRMED';

CREATE INDEX IF NOT EXISTS idx_api_endpoints_value_refresh
    ON api_endpoints (last_seen_at DESC)
    WHERE asset_status <> 'IGNORED';

-- 4b) api_model_versions：直击 ListFormalSchemas / ListFormalModelVersions / FormalSchema 全表排序
CREATE INDEX IF NOT EXISTS idx_api_model_versions_formal_key_confirmed
    ON api_model_versions (endpoint_key, confirmed_at DESC NULLS LAST)
    INCLUDE (id, version_number)
    WHERE status = 'FORMAL';

CREATE INDEX IF NOT EXISTS idx_api_model_versions_status
    ON api_model_versions (status);

-- 4c) api_call_edges：补齐源端外键、调用量倒序与活跃时间窗索引
CREATE INDEX IF NOT EXISTS idx_api_call_edges_source
    ON api_call_edges (source_endpoint_id)
    WHERE source_endpoint_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_api_call_edges_call_count
    ON api_call_edges (call_count DESC, id);

CREATE INDEX IF NOT EXISTS idx_api_call_edges_last_seen_count
    ON api_call_edges (last_seen_at DESC, call_count DESC);

-- 4d) api_schema_violations：补齐默认时间倒序列表、违例类型筛选与外键索引
CREATE INDEX IF NOT EXISTS idx_api_schema_violations_occurred
    ON api_schema_violations (occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_api_schema_violations_type_occurred
    ON api_schema_violations (violation_type, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_api_schema_violations_model_version
    ON api_schema_violations (model_version_id)
    WHERE model_version_id IS NOT NULL;

-- ==================== 5. 留存清理时间前导索引 & 核心大表未索引外键 ====================
CREATE INDEX IF NOT EXISTS idx_agent_http_events_created_at
    ON agent_http_events (created_at);

CREATE INDEX IF NOT EXISTS idx_upstream_health_records_checked_at
    ON upstream_health_records (checked_at);

CREATE INDEX IF NOT EXISTS idx_system_health_snapshots_taken_at
    ON system_health_snapshots (taken_at);

CREATE INDEX IF NOT EXISTS idx_api_endpoint_traffic_buckets_bucket
    ON api_endpoint_traffic_buckets (bucket_start);

CREATE INDEX IF NOT EXISTS idx_agent_api_obs_asset_events_projected
    ON agent_api_observation_asset_events (projected_at);

CREATE INDEX IF NOT EXISTS idx_api_authz_candidate_receipts_processed
    ON api_authz_candidate_event_receipts (processed_at);

CREATE INDEX IF NOT EXISTS idx_behavior_statistics_window_start
    ON behavior_statistics (window_start);

CREATE INDEX IF NOT EXISTS idx_api_parameter_relations_source
    ON api_parameter_relations (source_parameter_id);

CREATE INDEX IF NOT EXISTS idx_api_parameter_relations_target
    ON api_parameter_relations (target_parameter_id);

CREATE INDEX IF NOT EXISTS idx_api_identity_profiles_endpoint
    ON api_identity_profiles (endpoint_id);

CREATE INDEX IF NOT EXISTS idx_api_file_assets_endpoint
    ON api_file_assets (endpoint_id)
    WHERE endpoint_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_api_object_relation_candidates_endpoint
    ON api_object_relation_candidates (endpoint_id)
    WHERE endpoint_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agent_http_asset_sources_endpoint
    ON agent_http_asset_sources (endpoint_id)
    WHERE endpoint_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_site_traffic_daily_app
    ON site_traffic_daily (application_id);

CREATE INDEX IF NOT EXISTS idx_rate_limit_policies_app
    ON rate_limit_policies (application_id)
    WHERE application_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_temporary_blocks_app
    ON temporary_blocks (application_id)
    WHERE application_id IS NOT NULL;

-- ==================== 6. security_events / access_control_events 精简与冗余清理 ====================
CREATE INDEX IF NOT EXISTS idx_security_events_client_ip_occurred
    ON security_events (client_ip, occurred_at DESC)
    WHERE client_ip IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_security_events_attack_type_occurred
    ON security_events (attack_type, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_action_occurred
    ON security_events (action, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_request_occurred
    ON security_events (request_id, occurred_at);

DROP INDEX IF EXISTS idx_security_events_client_ip;
DROP INDEX IF EXISTS idx_security_events_attack_type;
DROP INDEX IF EXISTS idx_security_events_action;
DROP INDEX IF EXISTS idx_security_events_severity;
DROP INDEX IF EXISTS idx_security_events_request_id;
DROP INDEX IF EXISTS idx_security_events_time;
DROP INDEX IF EXISTS idx_security_events_disposition;

-- 与 idx_ac_events_type (event_type, occurred_at DESC) 100% 重复
DROP INDEX IF EXISTS idx_ac_events_disposition_time;

-- 仅在 000028 身份复合索引确认存在时移除前缀冗余索引
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = current_schema()
          AND tablename = 'api_parameter_models'
          AND indexname IN ('ux_api_parameter_models_identity', 'idx_api_parameter_models_identity')
    ) THEN
        DROP INDEX IF EXISTS idx_api_parameter_models_version;
    END IF;
END $$;

-- 已被表级 UNIQUE 约束前缀覆盖的冗余索引
DROP INDEX IF EXISTS idx_waf_rules_rule_id;
DROP INDEX IF EXISTS idx_custom_rules_rule_id;
DROP INDEX IF EXISTS idx_user_roles_user;
DROP INDEX IF EXISTS idx_role_permissions_role;
DROP INDEX IF EXISTS idx_app_certs_app;
DROP INDEX IF EXISTS idx_app_policies_app;
DROP INDEX IF EXISTS idx_api_parameter_value_obs_endpoint;
DROP INDEX IF EXISTS idx_api_role_baselines_endpoint;
DROP INDEX IF EXISTS idx_strong_flow_steps_def;
DROP INDEX IF EXISTS idx_agent_policy_versions_policy;
DROP INDEX IF EXISTS idx_agent_cert_rotations_agent;
DROP INDEX IF EXISTS idx_ai_prompt_versions_prompt;
DROP INDEX IF EXISTS idx_mcp_catalog_tools_catalog;
DROP INDEX IF EXISTS idx_sreg_cases_run;

-- ==================== 7. 高频更新表 fillfactor=80（提升 HOT 更新比例） ====================
ALTER TABLE api_endpoints        SET (fillfactor = 80);
ALTER TABLE client_identity      SET (fillfactor = 80);
ALTER TABLE identity_ip_history  SET (fillfactor = 80);
ALTER TABLE api_runtime_findings SET (fillfactor = 80);
ALTER TABLE api_call_edges       SET (fillfactor = 80);

-- ==================== 8. 防御式启用 pg_trgm 与高频模糊搜索 GIN 索引 ====================
DO $$
BEGIN
    BEGIN
        CREATE EXTENSION IF NOT EXISTS pg_trgm;
    EXCEPTION WHEN insufficient_privilege OR undefined_file THEN
        RAISE WARNING 'pg_trgm extension unavailable, skipping trigram GIN indexes: %', SQLERRM;
    END;

    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') THEN
        CREATE INDEX IF NOT EXISTS idx_access_logs_domain_trgm
            ON access_logs USING GIN (domain gin_trgm_ops);
        CREATE INDEX IF NOT EXISTS idx_access_logs_uri_trgm
            ON access_logs USING GIN (request_uri gin_trgm_ops);
        CREATE INDEX IF NOT EXISTS idx_security_events_domain_trgm
            ON security_events USING GIN (domain gin_trgm_ops);
        CREATE INDEX IF NOT EXISTS idx_security_events_uri_trgm
            ON security_events USING GIN (request_uri gin_trgm_ops);
        CREATE INDEX IF NOT EXISTS idx_api_endpoints_path_trgm
            ON api_endpoints USING GIN (normalized_path gin_trgm_ops);
        CREATE INDEX IF NOT EXISTS idx_tls_handshake_events_sni_trgm
            ON tls_handshake_events USING GIN (sni gin_trgm_ops);
    END IF;
END $$;

COMMIT;
