-- 000242 回滚：恢复迁移前索引与存储参数（不删除可能已被其他扩展依赖的 pg_trgm 扩展本身）
BEGIN;

-- 8. 移除 trigram GIN 索引
DROP INDEX IF EXISTS idx_tls_handshake_events_sni_trgm;
DROP INDEX IF EXISTS idx_api_endpoints_path_trgm;
DROP INDEX IF EXISTS idx_security_events_uri_trgm;
DROP INDEX IF EXISTS idx_security_events_domain_trgm;
DROP INDEX IF EXISTS idx_access_logs_uri_trgm;
DROP INDEX IF EXISTS idx_access_logs_domain_trgm;

-- 7. 恢复默认 fillfactor
ALTER TABLE api_call_edges       RESET (fillfactor);
ALTER TABLE api_runtime_findings RESET (fillfactor);
ALTER TABLE identity_ip_history  RESET (fillfactor);
ALTER TABLE client_identity      RESET (fillfactor);
ALTER TABLE api_endpoints        RESET (fillfactor);

-- 6. 恢复被清理的旧索引并移除新复合索引
CREATE INDEX IF NOT EXISTS idx_sreg_cases_run ON security_regression_cases (run_ref);
CREATE INDEX IF NOT EXISTS idx_mcp_catalog_tools_catalog ON mcp_catalog_tools (catalog_id, tool_name);
CREATE INDEX IF NOT EXISTS idx_ai_prompt_versions_prompt ON ai_prompt_versions (prompt_id, version_number DESC);
CREATE INDEX IF NOT EXISTS idx_agent_cert_rotations_agent ON agent_cert_rotations (agent_id, old_fingerprint);
CREATE INDEX IF NOT EXISTS idx_agent_policy_versions_policy ON agent_policy_versions (policy_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_strong_flow_steps_def ON api_strong_flow_steps (definition_id, sequence);
CREATE INDEX IF NOT EXISTS idx_api_role_baselines_endpoint ON api_role_baselines (endpoint_id, role);
CREATE INDEX IF NOT EXISTS idx_api_parameter_value_obs_endpoint ON api_parameter_value_obs (endpoint_key);
CREATE INDEX IF NOT EXISTS idx_app_policies_app ON application_policies (application_id);
CREATE INDEX IF NOT EXISTS idx_app_certs_app ON application_certificates (application_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions (role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles (user_id);
CREATE INDEX IF NOT EXISTS idx_custom_rules_rule_id ON custom_rules (rule_id);
CREATE INDEX IF NOT EXISTS idx_waf_rules_rule_id ON waf_rules (rule_id);
CREATE INDEX IF NOT EXISTS idx_api_parameter_models_version ON api_parameter_models (model_version_id, direction);
CREATE INDEX IF NOT EXISTS idx_ac_events_disposition_time ON access_control_events (event_type, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_client_ip ON security_events (client_ip);
CREATE INDEX IF NOT EXISTS idx_security_events_attack_type ON security_events (attack_type);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events (severity);
CREATE INDEX IF NOT EXISTS idx_security_events_action ON security_events (action);
CREATE INDEX IF NOT EXISTS idx_security_events_disposition ON security_events (disposition_status);
CREATE INDEX IF NOT EXISTS idx_security_events_request_id ON security_events (request_id);

DROP INDEX IF EXISTS idx_security_events_request_occurred;
DROP INDEX IF EXISTS idx_security_events_action_occurred;
DROP INDEX IF EXISTS idx_security_events_attack_type_occurred;
DROP INDEX IF EXISTS idx_security_events_client_ip_occurred;

-- 5. 移除清理时间索引与补充外键索引
DROP INDEX IF EXISTS idx_temporary_blocks_app;
DROP INDEX IF EXISTS idx_rate_limit_policies_app;
DROP INDEX IF EXISTS idx_site_traffic_daily_app;
DROP INDEX IF EXISTS idx_agent_http_asset_sources_endpoint;
DROP INDEX IF EXISTS idx_api_object_relation_candidates_endpoint;
DROP INDEX IF EXISTS idx_api_file_assets_endpoint;
DROP INDEX IF EXISTS idx_api_identity_profiles_endpoint;
DROP INDEX IF EXISTS idx_api_parameter_relations_target;
DROP INDEX IF EXISTS idx_api_parameter_relations_source;
DROP INDEX IF EXISTS idx_behavior_statistics_window_start;
DROP INDEX IF EXISTS idx_api_authz_candidate_receipts_processed;
DROP INDEX IF EXISTS idx_agent_api_obs_asset_events_projected;
DROP INDEX IF EXISTS idx_api_endpoint_traffic_buckets_bucket;
DROP INDEX IF EXISTS idx_system_health_snapshots_taken_at;
DROP INDEX IF EXISTS idx_upstream_health_records_checked_at;
DROP INDEX IF EXISTS idx_agent_http_events_created_at;

-- 4. 移除 API 核心表新索引与列
DROP INDEX IF EXISTS idx_api_schema_violations_model_version;
DROP INDEX IF EXISTS idx_api_schema_violations_type_occurred;
DROP INDEX IF EXISTS idx_api_schema_violations_occurred;
DROP INDEX IF EXISTS idx_api_call_edges_last_seen_count;
DROP INDEX IF EXISTS idx_api_call_edges_call_count;
DROP INDEX IF EXISTS idx_api_call_edges_source;
DROP INDEX IF EXISTS idx_api_model_versions_status;
DROP INDEX IF EXISTS idx_api_model_versions_formal_key_confirmed;
DROP INDEX IF EXISTS idx_api_endpoints_value_refresh;
DROP INDEX IF EXISTS idx_api_endpoints_app_confirmed_key;
DROP INDEX IF EXISTS idx_api_endpoints_app_is_api_last_seen;
DROP INDEX IF EXISTS idx_api_endpoints_is_api_last_seen;
ALTER TABLE api_endpoints DROP COLUMN IF EXISTS asset_value_computed_at;

-- 3. 恢复 api_runtime_events 旧索引
CREATE INDEX IF NOT EXISTS idx_api_runtime_events_identity
    ON api_runtime_events (identity_fingerprint) WHERE identity_fingerprint <> '';
DROP INDEX IF EXISTS idx_api_runtime_events_details_gin;
DROP INDEX IF EXISTS idx_api_runtime_events_final_action_occurred;
DROP INDEX IF EXISTS idx_api_runtime_events_identity_occurred;
DROP INDEX IF EXISTS idx_api_runtime_events_endpoint_occurred;

-- 2. 恢复 access_logs 旧索引
CREATE INDEX IF NOT EXISTS idx_access_logs_domain ON access_logs (domain);
CREATE INDEX IF NOT EXISTS idx_access_logs_client_ip ON access_logs (client_ip);
CREATE INDEX IF NOT EXISTS idx_access_logs_response_status ON access_logs (response_status);
DROP INDEX IF EXISTS idx_access_logs_status_err_occurred;
DROP INDEX IF EXISTS idx_access_logs_waf_action_occurred;
DROP INDEX IF EXISTS idx_access_logs_endpoint_occurred;
DROP INDEX IF EXISTS idx_access_logs_client_ip_occurred;

-- 1. 移除攻击会话与身份关联索引
DROP INDEX IF EXISTS idx_identity_ip_history_ip;
DROP INDEX IF EXISTS idx_identity_behavior_events_request_id;

COMMIT;
