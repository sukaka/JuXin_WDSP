-- 000018 回滚：恢复 000016 简化结构并删除新增 23 张表
BEGIN;

-- 关联约束
ALTER TABLE api_model_versions DROP CONSTRAINT IF EXISTS fk_api_model_versions_response_schema_set;
ALTER TABLE api_model_versions DROP CONSTRAINT IF EXISTS fk_api_model_versions_request_schema;
ALTER TABLE api_endpoints DROP CONSTRAINT IF EXISTS fk_api_endpoints_current_model;

-- 新增表（按依赖反序）
DROP TABLE IF EXISTS api_spec_diffs;
DROP TABLE IF EXISTS api_import_specs;
DROP TABLE IF EXISTS api_model_diffs;
DROP TABLE IF EXISTS api_model_reviews;
DROP TABLE IF EXISTS api_lifecycle_events;
DROP TABLE IF EXISTS api_schema_violations;
DROP TABLE IF EXISTS api_runtime_findings;
DROP TABLE IF EXISTS api_sensitive_fields;
DROP TABLE IF EXISTS api_call_edges;
DROP TABLE IF EXISTS api_behavior_profiles;
DROP TABLE IF EXISTS api_object_models;
DROP TABLE IF EXISTS api_identity_profiles;
DROP TABLE IF EXISTS api_custom_taxonomies;
DROP TABLE IF EXISTS api_classification_dimensions;
DROP TABLE IF EXISTS api_classifications;
DROP TABLE IF EXISTS api_response_schemas;
DROP TABLE IF EXISTS api_request_schemas;
DROP TABLE IF EXISTS api_parameter_relations;
DROP TABLE IF EXISTS api_parameter_statistics;
DROP TABLE IF EXISTS api_parameter_models;
DROP TABLE IF EXISTS api_learning_samples;
DROP TABLE IF EXISTS api_learning_jobs;
DROP TABLE IF EXISTS api_assets;
DROP TABLE IF EXISTS api_endpoint_path_segments;
DROP TABLE IF EXISTS api_endpoint_aliases;

-- api_model_versions 还原
ALTER TABLE api_model_versions ADD COLUMN IF NOT EXISTS frozen_at TIMESTAMPTZ;
UPDATE api_model_versions SET frozen_at = confirmed_at WHERE frozen_at IS NULL AND confirmed_at IS NOT NULL;
ALTER TABLE api_model_versions
    DROP COLUMN IF EXISTS version_number,
    DROP COLUMN IF EXISTS parent_version_id,
    DROP COLUMN IF EXISTS request_schema_id,
    DROP COLUMN IF EXISTS response_schema_set_id,
    DROP COLUMN IF EXISTS sample_count,
    DROP COLUMN IF EXISTS valid_sample_count,
    DROP COLUMN IF EXISTS excluded_sample_count,
    DROP COLUMN IF EXISTS confidence,
    DROP COLUMN IF EXISTS change_summary,
    DROP COLUMN IF EXISTS created_reason,
    DROP COLUMN IF EXISTS created_by,
    DROP COLUMN IF EXISTS confirmed_by,
    DROP COLUMN IF EXISTS confirmed_at,
    DROP COLUMN IF EXISTS activated_at;
ALTER TABLE api_model_versions RENAME COLUMN api_endpoint_id TO endpoint_id;

-- api_endpoints 还原
ALTER TABLE api_endpoints
    DROP COLUMN IF EXISTS domain_id,
    DROP COLUMN IF EXISTS raw_path_example,
    DROP COLUMN IF EXISTS protocol_type,
    DROP COLUMN IF EXISTS learning_status,
    DROP COLUMN IF EXISTS current_model_version_id,
    DROP COLUMN IF EXISTS classification_locked;
ALTER TABLE api_endpoints RENAME COLUMN http_method TO method;
ALTER TABLE api_endpoints RENAME COLUMN normalized_path TO path_template;
ALTER TABLE api_endpoints RENAME COLUMN api_confidence TO confidence;
ALTER TABLE api_endpoints RENAME COLUMN asset_status TO status;
ALTER INDEX IF EXISTS idx_api_endpoints_asset_status RENAME TO idx_api_endpoints_status;
DROP INDEX IF EXISTS idx_api_endpoints_application;
DROP INDEX IF EXISTS idx_api_endpoints_learning;

COMMIT;
