-- 阶段8 任务书第五十章：API 动态防护完整数据库结构（27 张表口径）。
-- 在 000016 简化结构基础上扩展：
--   1) api_endpoints / api_model_versions 对齐任务书 50.1 / 50.2 列（重命名 + 补充，数据保留）；
--   2) 新增其余 23 张表（别名/路径段/资产/学习/参数/分类/身份/行为/图谱/敏感/发现/违例/生命周期/评审/规范）。
-- 注意：api_runtime_events（统一主事件）已在 000016 建立，不在本迁移重复。
BEGIN;

-- ==================== 1. api_endpoints 对齐任务书 50.1 ====================
ALTER TABLE api_endpoints RENAME COLUMN method TO http_method;
ALTER TABLE api_endpoints RENAME COLUMN path_template TO normalized_path;
ALTER TABLE api_endpoints RENAME COLUMN confidence TO api_confidence;
ALTER TABLE api_endpoints RENAME COLUMN status TO asset_status;
ALTER TABLE api_endpoints
    ADD COLUMN IF NOT EXISTS domain_id UUID,
    ADD COLUMN IF NOT EXISTS raw_path_example VARCHAR(512) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS protocol_type VARCHAR(32) NOT NULL DEFAULT 'REST',
    ADD COLUMN IF NOT EXISTS learning_status VARCHAR(32) NOT NULL DEFAULT 'NOT_STARTED', -- NOT_STARTED / LEARNING / PAUSED / LEARNED
    ADD COLUMN IF NOT EXISTS current_model_version_id UUID,
    ADD COLUMN IF NOT EXISTS classification_locked BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE api_endpoints SET raw_path_example = normalized_path WHERE raw_path_example = '';
ALTER INDEX idx_api_endpoints_status RENAME TO idx_api_endpoints_asset_status;
CREATE INDEX IF NOT EXISTS idx_api_endpoints_application ON api_endpoints (application_id);
CREATE INDEX IF NOT EXISTS idx_api_endpoints_learning ON api_endpoints (learning_status);

-- ==================== 2. api_model_versions 对齐任务书 50.2 ====================
ALTER TABLE api_model_versions RENAME COLUMN endpoint_id TO api_endpoint_id;
ALTER INDEX idx_api_model_versions_endpoint RENAME TO idx_api_model_versions_endpoint;
ALTER TABLE api_model_versions
    ADD COLUMN IF NOT EXISTS version_number INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS parent_version_id UUID,
    ADD COLUMN IF NOT EXISTS request_schema_id UUID,
    ADD COLUMN IF NOT EXISTS response_schema_set_id UUID,
    ADD COLUMN IF NOT EXISTS sample_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS valid_sample_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS excluded_sample_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS change_summary TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS created_reason VARCHAR(64) NOT NULL DEFAULT 'manual', -- manual / learning_threshold / relearn / import
    ADD COLUMN IF NOT EXISTS created_by UUID,
    ADD COLUMN IF NOT EXISTS confirmed_by UUID,
    ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ;
-- 旧 frozen_at（冻结时间）语义拆分：确认时间与激活时间同源回填
UPDATE api_model_versions SET confirmed_at = frozen_at, activated_at = frozen_at WHERE frozen_at IS NOT NULL;
ALTER TABLE api_model_versions DROP COLUMN IF EXISTS frozen_at;

-- ==================== 3. 端点补充结构 ====================

-- 端点别名（合并/拆分前的历史端点键）
CREATE TABLE IF NOT EXISTS api_endpoint_aliases (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id     UUID NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    alias_key       VARCHAR(560) NOT NULL,
    created_reason  VARCHAR(64)  NOT NULL DEFAULT '', -- merge / split / renormalize
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_endpoint_aliases_key ON api_endpoint_aliases (alias_key);
CREATE INDEX IF NOT EXISTS idx_api_endpoint_aliases_endpoint ON api_endpoint_aliases (endpoint_id);

-- 端点路径段（段级静态/动态识别与样本）
CREATE TABLE IF NOT EXISTS api_endpoint_path_segments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id     UUID NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    position        INTEGER NOT NULL,
    literal_value   VARCHAR(255) NOT NULL DEFAULT '',
    is_variable     BOOLEAN NOT NULL DEFAULT FALSE,
    variable_name   VARCHAR(128) NOT NULL DEFAULT '',
    sample_hashes   JSONB NOT NULL DEFAULT '[]', -- 样本哈希，不存明文敏感值
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (endpoint_id, position)
);

-- API 资产（业务维度归属）
CREATE TABLE IF NOT EXISTS api_assets (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id         UUID NOT NULL UNIQUE REFERENCES api_endpoints(id) ON DELETE CASCADE,
    purpose             VARCHAR(128) NOT NULL DEFAULT '',
    exposure            VARCHAR(32)  NOT NULL DEFAULT 'INTERNAL', -- INTERNAL / PARTNER / PUBLIC
    data_classification VARCHAR(32)  NOT NULL DEFAULT 'UNKNOWN',
    owner               VARCHAR(128) NOT NULL DEFAULT '',
    tags                JSONB NOT NULL DEFAULT '[]',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==================== 4. 学习体系 ====================

-- 学习任务（50.x；start/stop/status 接口的状态源）
CREATE TABLE IF NOT EXISTS api_learning_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id     UUID NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    status          VARCHAR(32) NOT NULL DEFAULT 'RUNNING', -- RUNNING / STOPPED / COMPLETED / FAILED
    sample_target   INTEGER NOT NULL DEFAULT 0,
    collected_count INTEGER NOT NULL DEFAULT 0,
    valid_count     INTEGER NOT NULL DEFAULT 0,
    excluded_count  INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT NOT NULL DEFAULT '',
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    stopped_at      TIMESTAMPTZ,
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_learning_jobs_endpoint ON api_learning_jobs (endpoint_id, status);

-- 学习样本（任务书 50.4；不保存完整敏感值）
CREATE TABLE IF NOT EXISTS api_learning_samples (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_endpoint_id      UUID NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    request_id           VARCHAR(64) NOT NULL DEFAULT '',
    sample_hash          VARCHAR(128) NOT NULL,
    source_fingerprint   VARCHAR(128) NOT NULL DEFAULT '',
    identity_fingerprint VARCHAR(128) NOT NULL DEFAULT '',
    response_status      INTEGER,
    accepted             BOOLEAN NOT NULL DEFAULT TRUE,
    exclude_reason       VARCHAR(255) NOT NULL DEFAULT '',
    collected_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_learning_samples_endpoint ON api_learning_samples (api_endpoint_id, collected_at DESC);

-- ==================== 5. 参数模型体系 ====================

-- 参数模型（任务书 50.3）
CREATE TABLE IF NOT EXISTS api_parameter_models (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_version_id        UUID NOT NULL REFERENCES api_model_versions(id) ON DELETE CASCADE,
    direction               VARCHAR(16) NOT NULL, -- REQUEST / RESPONSE
    location                VARCHAR(32) NOT NULL, -- PATH / QUERY / HEADER / COOKIE / BODY
    structured_path         VARCHAR(512) NOT NULL DEFAULT '',
    parameter_name          VARCHAR(255) NOT NULL,
    base_type               VARCHAR(32) NOT NULL DEFAULT 'string',
    semantic_type           VARCHAR(64) NOT NULL DEFAULT '',
    required                BOOLEAN NOT NULL DEFAULT FALSE,
    nullable                BOOLEAN NOT NULL DEFAULT TRUE,
    empty_allowed           BOOLEAN NOT NULL DEFAULT TRUE,
    observed_constraints    JSONB NOT NULL DEFAULT '{}',
    recommended_constraints JSONB NOT NULL DEFAULT '{}',
    confirmed_constraints   JSONB NOT NULL DEFAULT '{}',
    sensitivity_level       VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    confidence              DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_parameter_models_version ON api_parameter_models (model_version_id, direction);

-- 参数统计画像（长度/值域/基数；样本以哈希留存）
CREATE TABLE IF NOT EXISTS api_parameter_statistics (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parameter_id   UUID NOT NULL UNIQUE REFERENCES api_parameter_models(id) ON DELETE CASCADE,
    sample_count   INTEGER NOT NULL DEFAULT 0,
    min_length     INTEGER,
    max_length     INTEGER,
    min_value      DOUBLE PRECISION,
    max_value      DOUBLE PRECISION,
    distinct_count INTEGER,
    example_hashes JSONB NOT NULL DEFAULT '[]',
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 参数条件关系（如 A 存在时 B 必填）
CREATE TABLE IF NOT EXISTS api_parameter_relations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_version_id    UUID NOT NULL REFERENCES api_model_versions(id) ON DELETE CASCADE,
    source_parameter_id UUID NOT NULL REFERENCES api_parameter_models(id) ON DELETE CASCADE,
    target_parameter_id UUID NOT NULL REFERENCES api_parameter_models(id) ON DELETE CASCADE,
    relation_type       VARCHAR(64) NOT NULL, -- REQUIRES / EXCLUDES / CO_OCCURS
    condition           JSONB NOT NULL DEFAULT '{}',
    confidence          DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_parameter_relations_version ON api_parameter_relations (model_version_id);

-- 请求/响应 Schema（版本化模型的结构化载体）
CREATE TABLE IF NOT EXISTS api_request_schemas (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_version_id UUID NOT NULL REFERENCES api_model_versions(id) ON DELETE CASCADE,
    schema_json      JSONB NOT NULL,
    content_hash     VARCHAR(128) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_request_schemas_version ON api_request_schemas (model_version_id);

CREATE TABLE IF NOT EXISTS api_response_schemas (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_version_id UUID NOT NULL REFERENCES api_model_versions(id) ON DELETE CASCADE,
    status_code      INTEGER NOT NULL DEFAULT 200,
    schema_json      JSONB NOT NULL,
    content_hash     VARCHAR(128) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_response_schemas_version ON api_response_schemas (model_version_id);

-- ==================== 6. 用途分类体系 ====================

-- 用途分类（内置 + 自定义）
CREATE TABLE IF NOT EXISTS api_classifications (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code        VARCHAR(64) NOT NULL UNIQUE,
    name        VARCHAR(128) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_builtin  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 端点分类维度（多维：用途/数据/暴露面等）
CREATE TABLE IF NOT EXISTS api_classification_dimensions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    dimension   VARCHAR(64) NOT NULL, -- PURPOSE / DATA_TYPE / EXPOSURE / CUSTOM:*
    value       VARCHAR(128) NOT NULL,
    source      VARCHAR(32) NOT NULL DEFAULT 'AUTO', -- AUTO / MANUAL / AI
    confidence  DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (endpoint_id, dimension)
);

-- 自定义分类法
CREATE TABLE IF NOT EXISTS api_custom_taxonomies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dimension   VARCHAR(64) NOT NULL,
    value       VARCHAR(128) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_by  UUID,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (dimension, value)
);

-- ==================== 7. 身份 / 对象 / 行为 ====================

-- 身份画像（凭据指纹维度，不存明文）
CREATE TABLE IF NOT EXISTS api_identity_profiles (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_fingerprint VARCHAR(128) NOT NULL,
    endpoint_id          UUID NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    auth_type            VARCHAR(32) NOT NULL DEFAULT '',
    request_count        BIGINT NOT NULL DEFAULT 0,
    first_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (identity_fingerprint, endpoint_id)
);

-- 对象模型（BOLA 辅助：对象标识符形态）
CREATE TABLE IF NOT EXISTS api_object_models (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id      UUID NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    object_segment   VARCHAR(255) NOT NULL, -- 归一化段位置或参数名
    identifier_type  VARCHAR(64) NOT NULL DEFAULT 'unknown', -- numeric / uuid / hash / mixed
    example_hash     VARCHAR(128) NOT NULL DEFAULT '',
    entropy_estimate DOUBLE PRECISION,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (endpoint_id, object_segment)
);

-- 行为基线（端点 × 身份 × 窗口）
CREATE TABLE IF NOT EXISTS api_behavior_profiles (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id          UUID NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    identity_fingerprint VARCHAR(128) NOT NULL DEFAULT '',
    window_seconds       INTEGER NOT NULL DEFAULT 3600,
    request_count        BIGINT NOT NULL DEFAULT 0,
    avg_rate             DOUBLE PRECISION NOT NULL DEFAULT 0,
    status_code_dist     JSONB NOT NULL DEFAULT '{}',
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (endpoint_id, identity_fingerprint, window_seconds)
);

-- 调用边（API 图谱/拓扑）
CREATE TABLE IF NOT EXISTS api_call_edges (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    caller_fingerprint VARCHAR(128) NOT NULL DEFAULT '',
    source_endpoint_id UUID REFERENCES api_endpoints(id) ON DELETE SET NULL,
    target_endpoint_id UUID NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    call_count         BIGINT NOT NULL DEFAULT 0,
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_call_edges_target ON api_call_edges (target_endpoint_id);

-- ==================== 8. 风险与运行时 ====================

-- 敏感字段识别
CREATE TABLE IF NOT EXISTS api_sensitive_fields (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id      UUID NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    direction        VARCHAR(16) NOT NULL DEFAULT 'REQUEST', -- REQUEST / RESPONSE
    structured_path  VARCHAR(512) NOT NULL,
    data_type        VARCHAR(64) NOT NULL, -- phone / id_card / bank_card / email / credential / ...
    confidence       DOUBLE PRECISION NOT NULL DEFAULT 0,
    detection_source VARCHAR(32) NOT NULL DEFAULT 'AUTO', -- AUTO / MANUAL
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (endpoint_id, direction, structured_path)
);

-- 运行时发现（Shadow/Zombie/越权/偏离等风险条目）
CREATE TABLE IF NOT EXISTS api_runtime_findings (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id  UUID REFERENCES api_endpoints(id) ON DELETE SET NULL,
    request_id   VARCHAR(64) NOT NULL DEFAULT '',
    finding_type VARCHAR(64) NOT NULL, -- SHADOW / ZOMBIE / DEPRECATED / BOLA / BFLA / SCHEMA_DEVIATION / SENSITIVE_LEAK / ...
    severity     VARCHAR(32) NOT NULL DEFAULT 'INFO', -- INFO / LOW / MEDIUM / HIGH / CRITICAL
    status       VARCHAR(32) NOT NULL DEFAULT 'OPEN', -- OPEN / ACKNOWLEDGED / RESOLVED / FALSE_POSITIVE
    title        VARCHAR(255) NOT NULL DEFAULT '',
    detail       JSONB NOT NULL DEFAULT '{}',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_runtime_findings_endpoint ON api_runtime_findings (endpoint_id, status);
CREATE INDEX IF NOT EXISTS idx_api_runtime_findings_type ON api_runtime_findings (finding_type, severity);

-- Schema 违例记录
CREATE TABLE IF NOT EXISTS api_schema_violations (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id      UUID REFERENCES api_endpoints(id) ON DELETE SET NULL,
    model_version_id UUID REFERENCES api_model_versions(id) ON DELETE SET NULL,
    request_id       VARCHAR(64) NOT NULL DEFAULT '',
    violation_type   VARCHAR(64) NOT NULL, -- undefined_field / type_mismatch / missing_field / ...
    field_path       VARCHAR(512) NOT NULL DEFAULT '',
    expected         VARCHAR(128) NOT NULL DEFAULT '',
    observed         VARCHAR(128) NOT NULL DEFAULT '',
    action_taken     VARCHAR(32) NOT NULL DEFAULT 'OBSERVE',
    occurred_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_schema_violations_endpoint ON api_schema_violations (endpoint_id, occurred_at DESC);

-- 生命周期事件（Shadow/Zombie/Deprecated 判定轨迹）
CREATE TABLE IF NOT EXISTS api_lifecycle_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    from_status VARCHAR(32) NOT NULL DEFAULT '',
    to_status   VARCHAR(32) NOT NULL,
    reason      VARCHAR(255) NOT NULL DEFAULT '',
    actor       VARCHAR(64) NOT NULL DEFAULT 'system', -- system / 用户名
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_lifecycle_events_endpoint ON api_lifecycle_events (endpoint_id, created_at DESC);

-- ==================== 9. 模型评审与规范导入 ====================

-- 模型评审记录
CREATE TABLE IF NOT EXISTS api_model_reviews (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_version_id UUID NOT NULL REFERENCES api_model_versions(id) ON DELETE CASCADE,
    reviewer_id      UUID,
    action           VARCHAR(32) NOT NULL, -- SUBMIT / APPROVE / REJECT
    comment          TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_model_reviews_version ON api_model_reviews (model_version_id);

-- 模型版本差异
CREATE TABLE IF NOT EXISTS api_model_diffs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_version_id UUID NOT NULL REFERENCES api_model_versions(id) ON DELETE CASCADE,
    other_version_id UUID NOT NULL REFERENCES api_model_versions(id) ON DELETE CASCADE,
    diff_json        JSONB NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (model_version_id, other_version_id)
);

-- 规范导入（OpenAPI）
CREATE TABLE IF NOT EXISTS api_import_specs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    format         VARCHAR(32) NOT NULL, -- openapi3 / swagger2
    file_name      VARCHAR(255) NOT NULL DEFAULT '',
    content_hash   VARCHAR(128) NOT NULL,
    spec_json      JSONB NOT NULL,
    endpoint_count INTEGER NOT NULL DEFAULT 0,
    imported_by    UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 规范与运行时对比结果
CREATE TABLE IF NOT EXISTS api_spec_diffs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    spec_id      UUID NOT NULL REFERENCES api_import_specs(id) ON DELETE CASCADE,
    diff_type    VARCHAR(32) NOT NULL, -- MISSING_IN_RUNTIME / MISSING_IN_SPEC / CHANGED
    endpoint_key VARCHAR(560) NOT NULL DEFAULT '',
    detail       JSONB NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_spec_diffs_spec ON api_spec_diffs (spec_id);

-- ==================== 10. 关联约束（环形 FK 在双方建表后补充） ====================
ALTER TABLE api_endpoints
    ADD CONSTRAINT fk_api_endpoints_current_model
    FOREIGN KEY (current_model_version_id) REFERENCES api_model_versions(id) ON DELETE SET NULL;
ALTER TABLE api_model_versions
    ADD CONSTRAINT fk_api_model_versions_request_schema
    FOREIGN KEY (request_schema_id) REFERENCES api_request_schemas(id) ON DELETE SET NULL,
    ADD CONSTRAINT fk_api_model_versions_response_schema_set
    FOREIGN KEY (response_schema_set_id) REFERENCES api_response_schemas(id) ON DELETE SET NULL;

COMMIT;
