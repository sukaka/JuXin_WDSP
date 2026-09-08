-- 000031：三微模型增强批次
-- 1) 参数值观测聚合表（网关脱敏观测 → 回填 statistics 长度/值域/基数）
-- 2) 身份画像表已有（000018），本迁移不改结构；写入方在 Go 聚合任务中接通
-- 3) 参数关系表已有；候选生成在 Go 中写入

CREATE TABLE IF NOT EXISTS api_parameter_value_obs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_key     VARCHAR(560) NOT NULL,
    location         VARCHAR(32)  NOT NULL,
    structured_path  VARCHAR(512) NOT NULL DEFAULT '',
    parameter_name   VARCHAR(255) NOT NULL,
    sample_count     BIGINT       NOT NULL DEFAULT 0,
    min_length       INT,
    max_length       INT,
    min_value        DOUBLE PRECISION,
    max_value        DOUBLE PRECISION,
    distinct_count   INT,
    value_hashes     JSONB        NOT NULL DEFAULT '[]'::jsonb,
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT ux_api_parameter_value_obs UNIQUE (endpoint_key, location, structured_path, parameter_name)
);

CREATE INDEX IF NOT EXISTS idx_api_parameter_value_obs_endpoint
    ON api_parameter_value_obs (endpoint_key);

COMMENT ON TABLE api_parameter_value_obs IS '参数值脱敏观测聚合（网关上报 length/hash/num，不落明文）';
