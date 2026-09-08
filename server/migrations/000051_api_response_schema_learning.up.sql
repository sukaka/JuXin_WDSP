-- 000051 响应 Schema 学习生产方（W5-A / P0-06）：api_response_schemas 运行时学习列补齐。
--
-- 背景：api_response_schemas 自 000018 建表起只有版本化载体语义
-- （model_version_id NOT NULL + status_code + schema_json + content_hash），无生产写入方。
-- 网关响应相位现上报 response_observations（一级字段路径→类型 + status_code/content_type/
-- body_size，证据纪律不落值），采集端按 端点×状态码 合并 UPSERT 为运行时学习行
-- （model_version_id 为空）；模型版本确认时按版本物化快照行（model_version_id 关联版本）。
BEGIN;

ALTER TABLE api_response_schemas
    ALTER COLUMN model_version_id DROP NOT NULL,
    ADD COLUMN IF NOT EXISTS endpoint_key VARCHAR(560),
    ADD COLUMN IF NOT EXISTS first_seen   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_seen    TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS sample_count BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS updated_at   TIMESTAMPTZ NOT NULL DEFAULT now();

-- 存量行回填（该表此前无生产写入方，防御性回填，正常为空表）
UPDATE api_response_schemas SET first_seen = created_at, last_seen = created_at WHERE first_seen IS NULL;

-- 运行时学习行唯一约束：仅覆盖 model_version_id 为空的运行时行（版本快照行不参与合并，
-- 同端点同状态码可存在多份不同版本的快照）
CREATE UNIQUE INDEX IF NOT EXISTS ux_api_response_schemas_runtime
    ON api_response_schemas (endpoint_key, status_code)
    WHERE endpoint_key IS NOT NULL AND model_version_id IS NULL;

COMMENT ON COLUMN api_response_schemas.endpoint_key IS '运行时学习行端点键（空 = 版本化载体/快照行）';
COMMENT ON COLUMN api_response_schemas.sample_count IS '运行时学习样本数（版本快照行复制自学习行）';

COMMIT;
