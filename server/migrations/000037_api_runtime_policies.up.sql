-- 000037：API 端点级运行时策略版本（Runtime Model Compiler 产物，P0-03/P0-21 补全）。
--
-- 生命周期状态机（语义注释与 apimodels/runtime_policy.go 保持一致）：
--   DRAFT       模型 Confirm(→FORMAL) 后由编译器自动创建的编译产物，尚未纳入发布；
--   VALIDATED   模型 Activate 后标记「待发布」（端点当前模型对应的策略，等待下次整站发布生效）；
--   PUBLISHED   预留中间态（已纳入发布内容、尚未确认生效；本波发布成功直接落 ACTIVE，
--               保留该态供后续多阶段生效校验扩展，发布回写 SQL 将其视同待发布集合）；
--   ACTIVE      整站发布成功且生效校验通过，网关当前实际生效的策略版本；
--               同端点旧 ACTIVE 在发布成功同事务迁移为 ROLLED_BACK（退出即生效集合）；
--   ROLLED_BACK 曾生效后退出的版本（被新版本取代或人工回滚退出），作为「已知良好版本」供回滚溯源；
--   FAILED      发布失败，error 记录发布侧失败原因。
--
-- runtime_version 采用「端点内自增 vN」方案（非全局序号）：与 api_model_versions.version_number
-- 的端点维度语义平行、可读性强（v3 即该端点第 3 个编译产物）；
-- 由 (endpoint_id, runtime_version) 唯一约束兜底并发冲突，冲突如实报错不静默重试。
BEGIN;

CREATE TABLE IF NOT EXISTS api_runtime_policies (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id             UUID         NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    source_model_version_id UUID         NOT NULL REFERENCES api_model_versions(id) ON DELETE CASCADE,
    runtime_version         VARCHAR(64)  NOT NULL,              -- 端点内自增 "vN"
    compiler_version        VARCHAR(32)  NOT NULL,              -- 编译器版本（apimodels.CompilerVersion）
    content_json            JSONB        NOT NULL,              -- CompiledEndpointPolicy 规范序列化
    content_hash            VARCHAR(128) NOT NULL,              -- content_json 规范序列化的 sha256
    status                  VARCHAR(32)  NOT NULL DEFAULT 'DRAFT',
    error                   TEXT         NOT NULL DEFAULT '',   -- 发布失败原因（status=FAILED 时）
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT now(),
    published_at            TIMESTAMPTZ,                        -- 最近一次随整站发布成功下发时间
    activated_at            TIMESTAMPTZ,                        -- 进入 ACTIVE 时间
    CONSTRAINT chk_api_runtime_policies_status
        CHECK (status IN ('DRAFT','VALIDATED','PUBLISHED','ACTIVE','ROLLED_BACK','FAILED'))
);

-- 端点内版本唯一（vN 自增的并发兜底）
CREATE UNIQUE INDEX IF NOT EXISTS ux_api_runtime_policies_endpoint_version
    ON api_runtime_policies (endpoint_id, runtime_version);
-- 发布回写/生效查询：按端点 + 状态过滤
CREATE INDEX IF NOT EXISTS idx_api_runtime_policies_endpoint_status
    ON api_runtime_policies (endpoint_id, status);
-- 模型 → 策略溯源（GET /api/v1/api-security/models/{id}/runtime）
CREATE INDEX IF NOT EXISTS idx_api_runtime_policies_model
    ON api_runtime_policies (source_model_version_id);
-- 整站发布结果回写（待发布集合全量扫描）
CREATE INDEX IF NOT EXISTS idx_api_runtime_policies_status
    ON api_runtime_policies (status);

COMMENT ON TABLE api_runtime_policies IS 'API 端点级运行时策略版本（Runtime Model Compiler 产物；DRAFT/VALIDATED/PUBLISHED/ACTIVE/ROLLED_BACK/FAILED 状态机）';

COMMIT;
