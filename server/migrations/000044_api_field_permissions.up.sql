-- 000044 API 字段权限（WDSP 阶段8 P0-17 Field Authorization / Mass Assignment 补全，W3-A 分片）。
--
-- 背景：docs/API_SECURITY_CURRENT_STATE.md P0-17 节盘点确认字段级授权整体缺失：
-- 学习侧已有参数物化与约束词汇（QUERY/PATH 参数、regex/nullable 等），但无
-- 「某角色对某字段可读/可写」的权限实体，Mass Assignment 与字段越权读取无判定基线。
-- 本迁移建立 api_field_permissions：
--   field_path  字段路径（与学习/敏感侧 structured_path 同风格：location.a.b）；
--   direction   REQUEST（请求侧，防 Mass Assignment）/ RESPONSE（响应侧，防越权读取）；
--   attribute   字段属性七值：READABLE/WRITABLE/READ_ONLY/ADMIN_WRITABLE/
--               SERVER_GENERATED/SENSITIVE/FORBIDDEN（判定语义由评估方组合，表只存基线）；
--   role        NULL = 默认（对该端点全部角色生效），非空 = 指定角色覆盖默认行；
--   tenant      NULL = 默认（全部租户），非空 = 指定租户覆盖。
-- 角色/租户覆盖行的优先级合并（角色行 > 租户行 > 默认行）由读取方实现，本迁移只建实体。
BEGIN;

CREATE TABLE IF NOT EXISTS api_field_permissions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    field_path  TEXT NOT NULL,                       -- 字段路径（location.a.b 风格）
    direction   TEXT NOT NULL
                CHECK (direction IN ('REQUEST','RESPONSE')),
    attribute   TEXT NOT NULL
                CHECK (attribute IN ('READABLE','WRITABLE','READ_ONLY','ADMIN_WRITABLE',
                                     'SERVER_GENERATED','SENSITIVE','FORBIDDEN')),
    role        TEXT,                                -- NULL = 默认；非空 = 角色覆盖
    tenant      TEXT,                                -- NULL = 默认；非空 = 租户覆盖
    created_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- 唯一性含 NULL 归一表达式（NULL 与 '' 视为同一默认行）；PG 唯一约束不支持表达式，
-- 用唯一索引实现（CRUD 捕获 23505 映射为冲突错误）。
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_field_permissions
    ON api_field_permissions (endpoint_id, field_path, direction, COALESCE(role, ''), COALESCE(tenant, ''));
CREATE INDEX IF NOT EXISTS idx_api_field_permissions_endpoint ON api_field_permissions (endpoint_id, direction);

COMMIT;
