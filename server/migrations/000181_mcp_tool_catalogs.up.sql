-- 000181 MCP 工具目录（NG-MCP G1 批次 B1，设计 docs/nextgen/NG-MCP-g1-toolcall.md §1.3/D3）：
-- mcp_tool_catalogs（目录=服务身份维度）+ mcp_catalog_tools（工具行）两表
-- （000076 api_grpc_descriptors 同迁移两表先例）。
--
-- 语义边界（设计冻结）：
--   - tool_hash = 审批绑定的不可变摘要（五元组（tool_name, tool_version, 规范化
--     描述全文, input_schema, output_schema）域分隔 sha256——产品内部规范化，
--     不宣称 JCS）；同名任何描述/Schema/版本变更 → 重算 tool_hash 且
--     review_status 重置 PENDING_REVIEW（旧审批不继承，NG-T-M02 红线）；
--   - catalog_hash = 排序拼接 APPROVED 工具 tool_hash 的 sha256（发布集摘要；
--     网关装配期重算比对，不符整目录拒装不误断）；
--   - review_status 三态：PENDING_REVIEW（导入与变更恒落）/APPROVED/REJECTED；
--     发布通道只下发 APPROVED 行（PENDING/REJECTED 不出现在快照）；
--   - risk_level 导入缺省 HIGH（未定级按高风险对待，与待审核语义同向；
--     审核时由审核人定级）；approval_required 为数据前向兼容字段（G1 语义
--     =默认拒绝同 HIGH，审批闭环后续子阶段）；
--   - allowed_principals/roles/tenants 空=该维度不约束，非空逐维 AND；
--   - description_preview 截断仅供管理面展示，永不为证据（设计 §1.3 明文）。
BEGIN;

CREATE TABLE IF NOT EXISTS mcp_tool_catalogs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             VARCHAR(128) NOT NULL,
    service_identity VARCHAR(256) NOT NULL,
    protocol_version VARCHAR(32) NOT NULL DEFAULT '2025-11-25',
    source           VARCHAR(32) NOT NULL DEFAULT 'MANUAL_IMPORT',
    status           VARCHAR(16) NOT NULL DEFAULT 'ENABLED',
    catalog_hash     VARCHAR(96) NOT NULL DEFAULT '',
    version          INTEGER NOT NULL DEFAULT 1,
    created_by       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_mcp_tool_catalogs_name UNIQUE (name),
    CONSTRAINT chk_mcp_tool_catalogs_source CHECK (source = 'MANUAL_IMPORT'),
    CONSTRAINT chk_mcp_tool_catalogs_status CHECK (status IN ('ENABLED','DISABLED'))
);

CREATE TABLE IF NOT EXISTS mcp_catalog_tools (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    catalog_id           UUID NOT NULL REFERENCES mcp_tool_catalogs(id) ON DELETE CASCADE,
    tool_name            VARCHAR(128) NOT NULL,
    tool_version         VARCHAR(128) NOT NULL DEFAULT '',
    description_digest   VARCHAR(64) NOT NULL,
    description_preview  VARCHAR(512) NOT NULL DEFAULT '',
    input_schema         JSONB,
    output_schema        JSONB,
    input_schema_digest  VARCHAR(64) NOT NULL DEFAULT '',
    output_schema_digest VARCHAR(64) NOT NULL DEFAULT '',
    tool_hash            VARCHAR(88) NOT NULL,
    capability_tags      JSONB NOT NULL DEFAULT '[]',
    risk_level           VARCHAR(16) NOT NULL DEFAULT 'HIGH',
    data_classification  VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN',
    allowed_principals   JSONB NOT NULL DEFAULT '[]',
    allowed_roles        JSONB NOT NULL DEFAULT '[]',
    allowed_tenants      JSONB NOT NULL DEFAULT '[]',
    approval_required    BOOLEAN NOT NULL DEFAULT false,
    max_calls_per_minute INTEGER NOT NULL DEFAULT 0,
    arg_constraints      JSONB NOT NULL DEFAULT '[]',
    review_status        VARCHAR(16) NOT NULL DEFAULT 'PENDING_REVIEW',
    reviewed_by          TEXT,
    reviewed_at          TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_mcp_catalog_tools_name UNIQUE (catalog_id, tool_name),
    CONSTRAINT chk_mcp_catalog_tools_risk CHECK (risk_level IN ('LOW','MEDIUM','HIGH')),
    CONSTRAINT chk_mcp_catalog_tools_classification CHECK (data_classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','UNKNOWN')),
    CONSTRAINT chk_mcp_catalog_tools_review CHECK (review_status IN ('PENDING_REVIEW','APPROVED','REJECTED')),
    CONSTRAINT chk_mcp_catalog_tools_rate CHECK (max_calls_per_minute >= 0),
    -- 摘要形态锚点（mcp-tool-sha256:v1: + 64 hex = 86 字符；content 为空即非法）
    CONSTRAINT chk_mcp_catalog_tools_hash CHECK (tool_hash ~ '^mcp-tool-sha256:v1:[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_mcp_catalog_tools_catalog ON mcp_catalog_tools (catalog_id, tool_name);
CREATE INDEX IF NOT EXISTS idx_mcp_catalog_tools_review ON mcp_catalog_tools (review_status) WHERE review_status = 'APPROVED';

COMMENT ON TABLE mcp_tool_catalogs IS 'MCP 工具目录（服务身份维度；NG-MCP G1：显式导入+审核态+发布集摘要）';
COMMENT ON TABLE mcp_catalog_tools IS 'MCP 目录工具行（tool_hash 审批绑定不可变摘要；发布只下发 APPROVED）';

COMMIT;
