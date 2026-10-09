-- 000182 MCP 目录绑定（NG-MCP G1 批次 B1，设计 §1.3/§1.14）：
-- 应用 × endpoint_path（精确匹配大小写敏感，绑定驱动识别承载）× 目录 × 模式。
--
-- 语义边界（设计冻结）：
--   - 绑定驱动识别：请求命中本应用登记的 endpoint_path（精确匹配）且方法 POST
--     且 Content-Type JSON 族 → 进入 mcpguard 评估；绑定缺失 = 零行为；
--   - mode OBSERVE（缺省只记录）| PROTECT（tools/call 违规按设计 §1.11 协议化
--     执行（JSON-RPC 错误对象）；含任一 PROTECT 绑定的快照能力门 required
--     protocols.mcp=acl_v1 + detectors.mcp.toolcall=mcp/2）；
--   - 目录删除级联删绑定（FK CASCADE）；应用删除级联；同（应用,endpoint_path）
--     恰一条绑定（唯一索引）；version 乐观锁（写操作携带比对，不匹配 409）。
BEGIN;

CREATE TABLE IF NOT EXISTS mcp_catalog_bindings (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    endpoint_path  TEXT NOT NULL,
    catalog_id     UUID NOT NULL REFERENCES mcp_tool_catalogs(id) ON DELETE CASCADE,
    mode           VARCHAR(16) NOT NULL DEFAULT 'OBSERVE',
    version        INTEGER NOT NULL DEFAULT 1,
    created_by     TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_mcp_catalog_bindings_mode CHECK (mode IN ('OBSERVE','PROTECT')),
    CONSTRAINT chk_mcp_catalog_bindings_path
        CHECK (endpoint_path LIKE '/%' AND length(endpoint_path) <= 1024)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_mcp_catalog_bindings_app_path
    ON mcp_catalog_bindings (application_id, endpoint_path);
CREATE INDEX IF NOT EXISTS idx_mcp_catalog_bindings_catalog
    ON mcp_catalog_bindings (catalog_id);

COMMENT ON TABLE mcp_catalog_bindings IS 'MCP 目录绑定（应用×endpoint_path×目录×模式；绑定驱动识别；NG-MCP G1）';

COMMIT;
