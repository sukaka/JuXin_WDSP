-- 000182 回滚：移除 MCP 目录绑定表（000181 目录表不受影响）。
BEGIN;

DROP TABLE IF EXISTS mcp_catalog_bindings;

COMMIT;
