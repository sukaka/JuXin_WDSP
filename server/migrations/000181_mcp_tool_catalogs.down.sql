-- 000181 回滚：移除 MCP 工具目录两表。
BEGIN;

DROP TABLE IF EXISTS mcp_catalog_tools;
DROP TABLE IF EXISTS mcp_tool_catalogs;

COMMIT;
