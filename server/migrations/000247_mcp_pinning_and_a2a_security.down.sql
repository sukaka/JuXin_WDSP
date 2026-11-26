-- 回滚 000247：移除 api_a2a 权限种子、A2A 四张表及 MCP 工具钉扎与绑定扩展列
BEGIN;

DELETE FROM role_permissions
WHERE permission_id IN (SELECT id FROM permissions WHERE code IN ('api_a2a.read', 'api_a2a.manage'));

DELETE FROM permissions WHERE code IN ('api_a2a.read', 'api_a2a.manage');

DROP TABLE IF EXISTS api_a2a_events;
DROP TABLE IF EXISTS api_a2a_agents;
DROP TABLE IF EXISTS api_a2a_policy_versions;
DROP TABLE IF EXISTS api_a2a_policies;

ALTER TABLE mcp_catalog_bindings
    DROP CONSTRAINT IF EXISTS chk_mcp_catalog_bindings_response_guard_mode,
    DROP COLUMN IF EXISTS oauth_resource_metadata_url,
    DROP COLUMN IF EXISTS require_session_binding,
    DROP COLUMN IF EXISTS response_guard_mode;

ALTER TABLE mcp_catalog_tools
    DROP CONSTRAINT IF EXISTS chk_mcp_catalog_tools_pin_enforcement,
    DROP COLUMN IF EXISTS pin_enforcement,
    DROP COLUMN IF EXISTS pinned_definition_hash,
    DROP COLUMN IF EXISTS description;

COMMIT;
