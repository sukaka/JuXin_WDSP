-- 扩展 agent_http_asset_sources.association_state 支持 SKIPPED_NON_API：
-- v2（及 v1 静态资源兜底）在命中非 API 或静态资源过滤规则时不再写入 api_endpoints，
-- 来源关系仍留存便于审计追踪，且不占用 API 资产表与授权端点配额。

ALTER TABLE agent_http_asset_sources
    ALTER COLUMN association_state TYPE VARCHAR(32);

ALTER TABLE agent_http_asset_sources
    DROP CONSTRAINT IF EXISTS agent_http_asset_sources_association_state_check;

ALTER TABLE agent_http_asset_sources
    ADD CONSTRAINT agent_http_asset_sources_association_state_check
    CHECK (association_state IN ('LINKED', 'UNASSIGNED', 'QUOTA_REJECTED', 'FAILED', 'SKIPPED_NON_API'));
