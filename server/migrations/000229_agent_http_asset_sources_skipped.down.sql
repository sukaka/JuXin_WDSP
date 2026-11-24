-- 回滚 SKIPPED_NON_API 关联状态：历史跳过行回退为 UNASSIGNED 以满足原 4 值 CHECK 约束。

UPDATE agent_http_asset_sources
SET association_state = 'UNASSIGNED'
WHERE association_state = 'SKIPPED_NON_API';

ALTER TABLE agent_http_asset_sources
    DROP CONSTRAINT IF EXISTS agent_http_asset_sources_association_state_check;

ALTER TABLE agent_http_asset_sources
    ADD CONSTRAINT agent_http_asset_sources_association_state_check
    CHECK (association_state IN ('LINKED', 'UNASSIGNED', 'QUOTA_REJECTED', 'FAILED'));

ALTER TABLE agent_http_asset_sources
    ALTER COLUMN association_state TYPE VARCHAR(16);
