-- 回滚 API 资产导出权限与 Agent HTTP 来源分类证据列。

BEGIN;

DELETE FROM role_permissions
WHERE permission_id IN (SELECT id FROM permissions WHERE code='api_asset.export');

DELETE FROM permissions WHERE code='api_asset.export';

ALTER TABLE agent_http_asset_sources
    DROP COLUMN IF EXISTS classification_is_api,
    DROP COLUMN IF EXISTS classification_confidence,
    DROP COLUMN IF EXISTS classification_level,
    DROP COLUMN IF EXISTS classification_signals,
    DROP COLUMN IF EXISTS classified_at;

COMMIT;
