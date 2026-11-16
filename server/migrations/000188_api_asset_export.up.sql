-- API 资产详细导出：导出权限 + Agent HTTP 来源分类证据。
-- api_asset.export 仅授予 SECURITY_ADMIN（按 000100 三权重划）；历史来源行不回填分类证据。

BEGIN;

ALTER TABLE agent_http_asset_sources
    ADD COLUMN IF NOT EXISTS classification_is_api BOOLEAN,
    ADD COLUMN IF NOT EXISTS classification_confidence DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS classification_level VARCHAR(32) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS classification_signals JSONB NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS classified_at TIMESTAMPTZ;

INSERT INTO permissions (code, name, module, description) VALUES
('api_asset.export', '导出API资产', 'api', '导出API端点详细档案与资产清单')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code = 'api_asset.export'
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
