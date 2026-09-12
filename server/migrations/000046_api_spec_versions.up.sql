-- API 安全补全第三波（W3-C 规范中心增强）：api_import_specs 版本状态机。
--   1) 新增 name / version_no / status / parent_id / activated_at 列；
--   2) 存量数据回填：name 取 file_name → spec_json.info.title → unnamed-<hash8>，
--      同名多行按 created_at 升序编版本号，仅最新版保持 ACTIVE，其余降为 HISTORICAL；
--   3) 唯一索引 (name, version_no) + 单 ACTIVE 部分唯一索引；
--   4) 新增权限点 api_spec.manage（激活规范版本），授权口径与 000019/000041 一致。
BEGIN;

ALTER TABLE api_import_specs
    ADD COLUMN IF NOT EXISTS name         VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS version_no   INTEGER      NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS status       TEXT         NOT NULL DEFAULT 'ACTIVE',
    ADD COLUMN IF NOT EXISTS parent_id    UUID REFERENCES api_import_specs(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ;

ALTER TABLE api_import_specs
    ADD CONSTRAINT chk_api_import_specs_status
    CHECK (status IN ('DRAFT', 'ACTIVE', 'HISTORICAL', 'INVALID', 'ARCHIVED'));

-- name 回填（优先级：file_name > info.title > unnamed-<内容哈希前8位>）
UPDATE api_import_specs SET name = btrim(file_name) WHERE name = '' AND btrim(file_name) <> '';
UPDATE api_import_specs SET name = btrim(spec_json->'info'->>'title')
WHERE name = '' AND btrim(COALESCE(spec_json->'info'->>'title', '')) <> '';
UPDATE api_import_specs SET name = 'unnamed-' || substr(content_hash, 1, 8) WHERE name = '';

-- 同名多行按导入先后编版本号（最旧为 v1）
WITH ranked AS (
    SELECT id, row_number() OVER (PARTITION BY name ORDER BY created_at, id) AS rn
    FROM api_import_specs
)
UPDATE api_import_specs s SET version_no = r.rn FROM ranked r WHERE s.id = r.id;

-- 同名仅最新版保持 ACTIVE，其余降为 HISTORICAL；现存 ACTIVE 视为已激活
UPDATE api_import_specs s SET status = 'HISTORICAL'
WHERE EXISTS (SELECT 1 FROM api_import_specs n WHERE n.name = s.name AND n.version_no > s.version_no);
UPDATE api_import_specs SET activated_at = created_at WHERE status = 'ACTIVE' AND activated_at IS NULL;

-- 同规范维度版本唯一；同规范同一时间仅一个 ACTIVE 版本
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_import_specs_name_version ON api_import_specs (name, version_no);
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_import_specs_active_name ON api_import_specs (name) WHERE status = 'ACTIVE';
CREATE INDEX IF NOT EXISTS idx_api_import_specs_status ON api_import_specs (status);

-- 规范版本管理权限点（激活/切换 ACTIVE）
INSERT INTO permissions (code, name, module, description) VALUES
('api_spec.manage', '管理API规范版本', 'api', '激活/切换API规范版本')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：含规范版本管理（与 000019 口径一致，AUDIT_ADMIN/SYSTEM_ADMIN 不授权）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('api_spec.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
