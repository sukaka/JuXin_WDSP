-- 阶段8：端点目录维度（站点/目录组织视图）
-- directory_path = normalized_path 去掉最后一段（/test/php/login → /test/php；/users/{id} → /users；/health → ''）
BEGIN;

ALTER TABLE api_endpoints
    ADD COLUMN IF NOT EXISTS directory_path VARCHAR(512) NOT NULL DEFAULT '';

-- 存量回填：正则去除末尾 /段
UPDATE api_endpoints
SET directory_path = regexp_replace(normalized_path, '/[^/]*$', '')
WHERE directory_path = '' AND normalized_path <> '';

CREATE INDEX IF NOT EXISTS idx_api_endpoints_directory ON api_endpoints (directory_path);

COMMIT;
