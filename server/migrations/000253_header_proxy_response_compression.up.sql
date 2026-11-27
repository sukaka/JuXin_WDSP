-- 应用级 HTTP 代理响应压缩（Caddy encode：gzip / zstd，默认关闭以保持存量站点行为不变）
BEGIN;

ALTER TABLE app_header_configs
    ADD COLUMN IF NOT EXISTS response_compression_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS response_compression_encodings VARCHAR(32) NOT NULL DEFAULT 'zstd,gzip';

COMMIT;
