-- 000245 AI 爬虫治理、Web Bot Auth（RFC 9421）爬虫公钥目录与离线 AI 迷宫诱捕（Phase 9A-2）：
--   a) ai_crawler_directories：Web Bot Auth 爬虫公钥目录（内置离线公共目录元数据 + 管理员自定义/离线导入/手动同步）
--   b) ai_crawl_policies：按应用的 AI 爬虫治理与迷宫诱捕当前草稿策略（application_id UNIQUE + version 乐观锁）
--   c) ai_crawl_policy_versions：不可变策略版本记录（UNIQUE(application_id, version)，携带变更理由留存审计）
--   d) permissions / role_permissions：种子化 ai_crawl.read 与 ai_crawl.manage（遵循 000232 三权边界）
BEGIN;

-- a) Web Bot Auth 爬虫公钥目录
CREATE TABLE IF NOT EXISTS ai_crawler_directories (
    id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            VARCHAR(64)   NOT NULL UNIQUE,
    name            VARCHAR(128)  NOT NULL,
    category        VARCHAR(32)   NOT NULL
                    CHECK (category IN ('SEARCH_ENGINE', 'AI_TRAINING', 'AI_ASSISTANT', 'AI_AGENT', 'UNKNOWN_BOT')),
    signature_agent VARCHAR(512)  NOT NULL DEFAULT '',
    directory_url   VARCHAR(1024) NOT NULL DEFAULT '',
    keys            JSONB         NOT NULL DEFAULT '[]'::jsonb,
    is_builtin      BOOLEAN       NOT NULL DEFAULT FALSE,
    enabled         BOOLEAN       NOT NULL DEFAULT TRUE,
    last_synced_at  TIMESTAMPTZ,
    last_sync_error TEXT          NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_crawler_directories_enabled_category
    ON ai_crawler_directories (enabled, category);

COMMENT ON TABLE ai_crawler_directories IS
    'Web Bot Auth（RFC 9421）爬虫公钥目录（支持内置元数据、离线 JSON 包导入与 SSRF 防护手动同步，仅存公钥）';

-- b) 应用级 AI 爬虫治理与迷宫策略（当前草稿）
CREATE TABLE IF NOT EXISTS ai_crawl_policies (
    id                        UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id            UUID         NOT NULL UNIQUE REFERENCES applications(id) ON DELETE CASCADE,
    mode                      VARCHAR(16)  NOT NULL DEFAULT 'OFF'
                              CHECK (mode IN ('OFF', 'OBSERVE', 'PROTECT')),
    version                   INT          NOT NULL DEFAULT 1,
    default_ai_action         VARCHAR(24)  NOT NULL DEFAULT 'ALLOW'
                              CHECK (default_ai_action IN ('ALLOW', 'RATE_LIMIT', 'CHALLENGE', 'TARPIT', 'HTTP_402', 'BLOCK')),
    content_signal            VARCHAR(512) NOT NULL DEFAULT '',
    verify_web_bot_auth       BOOLEAN      NOT NULL DEFAULT TRUE,
    labyrinth_enabled         BOOLEAN      NOT NULL DEFAULT FALSE,
    labyrinth_inject_links    BOOLEAN      NOT NULL DEFAULT FALSE,
    labyrinth_max_depth       INT          NOT NULL DEFAULT 5,
    labyrinth_max_concurrency INT          NOT NULL DEFAULT 256,
    labyrinth_delay_ms        INT          NOT NULL DEFAULT 150,
    http_402                  JSONB        NOT NULL DEFAULT '{"message":"","price_hint":"","contact_url":"","receipt_header":""}'::jsonb,
    rules                     JSONB        NOT NULL DEFAULT '[]'::jsonb,
    updated_by                VARCHAR(255) NOT NULL DEFAULT '',
    created_at                TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE ai_crawl_policies IS
    '应用级 AI 爬虫治理策略草稿（Content-Signal、Web Bot Auth 验签、分级处置、HTTP 402 与离线 AI 迷宫诱捕）';

-- c) 应用级 AI 爬虫治理策略不可变版本记录
CREATE TABLE IF NOT EXISTS ai_crawl_policy_versions (
    id                        UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id            UUID         NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    version                   INT          NOT NULL,
    mode                      VARCHAR(16)  NOT NULL
                              CHECK (mode IN ('OFF', 'OBSERVE', 'PROTECT')),
    default_ai_action         VARCHAR(24)  NOT NULL
                              CHECK (default_ai_action IN ('ALLOW', 'RATE_LIMIT', 'CHALLENGE', 'TARPIT', 'HTTP_402', 'BLOCK')),
    content_signal            VARCHAR(512) NOT NULL DEFAULT '',
    verify_web_bot_auth       BOOLEAN      NOT NULL DEFAULT TRUE,
    labyrinth_enabled         BOOLEAN      NOT NULL DEFAULT FALSE,
    labyrinth_inject_links    BOOLEAN      NOT NULL DEFAULT FALSE,
    labyrinth_max_depth       INT          NOT NULL DEFAULT 5,
    labyrinth_max_concurrency INT          NOT NULL DEFAULT 256,
    labyrinth_delay_ms        INT          NOT NULL DEFAULT 150,
    http_402                  JSONB        NOT NULL DEFAULT '{}'::jsonb,
    rules                     JSONB        NOT NULL DEFAULT '[]'::jsonb,
    reason                    TEXT         NOT NULL,
    created_by                VARCHAR(255) NOT NULL DEFAULT '',
    created_at                TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (application_id, version)
);

COMMENT ON TABLE ai_crawl_policy_versions IS
    '应用级 AI 爬虫治理策略不可变版本历史（每次草稿保存追加一行，供版本溯源与审计对照）';

-- d) 权限种子（遵循 000232 三权边界：业务防护策略归运维管理员 SECURITY_ADMIN，审计管理员 AUDIT_ADMIN 只读）
INSERT INTO permissions (code, name, module, description) VALUES
('ai_crawl.read', '查看AI爬虫治理', 'security', '查看 Web Bot Auth 爬虫公钥目录与应用级 AI 爬虫治理策略'),
('ai_crawl.manage', '管理AI爬虫治理', 'security', '管理爬虫公钥目录（新增/编辑/离线导入/手动同步）与应用级 AI 爬虫治理策略')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('ai_crawl.read', 'ai_crawl.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('ai_crawl.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- e) 内置公共 AI / 搜索引擎爬虫目录元数据种子（离线默认 keys 为空数组，不含任何私钥，可通过离线导入或手动同步填充公钥）
INSERT INTO ai_crawler_directories (slug, name, category, signature_agent, directory_url, keys, is_builtin, enabled) VALUES
('openai-chatgpt-agent', 'OpenAI ChatGPT Agent', 'AI_AGENT', 'https://chatgpt.com', 'https://chatgpt.com/.well-known/http-message-signatures-directory', '[]'::jsonb, TRUE, TRUE),
('openai-gptbot', 'OpenAI GPTBot', 'AI_TRAINING', 'https://openai.com', '', '[]'::jsonb, TRUE, TRUE),
('anthropic-claudebot', 'Anthropic ClaudeBot', 'AI_TRAINING', 'https://anthropic.com', '', '[]'::jsonb, TRUE, TRUE),
('perplexity-bot', 'PerplexityBot', 'AI_ASSISTANT', 'https://www.perplexity.ai', '', '[]'::jsonb, TRUE, TRUE),
('google-extended', 'Google-Extended', 'AI_TRAINING', 'https://google.com', '', '[]'::jsonb, TRUE, TRUE),
('googlebot-search', 'Googlebot', 'SEARCH_ENGINE', 'https://google.com', '', '[]'::jsonb, TRUE, TRUE),
('bingbot-search', 'Bingbot', 'SEARCH_ENGINE', 'https://www.bing.com', '', '[]'::jsonb, TRUE, TRUE)
ON CONFLICT (slug) DO NOTHING;

COMMIT;
