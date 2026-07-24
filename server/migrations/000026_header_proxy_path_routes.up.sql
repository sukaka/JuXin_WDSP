-- 站点级 HTTP 头合规与代理配置 + 路径粒度转发（每应用一份，经配置发布下发）
BEGIN;

-- 头合规与代理配置（应用一对一）
CREATE TABLE IF NOT EXISTS app_header_configs (
    application_id          UUID PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
    -- 基础头处理：Server / X-Author / X-Powered-By（keep|hide|replace）
    server_action           VARCHAR(16) NOT NULL DEFAULT 'keep',
    server_value            VARCHAR(255) NOT NULL DEFAULT '',
    x_author_action         VARCHAR(16) NOT NULL DEFAULT 'keep',
    x_author_value          VARCHAR(255) NOT NULL DEFAULT '',
    x_powered_by_action     VARCHAR(16) NOT NULL DEFAULT 'keep',
    x_powered_by_value      VARCHAR(255) NOT NULL DEFAULT '',
    -- X-Frame-Options：default(默认 DENY) | inherit(透传源站) | deny | sameorigin | allow_from
    x_frame_options         VARCHAR(16) NOT NULL DEFAULT 'default',
    x_frame_options_url     VARCHAR(512) NOT NULL DEFAULT '',
    x_xss_protection        BOOLEAN NOT NULL DEFAULT FALSE,
    vary_user_agent         BOOLEAN NOT NULL DEFAULT FALSE,
    -- HSTS
    hsts_enabled            BOOLEAN NOT NULL DEFAULT FALSE,
    hsts_max_age            INTEGER NOT NULL DEFAULT 31536000,
    -- CSP：off | preset(预设基础档) | custom
    csp_mode                VARCHAR(16) NOT NULL DEFAULT 'off',
    csp_value               TEXT NOT NULL DEFAULT '',
    -- 说明：下划线请求头由网关内核（Caddy 2.11+，GHSA-f59h-q822-g45g）在入口强制丢弃，
    -- 始终生效、无需配置，故不提供开关列。
    -- HTTP 代理配置
    response_buffering      BOOLEAN NOT NULL DEFAULT FALSE,   -- 响应缓冲（flush_interval=-1）
    xff_overwrite           BOOLEAN NOT NULL DEFAULT FALSE,   -- X-Forwarded-For 上一跳覆盖
    host_strip_port         BOOLEAN NOT NULL DEFAULT FALSE,   -- Host 不包含端口
    accept_encoding_off     BOOLEAN NOT NULL DEFAULT FALSE,   -- 关闭压缩协商（Accept-Encoding: identity）
    redirect_port_rewrite   BOOLEAN NOT NULL DEFAULT FALSE,   -- 302 Location 端口改写为接入端口
    -- 自定义头修改规则 [{name, method(set|add|delete), value}]
    custom_request_rules    JSONB NOT NULL DEFAULT '[]',
    custom_response_rules   JSONB NOT NULL DEFAULT '[]',
    updated_by              UUID,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    version                 INTEGER NOT NULL DEFAULT 1
);

-- 路径粒度转发（应用内路径前缀 → 指定源站，可剥离前缀）
CREATE TABLE IF NOT EXISTS app_path_routes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id  UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    path_prefix     VARCHAR(512) NOT NULL,
    upstream_scheme VARCHAR(8)  NOT NULL DEFAULT 'http',
    upstream_host   VARCHAR(255) NOT NULL,
    upstream_port   INTEGER NOT NULL,
    strip_prefix    BOOLEAN NOT NULL DEFAULT FALSE,  -- false=保留路径转发，true=剥离前缀
    priority        INTEGER NOT NULL DEFAULT 100,    -- 数值小者优先；同优先级长前缀优先
    status          VARCHAR(16) NOT NULL DEFAULT 'ENABLED',  -- ENABLED / DISABLED
    description     VARCHAR(255) NOT NULL DEFAULT '',
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    version         INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_app_path_routes_app ON app_path_routes (application_id, status, priority);
CREATE UNIQUE INDEX IF NOT EXISTS ux_app_path_routes_prefix ON app_path_routes (application_id, path_prefix, upstream_host, upstream_port);

COMMIT;
