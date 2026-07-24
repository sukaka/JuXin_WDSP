-- 全量访问日志（二期）：access_logs 表 + 权限种子 + logging 组系统设置种子
-- 数据流：网关 jiuzhang_guard 写 JSON Lines（脱敏后）→ API 采集器 tail 入库。
-- 表为普通表（不分区），靠 retention_days 定期清理控制体量。
-- request_id 唯一索引为部分索引（排除空串）：未携带 X-Request-Id 的请求 request_id 为空，
-- 空串不参与去重，避免多行空 request_id 冲突。

BEGIN;

-- ---------- 全量访问日志 ----------
CREATE TABLE IF NOT EXISTS access_logs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at             TIMESTAMPTZ  NOT NULL,
    request_id              VARCHAR(64)  NOT NULL DEFAULT '',
    application_id          UUID,
    domain                  VARCHAR(255) NOT NULL DEFAULT '',
    gateway_node_id         VARCHAR(64)  NOT NULL DEFAULT '',
    client_ip               INET,
    client_port             INTEGER,
    request_method          VARCHAR(16)  NOT NULL DEFAULT '',
    request_uri             TEXT         NOT NULL DEFAULT '',
    request_path            TEXT         NOT NULL DEFAULT '',
    query_summary           TEXT         NOT NULL DEFAULT '',
    http_version            VARCHAR(16)  NOT NULL DEFAULT '',
    content_type            VARCHAR(255) NOT NULL DEFAULT '',
    user_agent_summary      VARCHAR(512) NOT NULL DEFAULT '',
    referer_summary         VARCHAR(512) NOT NULL DEFAULT '',
    response_status         INTEGER      NOT NULL DEFAULT 0,
    bytes_in                BIGINT       NOT NULL DEFAULT 0,
    bytes_out               BIGINT       NOT NULL DEFAULT 0,
    duration_ms             INTEGER      NOT NULL DEFAULT 0,
    waf_action              VARCHAR(32)  NOT NULL DEFAULT '',
    request_headers         JSONB        NOT NULL DEFAULT '{}',
    request_body            TEXT         NOT NULL DEFAULT '',
    request_body_truncated  BOOLEAN      NOT NULL DEFAULT FALSE,
    response_headers        JSONB        NOT NULL DEFAULT '{}',
    response_body           TEXT         NOT NULL DEFAULT '',
    response_body_truncated BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_access_logs_occurred_at ON access_logs (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_logs_domain ON access_logs (domain);
CREATE INDEX IF NOT EXISTS idx_access_logs_client_ip ON access_logs (client_ip);
CREATE INDEX IF NOT EXISTS idx_access_logs_response_status ON access_logs (response_status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_access_logs_request_id ON access_logs (request_id) WHERE request_id <> '';

-- ---------- 权限种子 ----------
INSERT INTO permissions (code, name, module, description) VALUES
('access_logs.read',   '查看访问日志', 'access_logs', '查看全量访问日志列表与详情'),
('access_logs.export', '导出访问日志', 'access_logs', '导出全量访问日志')
ON CONFLICT (code) DO NOTHING;

-- 系统管理员与安全管理员：查看 + 导出
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code IN ('SYSTEM_ADMIN', 'SECURITY_ADMIN') AND p.code IN ('access_logs.read', 'access_logs.export')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- ---------- 系统设置种子（logging 组） ----------
-- access_log_enabled 为总开关，默认关闭；请求/响应体留痕默认关闭（体量与敏感度最高）。
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('logging', 'access_log_enabled',       'false', 'boolean', FALSE, '全量访问日志总开关'),
('logging', 'capture_request_headers',  'true',  'boolean', FALSE, '访问日志采集请求头（敏感头掩码）'),
('logging', 'capture_request_body',     'false', 'boolean', FALSE, '访问日志采集请求体（敏感键值掩码）'),
('logging', 'capture_response_headers', 'true',  'boolean', FALSE, '访问日志采集响应头（敏感头掩码）'),
('logging', 'capture_response_body',    'false', 'boolean', FALSE, '访问日志采集响应体（仅文本类）'),
('logging', 'body_limit_kb',            '64',    'integer', FALSE, '访问日志单条头体最大长度（KB）'),
('logging', 'retention_days',           '7',     'integer', FALSE, '访问日志保留天数（到期自动清理）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
