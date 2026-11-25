-- 000241 SSL/HTTPS 加密会话分析：
--   a) access_logs：扩展 5 个可选 TLS/国密加密会话字段（旧行默认空串/FALSE，完全向后兼容）
--   b) tls_handshake_events：存储网关 jiuzhang_tls_mux 采集的全版本 SSL/TLS/TLCP 握手与阻断事件
--   c) permissions / role_permissions：种子化 events.read 权限并授予运维管理员（SECURITY_ADMIN）
BEGIN;

-- a) 全量访问日志表扩展加密会话分析字段
ALTER TABLE access_logs
    ADD COLUMN IF NOT EXISTS tls_protocol         VARCHAR(24) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS tls_cipher_suite     VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS tls_is_gm            BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS tls_ja3              VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS client_hello_version VARCHAR(24) NOT NULL DEFAULT '';

COMMENT ON COLUMN access_logs.tls_protocol IS
    '实际协商的 TLS/TLCP 协议版本（TLCP1.1/TLS1.0~1.3）；明文 HTTP 或旧数据为空串';
COMMENT ON COLUMN access_logs.tls_cipher_suite IS
    '实际协商的密码套件名称（含国密 SM4/SM3 与国际标准套件）；明文 HTTP 或旧数据为空串';
COMMENT ON COLUMN access_logs.tls_is_gm IS
    '是否国密加密会话（SM2/TLCP1.1）；默认 FALSE';
COMMENT ON COLUMN access_logs.tls_ja3 IS
    '客户端 ClientHello JA3 指纹（32 位小写 MD5 十六进制）；明文 HTTP 或旧数据为空串';
COMMENT ON COLUMN access_logs.client_hello_version IS
    'ClientHello 原始检测版本（SSLv2/SSLv2/v3/SSLv3/TLS1.0~1.3/TLCP1.1）；明文 HTTP 或旧数据为空串';

-- b) SSL/HTTPS 加密会话握手事件表
CREATE TABLE IF NOT EXISTS tls_handshake_events (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at         TIMESTAMPTZ NOT NULL,
    gateway_node_id     VARCHAR(64) NOT NULL DEFAULT '',
    application_id      UUID,
    sni                 VARCHAR(255) NOT NULL DEFAULT '',
    client_ip           VARCHAR(64) NOT NULL DEFAULT '',
    client_port         INTEGER     NOT NULL DEFAULT 0,
    server_port         INTEGER     NOT NULL DEFAULT 0,
    detected_protocol   VARCHAR(24) NOT NULL DEFAULT 'UNKNOWN',
    negotiated_protocol VARCHAR(24) NOT NULL DEFAULT '',
    cipher_suite        VARCHAR(64) NOT NULL DEFAULT '',
    is_gm               BOOLEAN     NOT NULL DEFAULT FALSE,
    ja3_hash            VARCHAR(64) NOT NULL DEFAULT '',
    alpn                VARCHAR(64) NOT NULL DEFAULT '',
    action              VARCHAR(32) NOT NULL DEFAULT 'ALLOWED'
                                    CHECK (action IN ('ALLOWED', 'BLOCKED_LEGACY_SSL', 'BLOCKED_PROTOCOL_POLICY', 'HANDSHAKE_FAILED')),
    error_reason        VARCHAR(512) NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_tls_handshake_events_occurred_at
    ON tls_handshake_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_tls_handshake_events_protocol_occurred
    ON tls_handshake_events (detected_protocol, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_tls_handshake_events_action_occurred
    ON tls_handshake_events (action, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_tls_handshake_events_sni_occurred
    ON tls_handshake_events (sni, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_tls_handshake_events_app_occurred
    ON tls_handshake_events (application_id, occurred_at DESC);

COMMENT ON TABLE tls_handshake_events IS
    'SSL/TLS/国密 TLCP 加密会话分析握手事件表（网关 jiuzhang_tls_mux JSONL 采集入库）';

-- c) 加密会话分析只读权限种子（遵循 000100/000232 三权边界：事件中心归属运维管理员 SECURITY_ADMIN）
INSERT INTO permissions (code, name, module, description) VALUES
('events.read', '查看加密会话分析', 'security_events', '查看 SSL/HTTPS 加密会话分析明细与协议汇总统计')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code = 'events.read'
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
