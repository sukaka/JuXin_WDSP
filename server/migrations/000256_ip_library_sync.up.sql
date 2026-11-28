-- 000256 IP 库（GeoIP 归属地库 + 威胁情报 IP 黑名单库）离线/在线定时更新与热加载：
--   a) geoip_slot_configs：5 个 GeoIP 槽位配置与当前活跃摘要（默认全部 OFFLINE_ONLY / 停用定时）
--   b) geoip_sync_runs：GeoIP 离线上传/在线同步/回滚/HA 推送执行流水
--   c) threat_intel_feeds：威胁情报 IP 黑名单多源订阅配置（预置 CC0 源 feodo / sslbl，默认关闭）
--   d) threat_intel_sync_runs：威胁情报在线拉取与离线导入对账历史
--   e) system_settings：ip_library（出站白名单/代理）、geoip（定时/HA/MaxMind 凭据）、threat_intel（定时/熔断）
--   f) permissions & role_permissions：遵循 000232 三权边界（SECURITY_ADMIN 全量，AUDIT_ADMIN 只读）
BEGIN;

-- a) GeoIP 槽位配置表
CREATE TABLE IF NOT EXISTS geoip_slot_configs (
    slot               VARCHAR(32)  PRIMARY KEY
                       CHECK (slot IN ('ip2region_v4', 'ip2region_v6', 'dbip_city', 'city_ipv6', 'country')),
    display_name       VARCHAR(128) NOT NULL,
    enabled            BOOLEAN      NOT NULL DEFAULT FALSE,
    source_mode        VARCHAR(24)  NOT NULL DEFAULT 'OFFLINE_ONLY'
                       CHECK (source_mode IN ('OFFLINE_ONLY', 'OFFICIAL', 'CUSTOM_URL')),
    official_preset    VARCHAR(64)  NOT NULL DEFAULT '',
    custom_url         TEXT         NOT NULL DEFAULT '',
    active_filename    VARCHAR(255) NOT NULL DEFAULT '',
    active_sha256      VARCHAR(64)  NOT NULL DEFAULT '',
    active_size_bytes  BIGINT       NOT NULL DEFAULT 0 CHECK (active_size_bytes >= 0),
    active_source_type VARCHAR(24)  NOT NULL DEFAULT 'BUILTIN'
                       CHECK (active_source_type IN ('BUILTIN', 'ONLINE', 'OFFLINE', 'HA_SYNC', 'ROLLBACK')),
    etag               VARCHAR(255) NOT NULL DEFAULT '',
    last_modified      VARCHAR(128) NOT NULL DEFAULT '',
    last_updated_at    TIMESTAMPTZ  NULL,
    last_status        VARCHAR(24)  NOT NULL DEFAULT 'IDLE'
                       CHECK (last_status IN ('IDLE', 'SUCCESS', 'SKIPPED_UNCHANGED', 'PARTIAL_HA_FAILED', 'FAILED')),
    last_error         TEXT         NOT NULL DEFAULT '',
    updated_by         UUID         NULL REFERENCES users(id) ON DELETE SET NULL,
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE geoip_slot_configs IS
    'GeoIP 离线归属地库槽位配置与活跃文件摘要（ip2region / DB-IP Lite / MaxMind GeoLite2）';

INSERT INTO geoip_slot_configs (slot, display_name, enabled, source_mode, official_preset) VALUES
('ip2region_v4', 'ip2region IPv4（国内省市/运营商）', FALSE, 'OFFLINE_ONLY', 'ip2region_v4'),
('ip2region_v6', 'ip2region IPv6（国内省市/运营商）', FALSE, 'OFFLINE_ONLY', 'ip2region_v6'),
('dbip_city',    '全球城市库（DB-IP Lite / MaxMind GeoLite2 City）', FALSE, 'OFFLINE_ONLY', 'dbip_city_lite'),
('city_ipv6',    'IPv6 专用城市库（MMDB）', FALSE, 'OFFLINE_ONLY', ''),
('country',      '国家码回退库（DB-IP / GeoLite2 / Country MMDB）', FALSE, 'OFFLINE_ONLY', 'dbip_country_lite')
ON CONFLICT (slot) DO NOTHING;

-- b) GeoIP 更新/上传/回滚/HA 同步流水表
CREATE TABLE IF NOT EXISTS geoip_sync_runs (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    slot            VARCHAR(32)  NOT NULL
                    CHECK (slot IN ('ip2region_v4', 'ip2region_v6', 'dbip_city', 'city_ipv6', 'country')),
    trigger_type    VARCHAR(24)  NOT NULL
                    CHECK (trigger_type IN ('SCHEDULED', 'MANUAL', 'OFFLINE_UPLOAD', 'ROLLBACK', 'HA_RESYNC')),
    status          VARCHAR(24)  NOT NULL
                    CHECK (status IN ('SUCCESS', 'SKIPPED_UNCHANGED', 'PARTIAL_HA_FAILED', 'FAILED')),
    source_label    VARCHAR(255) NOT NULL DEFAULT '',
    previous_sha256 VARCHAR(64)  NOT NULL DEFAULT '',
    new_sha256      VARCHAR(64)  NOT NULL DEFAULT '',
    file_size_bytes BIGINT       NOT NULL DEFAULT 0 CHECK (file_size_bytes >= 0),
    ha_results_json JSONB        NOT NULL DEFAULT '[]'::jsonb,
    error_message   TEXT         NOT NULL DEFAULT '',
    operator_id     UUID         NULL REFERENCES users(id) ON DELETE SET NULL,
    started_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE geoip_sync_runs IS
    'GeoIP 归属地库更新、离线上传、回滚与 HA 备节点同步流水记录';

CREATE INDEX IF NOT EXISTS idx_geoip_sync_runs_started_at
    ON geoip_sync_runs (started_at DESC);

CREATE INDEX IF NOT EXISTS idx_geoip_sync_runs_slot_started
    ON geoip_sync_runs (slot, started_at DESC);

-- c) 威胁情报 IP 黑名单订阅源表
CREATE TABLE IF NOT EXISTS threat_intel_feeds (
    id                   UUID             PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_key             VARCHAR(32)      NOT NULL UNIQUE
                         CHECK (feed_key ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
    name                 VARCHAR(128)     NOT NULL,
    description          TEXT             NOT NULL DEFAULT '',
    is_builtin           BOOLEAN          NOT NULL DEFAULT FALSE,
    enabled              BOOLEAN          NOT NULL DEFAULT FALSE,
    source_mode          VARCHAR(24)      NOT NULL DEFAULT 'OFFLINE_ONLY'
                         CHECK (source_mode IN ('OFFLINE_ONLY', 'OFFICIAL', 'CUSTOM_URL')),
    official_preset      VARCHAR(64)      NOT NULL DEFAULT '',
    custom_url           TEXT             NOT NULL DEFAULT '',
    format               VARCHAR(16)      NOT NULL DEFAULT 'text'
                         CHECK (format IN ('text', 'csv')),
    allow_cidr           BOOLEAN          NOT NULL DEFAULT FALSE,
    ttl_days             INTEGER          NOT NULL DEFAULT 30
                         CHECK (ttl_days >= 0 AND ttl_days <= 3650),
    schedule_cron        VARCHAR(64)      NOT NULL DEFAULT '0 */6 * * *',
    min_entries_guard    BOOLEAN          NOT NULL DEFAULT TRUE,
    max_drop_ratio       DOUBLE PRECISION NOT NULL DEFAULT 0.80
                         CHECK (max_drop_ratio >= 0.0 AND max_drop_ratio <= 1.0),
    etag                 VARCHAR(255)     NOT NULL DEFAULT '',
    last_modified        VARCHAR(128)     NOT NULL DEFAULT '',
    last_content_sha256  VARCHAR(64)      NOT NULL DEFAULT '',
    active_rule_count    INTEGER          NOT NULL DEFAULT 0 CHECK (active_rule_count >= 0),
    consecutive_failures INTEGER          NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    circuit_open         BOOLEAN          NOT NULL DEFAULT FALSE,
    last_sync_at         TIMESTAMPTZ      NULL,
    last_status          VARCHAR(24)      NOT NULL DEFAULT 'IDLE'
                         CHECK (last_status IN ('IDLE', 'SUCCESS', 'SKIPPED_NOT_MODIFIED', 'GUARD_ABORTED', 'FAILED')),
    last_error           TEXT             NOT NULL DEFAULT '',
    created_by           UUID             NULL REFERENCES users(id) ON DELETE SET NULL,
    updated_by           UUID             NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at           TIMESTAMPTZ      NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ      NOT NULL DEFAULT now()
);

COMMENT ON TABLE threat_intel_feeds IS
    '威胁情报 IP 黑名单多源订阅配置（支持预置 CC0 官方源、自定义内网/商业源及离线快照）';

INSERT INTO threat_intel_feeds (feed_key, name, description, is_builtin, enabled, source_mode, official_preset, format, ttl_days, schedule_cron) VALUES
('feodo', 'abuse.ch Feodo C2 IP 清单', '僵尸网络控制端（C2）推荐封禁 IPv4 列表（CC0 许可，默认关闭）', TRUE, FALSE, 'OFFICIAL', 'feodo', 'text', 30, '0 */6 * * *'),
('sslbl', 'abuse.ch SSLBL 恶意 C2 IP 清单', '恶意 SSL 证书关联僵尸网络 C2 IPv4 列表（CC0 许可，默认关闭）', TRUE, FALSE, 'OFFICIAL', 'sslbl', 'text', 30, '0 */6 * * *')
ON CONFLICT (feed_key) DO NOTHING;

-- d) 威胁情报同步与离线导入对账历史表
CREATE TABLE IF NOT EXISTS threat_intel_sync_runs (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_key         VARCHAR(32) NOT NULL,
    trigger_type     VARCHAR(24) NOT NULL
                     CHECK (trigger_type IN ('SCHEDULED', 'MANUAL', 'OFFLINE_IMPORT')),
    batch_id         VARCHAR(64) NOT NULL DEFAULT '',
    status           VARCHAR(24) NOT NULL
                     CHECK (status IN ('SUCCESS', 'SKIPPED_NOT_MODIFIED', 'GUARD_ABORTED', 'FAILED')),
    total_parsed     INTEGER     NOT NULL DEFAULT 0,
    added            INTEGER     NOT NULL DEFAULT 0,
    refreshed        INTEGER     NOT NULL DEFAULT 0,
    expired          INTEGER     NOT NULL DEFAULT 0,
    skipped_conflict INTEGER     NOT NULL DEFAULT 0,
    invalid_count    INTEGER     NOT NULL DEFAULT 0,
    published        BOOLEAN     NOT NULL DEFAULT FALSE,
    error_message    TEXT        NOT NULL DEFAULT '',
    operator_id      UUID        NULL REFERENCES users(id) ON DELETE SET NULL,
    started_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE threat_intel_sync_runs IS
    '威胁情报 IP 黑名单在线定时拉取与离线快照导入对账流水表';

CREATE INDEX IF NOT EXISTS idx_threat_intel_sync_runs_started_at
    ON threat_intel_sync_runs (started_at DESC);

CREATE INDEX IF NOT EXISTS idx_threat_intel_sync_runs_feed_started
    ON threat_intel_sync_runs (feed_key, started_at DESC);

-- e) 系统设置默认种子（所有在线定时更新默认关闭，纯离线部署零外连）
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('ip_library',   'outbound_allowlist',            '""',            'string',  FALSE, 'IP 库在线更新允许访问的内网镜像 CIDR 或精确主机名白名单（逗号分隔）'),
('ip_library',   'allow_insecure_http_mirror',    'false',         'boolean', FALSE, '是否允许已登记白名单的内网镜像源使用明文 HTTP（公网目标始终强制 HTTPS）'),
('ip_library',   'proxy_url',                     '""',            'string',  FALSE, 'IP 库在线更新可选正向代理地址（如 http://proxy.corp.local:3128）'),
('ip_library',   'proxy_auth_encrypted',          '""',            'string',  TRUE,  'IP 库在线更新正向代理认证凭据密文（user:pass 经系统主密钥加密）'),
('ip_library',   'http_timeout_seconds',          '120',           'number',  FALSE, 'IP 库在线下载单次请求超时时间（秒，范围 15–600）'),
('geoip',        'auto_update_enabled',           'false',         'boolean', FALSE, 'GeoIP 归属地库在线定时更新总开关（默认关闭）'),
('geoip',        'schedule_cron',                 '"0 3 2 * *"',   'string',  FALSE, 'GeoIP 归属地库定时更新 Cron 表达式（默认每月 2 日 03:00）'),
('geoip',        'ha_sync_enabled',               'true',          'boolean', FALSE, 'GeoIP 更新/上传/回滚后是否自动通过 hasyncd 同步至 HA 备节点'),
('geoip',        'maxmind_account_id',            '""',            'string',  FALSE, 'MaxMind GeoLite2 账号 ID（拉取官方 GeoLite2 时必填）'),
('geoip',        'maxmind_license_key_encrypted', '""',            'string',  TRUE,  'MaxMind GeoLite2 License Key 密文（经系统主密钥加密存储，绝不明文回显）'),
('threat_intel', 'auto_update_enabled',           'false',         'boolean', FALSE, '威胁情报 IP 黑名单库在线定时更新总开关（默认关闭）'),
('threat_intel', 'circuit_threshold',             '5',             'number',  FALSE, '威胁情报单个订阅源连续失败自动熔断阈值（范围 1–20）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

-- f) 权限种子（遵循 000232 三权边界：访问控制域归运维管理员 SECURITY_ADMIN，审计管理员 AUDIT_ADMIN 只读）
INSERT INTO permissions (code, name, module, description) VALUES
('geoip.read',          '查看 IP 归属地库',     'access_control', '查看 GeoIP 归属地库状态、槽位摘要、定时设置、HA 一致性与更新历史'),
('geoip.manage',        '管理 IP 归属地库',     'access_control', '离线上传、在线同步、回滚、配置定时更新/MaxMind 凭据与 HA 重同步 GeoIP 归属地库'),
('threat_intel.read',   '查看威胁情报 IP 库',   'access_control', '查看威胁情报 IP 黑名单订阅源配置、熔断状态与同步对账历史'),
('threat_intel.manage', '管理威胁情报 IP 库',   'access_control', '增改删威胁情报 IP 黑名单订阅源、配置定时同步与触发在线拉取')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN'
  AND p.code IN ('geoip.read', 'geoip.manage', 'threat_intel.read', 'threat_intel.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN'
  AND p.code IN ('geoip.read', 'threat_intel.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
