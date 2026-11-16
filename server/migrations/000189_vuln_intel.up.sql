-- 漏洞情报提醒（VULN_INTEL MVP）：NVD 每日同步 PHP 漏洞 + 技术栈订阅提醒。
-- 表：vuln_advisories（漏洞库）/ application_technologies（应用技术栈映射）/
--     vuln_alerted（提醒去重）/ vuln_intel_sync_state（同步状态）。
-- 权限：vuln_intel.read（SYSTEM_ADMIN + SECURITY_ADMIN）、vuln_intel.manage（仅 SYSTEM_ADMIN）。

BEGIN;

CREATE TABLE IF NOT EXISTS vuln_advisories (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id           VARCHAR(32)  NOT NULL UNIQUE,
    title            VARCHAR(500) NOT NULL DEFAULT '',
    summary          TEXT         NOT NULL DEFAULT '',
    severity         VARCHAR(16)  NOT NULL DEFAULT 'NONE',
    cvss_score       DOUBLE PRECISION,
    published_at     TIMESTAMPTZ,
    last_modified_at TIMESTAMPTZ,
    tech_tags        JSONB        NOT NULL DEFAULT '[]',
    references_json  JSONB        NOT NULL DEFAULT '[]',
    source           VARCHAR(16)  NOT NULL,
    raw_json         JSONB,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT vuln_advisories_severity_chk
        CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','NONE')),
    CONSTRAINT vuln_advisories_source_chk
        CHECK (source IN ('NVD','MANUAL'))
);
CREATE INDEX IF NOT EXISTS idx_vuln_advisories_published ON vuln_advisories (published_at DESC);
CREATE INDEX IF NOT EXISTS idx_vuln_advisories_severity ON vuln_advisories (severity);
CREATE INDEX IF NOT EXISTS idx_vuln_advisories_tech_tags ON vuln_advisories USING GIN (tech_tags);

CREATE TABLE IF NOT EXISTS application_technologies (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID        NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    tech_name      VARCHAR(64) NOT NULL,
    source         VARCHAR(16) NOT NULL DEFAULT 'MANUAL',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT application_technologies_uniq UNIQUE (application_id, tech_name),
    -- 技术名小写规范化（php / nodejs / openjdk …），1-64 字符
    CONSTRAINT application_technologies_name_chk
        CHECK (tech_name ~ '^[a-z0-9][a-z0-9._+-]{0,63}$'),
    CONSTRAINT application_technologies_source_chk
        CHECK (source IN ('MANUAL','NVD'))
);
CREATE INDEX IF NOT EXISTS idx_application_technologies_tech ON application_technologies (tech_name);

CREATE TABLE IF NOT EXISTS vuln_alerted (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    advisory_id UUID        NOT NULL REFERENCES vuln_advisories(id) ON DELETE CASCADE,
    tech_name   VARCHAR(64) NOT NULL,
    alerted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    alert_id    UUID,
    CONSTRAINT vuln_alerted_uniq UNIQUE (advisory_id, tech_name)
);

CREATE TABLE IF NOT EXISTS vuln_intel_sync_state (
    source            VARCHAR(16) PRIMARY KEY,
    last_sync_at      TIMESTAMPTZ,
    last_window_start TIMESTAMPTZ,
    last_window_end   TIMESTAMPTZ,
    records_upserted  INTEGER     NOT NULL DEFAULT 0,
    status            VARCHAR(16) NOT NULL DEFAULT 'IDLE',
    failure_message   TEXT        NOT NULL DEFAULT '',
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT vuln_intel_sync_state_status_chk
        CHECK (status IN ('IDLE','SUCCESS','FAILED'))
);

-- 权限种子
INSERT INTO permissions (code, name, module, description) VALUES
('vuln_intel.read',   '查看漏洞情报', 'security', '查看漏洞情报概览、漏洞列表与详情、应用技术栈映射与订阅设置'),
('vuln_intel.manage', '管理漏洞情报', 'security', '手动同步/导入漏洞情报，维护应用技术栈映射与订阅设置')
ON CONFLICT (code) DO NOTHING;

-- 系统管理员 + 安全管理员：读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code IN ('SYSTEM_ADMIN','SECURITY_ADMIN') AND p.code = 'vuln_intel.read'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 仅系统管理员：写
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code = 'vuln_intel.manage'
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
