-- 站点资产被动发现（WDSP 网络模式扩展）：网关 mirrorcap 嗅探站点流量写 site-discovery.jsonl，
-- API 侧采集器 upsert 进 site_asset_discoveries（幂等键 domain+ip+port），管理面确认/忽略/恢复。
-- 同事务种子权限点 site_discovery.read / site_discovery.manage，角色授权对齐
-- applications.read/update 的既有集合（仅安全管理员，见 000005）。

BEGIN;

-- ---------- 站点发现结果 ----------
CREATE TABLE IF NOT EXISTS site_asset_discoveries (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain        TEXT         NOT NULL DEFAULT '',   -- 空串 = 未识别域名（按 IP+Port 维度发现）
    ip            TEXT         NOT NULL,
    port          INTEGER      NOT NULL,
    protocol      TEXT         NOT NULL,              -- HTTP / HTTPS
    source_mode   TEXT         NOT NULL DEFAULT '',   -- MIRROR / ROUTED / TRANSPARENT
    gateway_node  TEXT         NOT NULL DEFAULT '',
    seen_count    BIGINT       NOT NULL DEFAULT 0,    -- 累计观测窗口命中数（重放近似累加）
    client_count  INTEGER      NOT NULL DEFAULT 0,    -- 最近观测窗口去重客户端数
    first_seen    TIMESTAMPTZ  NOT NULL,
    last_seen     TIMESTAMPTZ  NOT NULL,
    status        TEXT         NOT NULL DEFAULT 'NEW',
    confirmed_by  TEXT         NOT NULL DEFAULT '',
    confirmed_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT chk_site_asset_discoveries_status CHECK (status IN ('NEW','CONFIRMED','IGNORED')),
    CONSTRAINT uq_site_asset_discoveries_target UNIQUE (domain, ip, port)
);
CREATE INDEX IF NOT EXISTS idx_site_asset_discoveries_last_seen ON site_asset_discoveries (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_site_asset_discoveries_status ON site_asset_discoveries (status);

-- ---------- 权限点 ----------
INSERT INTO permissions (code, name, module, description) VALUES
('site_discovery.read',   '查看站点发现', 'applications', '查看被动发现的站点资产'),
('site_discovery.manage', '管理站点发现', 'applications', '确认/忽略/恢复被动发现的站点资产')
ON CONFLICT (code) DO NOTHING;

-- ---------- 角色授权（与 applications.read/update 同集合：仅安全管理员） ----------
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('site_discovery.read','site_discovery.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
