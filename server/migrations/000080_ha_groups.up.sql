-- 000080 主备高可用（HA Active-Standby）：ha_groups / ha_group_members + ha.* 权限点。
--
-- 设计：docs/HA_ACTIVE_STANDBY_DESIGN.md §8.3（M2 范围）。
-- ha-vip.json 由管理面保存时原子写共享卷 sidecars（havipd 读取执行），
-- 漂移/联动事件经各节点 ha-vip-status.json 透传（采集通道落地后另行汇聚）。
BEGIN;

CREATE TABLE IF NOT EXISTS ha_groups (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name           TEXT         NOT NULL UNIQUE,           -- 组名（havipd vrrp_instance 名）
    state          VARCHAR(16)  NOT NULL DEFAULT 'ENABLED',-- ENABLED/DISABLED
    vrid           INT          NOT NULL,                  -- VRRP 虚拟路由 ID（1-255）
    iface          TEXT         NOT NULL,                  -- VIP 承载网卡
    vips           JSONB        NOT NULL DEFAULT '[]',     -- ["192.168.31.100/24"]
    preempt        BOOLEAN      NOT NULL DEFAULT FALSE,    -- 是否允许抢占（false=nopreempt）
    advert_int_ms  INT          NOT NULL DEFAULT 1000,     -- VRRP 通告间隔（200-10000）
    unicast        BOOLEAN      NOT NULL DEFAULT FALSE,    -- 单播 VRRP（云上禁组播环境）
    unicast_peers  JSONB        NOT NULL DEFAULT '[]',     -- 单播对端地址 ["192.168.31.61"]
    auth_ciphertext TEXT,                                  -- VRRP 认证串密文（encSvc；NULL=未配置/未装配加密服务）
    created_by     UUID,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    version        INT          NOT NULL DEFAULT 1,        -- 乐观锁
    CONSTRAINT chk_ha_groups_state CHECK (state IN ('ENABLED','DISABLED')),
    CONSTRAINT chk_ha_groups_vrid CHECK (vrid BETWEEN 1 AND 255),
    CONSTRAINT chk_ha_groups_advert CHECK (advert_int_ms BETWEEN 200 AND 10000)
);

CREATE TABLE IF NOT EXISTS ha_group_members (
    group_id UUID NOT NULL REFERENCES ha_groups(id) ON DELETE CASCADE,
    node_id  UUID NOT NULL REFERENCES api_gateway_nodes(id),
    priority INT  NOT NULL,                                -- 1-254，组内唯一，大者倾向 MASTER
    PRIMARY KEY (group_id, node_id),
    CONSTRAINT chk_ha_member_priority CHECK (priority BETWEEN 1 AND 254)
);

COMMENT ON TABLE ha_groups IS '主备高可用组（VIP 漂移）；保存时原子写 sidecars/ha-vip.json 由 havipd 执行';
COMMENT ON TABLE ha_group_members IS '主备组成员（恰 2 行；priority 决定主备倾向）';

-- 权限点（SECURITY_ADMIN/SYSTEM_ADMIN 管理，三权可读）
INSERT INTO permissions (code, name, module, description) VALUES
('ha.read',   '查看主备高可用', 'ha', '查看主备组配置与运行状态'),
('ha.manage', '管理主备高可用', 'ha', '创建/修改/删除主备组、启停与人工回切')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code IN ('SYSTEM_ADMIN','SECURITY_ADMIN') AND p.code IN ('ha.read','ha.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('ha.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
