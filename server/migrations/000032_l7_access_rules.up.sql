-- L7 访问控制规则（按 URI/方法/请求头/Cookie/Query/来源IP 组合条件匹配，首中即停）。
-- 仅 WAF/WDSP 产品形态交付；规则经发布通道随 GuardConfig 的 l7_rules 段下发网关。
BEGIN;

-- ---------- L7访问控制规则 ----------
CREATE TABLE IF NOT EXISTS l7_access_rules (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(200) NOT NULL,
    priority      INTEGER      NOT NULL DEFAULT 100,   -- 数值小者优先；同优先级按 created_at 稳定排序
    enabled       BOOLEAN      NOT NULL DEFAULT TRUE,
    conditions    JSONB        NOT NULL,               -- 条件数组（多条件 AND），单规则 ≤10 条（服务侧校验）
    action        VARCHAR(20)  NOT NULL,               -- block / allow / redirect / custom_page
    action_config JSONB        NOT NULL DEFAULT '{}'::jsonb, -- 按动作取对应字段（六键全量存储）
    created_by    UUID,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by    UUID,
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT chk_l7_access_rules_action CHECK (action IN ('block','allow','redirect','custom_page'))
);
CREATE INDEX IF NOT EXISTS idx_l7_access_rules_order ON l7_access_rules (priority ASC, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_l7_access_rules_enabled ON l7_access_rules (enabled);

-- L7 命中事件按规则聚合（列表 24h 命中数）：事件写 access_control_events，
-- event_type ∈ L7_RULE_ALLOW/BLOCK/REDIRECT/CUSTOM，access_rule_id 存 L7 规则 ID。
CREATE INDEX IF NOT EXISTS idx_ac_events_access_rule ON access_control_events (access_rule_id, occurred_at DESC) WHERE access_rule_id <> '';

-- ---------- 权限点种子（三权角色按现有惯例分配） ----------
INSERT INTO permissions (code, name, module, description) VALUES
('l7rules.read',    '查看L7访问控制', 'access_control', '查看L7访问控制规则、命中情况与规则测试'),
('l7rules.create',  '新建L7访问控制', 'access_control', '新建L7访问控制规则'),
('l7rules.update',  '编辑L7访问控制', 'access_control', '编辑L7访问控制规则（名称/优先级/启停/条件/动作）'),
('l7rules.delete',  '删除L7访问控制', 'access_control', '删除L7访问控制规则'),
('l7rules.publish', '发布L7访问控制', 'access_control', '发布L7访问控制配置到网关')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：全量
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN (
  'l7rules.read','l7rules.create','l7rules.update','l7rules.delete','l7rules.publish'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('l7rules.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 系统管理员：只读（运维可见，与阶段8种子口径一致）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN ('l7rules.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
