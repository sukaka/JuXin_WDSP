-- 系统控制权限种子：重启/关机/恢复出厂设置（systemops 模块）
-- 仅授予系统管理员（SYSTEM_ADMIN）；属高危操作，接口侧另有密码二次确认与 CRITICAL 审计

BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('system.reboot',         '系统重启',     'system', '重启系统（需密码二次确认）'),
('system.shutdown',       '系统关机',     'system', '关闭系统（需密码二次确认）'),
('system.factory_reset',  '恢复出厂设置', 'system', '恢复出厂设置（需密码二次确认与确认文本）')
ON CONFLICT (code) DO NOTHING;

-- 系统管理员
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN (
  'system.reboot','system.shutdown','system.factory_reset'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
