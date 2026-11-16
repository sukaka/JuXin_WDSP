-- 容器运维权限种子（containerops 模块）：容器状态/日志查看、启停控制、镜像更新
-- 仅授予系统管理员（SYSTEM_ADMIN）；写操作接口侧另有密码二次确认
-- （update 另需确认文本「更新容器」），审计 MEDIUM（list/logs）/HIGH（control）/CRITICAL（update）

BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('containers.read',    '容器状态查看', 'system', '查看容器清单与运维动作任务状态'),
('containers.logs',    '容器日志查看', 'system', '查看业务容器运行日志（sidecar 侧已脱敏）'),
('containers.control', '容器启停控制', 'system', '启动/停止/重启业务容器（需密码二次确认）'),
('containers.update',  '容器更新',     'system', '按锁定镜像更新业务容器（需密码二次确认与确认文本）')
ON CONFLICT (code) DO NOTHING;

-- 系统管理员
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN (
  'containers.read','containers.logs','containers.control','containers.update'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
