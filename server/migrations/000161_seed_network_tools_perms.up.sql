-- 网络诊断工具权限种子（netdiag 模块）
-- 仅授予系统管理员（SYSTEM_ADMIN）；执行与产物下载分离授权

BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('network_tools.execute', '网络诊断执行', 'network_tools', '创建/查询/停止网络诊断任务（ping/端口探测/路由追踪/DNS 查询/抓包）'),
('network_tools.download', '诊断产物下载', 'network_tools', '下载网络诊断抓包产物（pcap，含 sha256 一致性校验）')
ON CONFLICT (code) DO NOTHING;

-- 系统管理员
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN (
  'network_tools.execute','network_tools.download'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
