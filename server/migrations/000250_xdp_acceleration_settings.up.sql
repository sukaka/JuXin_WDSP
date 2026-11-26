-- 000250 内核级 eBPF/XDP 快速丢包加速设置与权限种子（Phase 9D-2）：
--   a) system_settings：种子化 xdp_acceleration 组 5 项默认配置（默认关闭，ON CONFLICT DO NOTHING）
--   b) permissions / role_permissions：种子化 xdp_accel.read（SYSTEM_ADMIN/SECURITY_ADMIN/AUDIT_ADMIN）
--      与 xdp_accel.manage（SYSTEM_ADMIN/SECURITY_ADMIN）
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('xdp_acceleration', 'enabled', 'false'::jsonb, 'boolean', FALSE, '是否启用内核级 eBPF/XDP 黑名单快速丢包加速（默认关闭，缺省或无特权环境自动回退用户态）'),
('xdp_acceleration', 'socket_path', '"/var/run/caddy/sidecars/xdpguard.sock"'::jsonb, 'string', FALSE, 'xdpguard 守护进程 Unix Domain Socket 绝对路径（仅限 /var/run/caddy/sidecars/ 或 /run/jiuzhang/）'),
('xdp_acceleration', 'interfaces', '[]'::jsonb, 'json', FALSE, '拟挂载 XDP 的物理业务网卡名称 JSON 数组（拒绝 lo 与容器/虚拟网桥，最多 16 个）'),
('xdp_acceleration', 'attach_mode', '"auto"'::jsonb, 'string', FALSE, 'XDP 网卡挂载模式（auto 优先驱动级 Native 回退 Generic / native / generic）'),
('xdp_acceleration', 'sync_interval_seconds', '5'::jsonb, 'integer', FALSE, '全局 IP 黑名单与全局临时封禁同步至 XDP 的周期（秒，1-300）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

INSERT INTO permissions (code, name, module, description) VALUES
('xdp_accel.read', '查看内核 XDP 加速', 'xdp_acceleration', '查看内核级 eBPF/XDP 快速丢包守护进程状态、丢包遥测与网卡配置'),
('xdp_accel.manage', '管理内核 XDP 加速', 'xdp_acceleration', '修改内核级 eBPF/XDP 加速配置并触发全局 IP 黑名单立即同步')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code IN ('SYSTEM_ADMIN', 'SECURITY_ADMIN', 'AUDIT_ADMIN')
  AND p.code = 'xdp_accel.read'
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code IN ('SYSTEM_ADMIN', 'SECURITY_ADMIN')
  AND p.code = 'xdp_accel.manage'
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
