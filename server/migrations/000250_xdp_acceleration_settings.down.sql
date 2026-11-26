-- 回滚 000250：移除 xdp_acceleration 权限种子与系统设置项
BEGIN;

DELETE FROM role_permissions
WHERE permission_id IN (SELECT id FROM permissions WHERE code IN ('xdp_accel.read', 'xdp_accel.manage'));

DELETE FROM permissions WHERE code IN ('xdp_accel.read', 'xdp_accel.manage');

DELETE FROM system_settings
WHERE setting_group = 'xdp_acceleration'
  AND setting_key IN ('enabled', 'socket_path', 'interfaces', 'attach_mode', 'sync_interval_seconds');

COMMIT;
