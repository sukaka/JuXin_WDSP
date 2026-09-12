-- 000057 回滚：删除 notify 组设置、notification.* 权限点及角色关联、通知渠道表
BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'notify' AND setting_key IN
  ('notify_rate_limit_per_minute','notify_mute_minutes','notify_group_window_seconds','notify_resolved');

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('notification.read','notification.update','notification.test')
);
DELETE FROM permissions WHERE code IN ('notification.read','notification.update','notification.test');

DROP TABLE IF EXISTS notification_channels;

COMMIT;
