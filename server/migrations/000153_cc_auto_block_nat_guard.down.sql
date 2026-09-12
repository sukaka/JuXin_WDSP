-- 000153 down：移除 cc_auto_block 组系统设置种子行
BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'cc_auto_block'
  AND setting_key IN ('nat_guard_enabled', 'nat_identity_threshold', 'nat_block_minutes');

COMMIT;
