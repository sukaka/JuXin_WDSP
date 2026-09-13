-- 000162 down：移除 network 组系统设置种子行
BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'network'
  AND setting_key IN ('ntp_servers', 'dns_servers');

COMMIT;
