-- 000151 down：移除 block_response 组系统设置种子行
BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'block_response'
  AND setting_key IN ('html_title', 'html_body', 'json_code', 'json_message');

COMMIT;
