BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'gateway_runtime'
  AND setting_key = 'api_file_watermark_include_inline_html';

COMMIT;
