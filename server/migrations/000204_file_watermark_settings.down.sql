BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'gateway_runtime'
  AND setting_key IN (
    'api_file_watermark_enabled',
    'api_file_watermark_template',
    'api_file_watermark_content_types',
    'api_file_watermark_json_key'
  );

COMMIT;
