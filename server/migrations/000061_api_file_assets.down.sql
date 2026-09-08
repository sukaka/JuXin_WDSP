-- 000061 API 文件资产回滚：drop 文件资产表，移除批量下载阈值设置种子。
BEGIN;

DROP TABLE IF EXISTS api_file_assets;

DELETE FROM system_settings
WHERE setting_group = 'api_data' AND setting_key = 'file_bulk_download_threshold';

COMMIT;
