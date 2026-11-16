-- 000204 文件与水印管理面设置种子；既有用户配置保持原值。
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('gateway_runtime', 'api_file_watermark_enabled', 'false', 'boolean', FALSE,
 '文件下载水印总开关；启用前需配置模板；保存后需发布配置'),
('gateway_runtime', 'api_file_watermark_template', '""', 'string', FALSE,
 '溯源水印模板，支持 {ip}/{identity}/{time}/{domain}；最长256字符，不含控制字符'),
('gateway_runtime', 'api_file_watermark_content_types', '"text/plain,text/csv,application/json,text/markdown"', 'string', FALSE,
 '允许加水印的 Content-Type；内联 HTML 需显式加入 text/html'),
('gateway_runtime', 'api_file_watermark_json_key', '"_wm"', 'string', FALSE,
 'JSON 顶层水印字段名，缺省 _wm；最长64字符且不含控制字符')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
