-- 000203 内联 HTML 网页溯源水印开关；默认关闭，保存后走既有配置发布链。
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('gateway_runtime', 'api_file_watermark_include_inline_html', 'false', 'boolean', FALSE,
 '内联 HTML 网页追加不可见溯源注释；需同时启用文件水印且将 text/html 加入白名单；保存后需发布配置')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
