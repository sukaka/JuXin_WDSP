-- 000151 阶段5 §5.1 自定义 429/阻断响应页面：block_response 组系统设置种子
--
--   四个键均为字符串，空串 = 使用网关内置默认模板（与历史版本逐字节一致）；
--   非空值随发布通道下发网关 jiuzhang_guard block_response 段（gatewayconfig
--   LoadBlockResponse 读取校验，网关装配期做大小上限校验与 HTML 白名单净化）；
--   接口修改白名单与字符串长度上限登记于 settings.AllowedSettingKeys /
--   settings.settingStringMaxLen；修改经现有发布链路下发后生效。
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('block_response', 'html_title', '""', 'string', FALSE, '429/阻断响应 HTML 页面标题（留空使用内置默认「请求过于频繁」；最长 128 字节，渲染时整串转义）'),
('block_response', 'html_body', '""', 'string', FALSE, '429/阻断响应 HTML 页面正文（留空使用内置默认；最长 4096 字节，仅放行基础排版标签且无属性，其余内容自动转义）'),
('block_response', 'json_code', '""', 'string', FALSE, '429/阻断 JSON 错误响应的 error 错误码（留空使用内置默认 too_many_requests；仅允许字母数字与 _ . -，最长 128 字节）'),
('block_response', 'json_message', '""', 'string', FALSE, '429/阻断 JSON 错误响应的 message 文案（留空使用内置默认「请求过于频繁，请稍后重试」；最长 512 字节）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
