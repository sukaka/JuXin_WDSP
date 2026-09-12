-- 000152 阶段8 §36 限流下发面：gateway_runtime 组配额/对象/分页/批量阈值设置种子
--
--   五个键均为字符串数值，空串 = 不启用（发布通道不下发，网关对应检测零行为；
--   与历史版本逐字节一致）；非空值经发布通道下发网关 jiuzhang_guard（guardconfig
--   applyGatewayRuntimeSettings 解析为非负整数，非法值中止发布；>0 才注入下发 JSON）。
--   接口修改白名单登记于 settings.AllowedSettingKeys；修改经现有发布链路下发后生效。
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('gateway_runtime', 'api_quota_per_hour', '""', 'string', FALSE, 'API 身份+端点每小时配额（定窗，自然小时；留空或 0 不启用；超限产 ratelimit.api_hourly_quota，PROTECT 映射 429）'),
('gateway_runtime', 'api_quota_per_day', '""', 'string', FALSE, 'API 身份+端点每日配额（UTC 自然日定窗；留空或 0 不启用；超限产 ratelimit.api_daily_quota，PROTECT 映射 429）'),
('gateway_runtime', 'object_rate_per_minute', '""', 'string', FALSE, '同身份对同对象每分钟上限（1 分钟滑窗，对象为路径位置参数/请求体主键值哈希；留空或 0 不启用；超限产 ratelimit.object_rate）'),
('gateway_runtime', 'max_page_size', '""', 'string', FALSE, 'API 分页大小上限（query 分页参数 limit/page_size/size 等；留空或 0 不启用；超限产 ratelimit.page_size_exceeded）'),
('gateway_runtime', 'max_batch_size', '""', 'string', FALSE, 'API 批量数量上限（query 逗号分隔列表元素数；留空或 0 不启用；超限产 ratelimit.batch_size_exceeded）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
