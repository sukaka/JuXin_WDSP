-- 000157 阶段5 §十七 CC_EXACT 探针：网关 CC 计数调试回显端点开关种子
--
--   网关保留命名空间 /_wdsp/debug/v1/cc-counter 返回指定策略键当前 CC 计数
--   （gateway/modules/jiuzhang_guard/debug_cccounter.go），供发布后流量冒烟
--   （gatewayconfig/publisher_smoke.go 第四探针 CC_EXACT）精确验证计数阈值。
--   端点仅回环/RFC1918/ULA 来源可访问、不回显计数键材料与客户端 IP、
--   自身请求不进 CC 计数、结构上不可能反向代理，安全约束内建于网关侧；
--   缺省 true 使发布后冒烟开箱可用，管理面可关闭（关闭后 CC_EXACT 如实 SKIP）。
--
--   消费侧：guardconfig.applyGatewayRuntimeSettings 解析 true/false，
--   非法值中止发布（与组内其他键同一纪律）。
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('gateway_runtime', 'debug_cc_counter', 'true', 'boolean', FALSE, 'CC计数调试回显端点开关（/_wdsp/debug/v1/cc-counter，仅回环/内网可访问）：供发布后冒烟CC_EXACT探针精确验证计数阈值')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
