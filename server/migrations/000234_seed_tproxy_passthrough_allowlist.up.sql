-- 000234 透明串接模式 TLS SNI 透传白名单系统设置种子（network 组）
--
--   tproxyd 已加固为 fail-closed：仅 protect_hosts 内域名的 TLS 连接送 Caddy 终结检测，
--   未列明 SNI 不自动透传；需放行同 IP 未纳管 HTTPS 站点时在此显式登记透传白名单。
--   支持逗号/换行分隔文本或 JSON 字符串数组，支持精确域名与 RFC 单级前导通配符（*.example.com）；
--   空串 = 不放行任何未列明 SNI 透传。保存后通过设置钩子即时刷新 tproxyd.json。
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('network', 'tproxy_passthrough_allowlist', '""', 'string', FALSE, '透明模式 TLS SNI 端到端透传白名单（逗号/换行分隔或 JSON 字符串数组，支持 *.example.com 单级通配符；留空 = 严格 fail-closed 不透传未纳管 HTTPS 站点）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
