-- 源站连通性测试私网受控放行设置（归属 network 组；默认关闭以保持 SSRF 基线，回环/链路本地/云元数据始终硬拦截）
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('network', 'upstream_test_allow_private', 'false', 'boolean', FALSE, '允许源站连通性测试访问内网私网地址（RFC 1918 / ULA；回环、链路本地与云元数据始终禁止）'),
('network', 'upstream_test_allowed_private_cidrs', '""', 'string', FALSE, '允许源站连通性测试访问的私网 CIDR 白名单（逗号分隔，最多 32 项；如 172.30.0.0/16,10.0.0.0/8）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
