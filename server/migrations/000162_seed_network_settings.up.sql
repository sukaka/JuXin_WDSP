-- 000162 节点 DNS/NTP 服务器系统设置：network 组系统设置种子
--
--   两个键均为逗号分隔主机列表字符串（每项为合法 IP 或主机名，各 ≤4 项，
--   总长 ≤255 字节）：
--     - ntp_servers 缺省 pool.ntp.org；
--     - dns_servers 缺省空串 = 继承宿主机现状（不下发）。
--   保存/重写 sidecars/network.json 时由 netconfig 直查本表合并进下发契约
--   （dns_servers/ntp_servers 可选字段，空设置不写字段，向后兼容），
--   网关节点 netmgrd 读取执行；接口修改白名单与列表校验登记于
--   settings.AllowedSettingKeys / settings.validateServerList。
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('network', 'ntp_servers', '"pool.ntp.org"', 'string', FALSE, '节点 NTP 服务器列表（逗号分隔，每项为合法 IP 或主机名，最多 4 项，总长 255 字节；随 network.json 下发网关节点 netmgrd 执行）'),
('network', 'dns_servers', '""',             'string', FALSE, '节点 DNS 服务器列表（逗号分隔，每项为合法 IP 或主机名，最多 4 项，总长 255 字节；留空 = 继承宿主机现状不下发）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
