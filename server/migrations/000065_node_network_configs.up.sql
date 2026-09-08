-- 000065 页面配置网桥与路由牵引（docs/NETWORK_MODES_DESIGN.md §七）：
-- 节点网络期望配置（网桥/ip_forward/路由牵引）按节点整体 JSONB 存储；
-- 保存时由 server 原子写共享卷 sidecars/network.json（网关节点 netmgrd 读取执行），
-- netmgrd 回写同目录 network-status.json，server 只读透传给前端。
-- 校验约束（桥名 br\d{1,2} 唯一、成员口 ≥2 且 present、MANAGEMENT 口禁入桥、
-- CIDR/IP 合法性等）在 server 接口层强制执行；权限复用
-- system_health.read / system_settings.update，不新增权限点。
BEGIN;

CREATE TABLE IF NOT EXISTS node_network_configs (
    node_name  VARCHAR(128) PRIMARY KEY,
    config     JSONB       NOT NULL DEFAULT '{"bridges":[],"ip_forward":false,"routes":[]}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE node_network_configs IS
    '节点网络期望配置（网桥/ip_forward/路由牵引），docs/NETWORK_MODES_DESIGN.md §七';
COMMENT ON COLUMN node_network_configs.config IS
    '期望配置：{"bridges":[{"name":"br0","ports":["eth2","eth3"]}],"ip_forward":true,"routes":[{"dst":"10.9.0.0/24","via":"192.168.50.1"}]}';

COMMIT;
