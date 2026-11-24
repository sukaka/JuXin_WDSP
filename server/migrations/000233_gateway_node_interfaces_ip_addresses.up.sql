-- WDSP 网口管理增强：记录物理网口当前绑定的全局单播 IPv4/IPv6 地址列表（CIDR 形式）。
BEGIN;

ALTER TABLE gateway_node_interfaces
    ADD COLUMN IF NOT EXISTS ip_addresses TEXT[] NOT NULL DEFAULT '{}'::TEXT[];

COMMIT;
