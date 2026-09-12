-- 000107 补齐 ha_groups.unicast_peers：000080 在部分环境先于「单播 VRRP 对端」能力落库，
-- 表已建但缺列，导致 GET /api/v1/ha/groups 报 column "unicast_peers" does not exist（500）。
-- IF NOT EXISTS 保证已含该列的全新环境幂等通过。
BEGIN;

ALTER TABLE ha_groups
    ADD COLUMN IF NOT EXISTS unicast_peers JSONB NOT NULL DEFAULT '[]'; -- 单播对端地址 ["192.168.31.61"]

COMMIT;
