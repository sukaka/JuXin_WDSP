-- 000107 回滚：移除 ha_groups.unicast_peers 补列。
BEGIN;

ALTER TABLE ha_groups
    DROP COLUMN IF EXISTS unicast_peers;

COMMIT;
