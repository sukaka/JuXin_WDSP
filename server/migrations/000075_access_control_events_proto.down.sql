-- 000075 回滚：移除 access_control_events.proto 列（采集端缺失容忍，回滚不影响既有事件读写）。
BEGIN;

ALTER TABLE access_control_events
    DROP COLUMN IF EXISTS proto;

COMMIT;
