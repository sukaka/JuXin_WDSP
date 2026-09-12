-- 000030 回滚：移除 api_behavior_profiles.hour_dist 与 api_runtime_events.response_status。
BEGIN;

ALTER TABLE api_behavior_profiles
    DROP COLUMN IF EXISTS hour_dist;

ALTER TABLE api_runtime_events
    DROP COLUMN IF EXISTS response_status;

COMMIT;
