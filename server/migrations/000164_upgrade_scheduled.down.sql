-- 回滚 000164：移除 upgrade_jobs.scheduled_at。
-- 说明：status 列无 CHECK 约束，SCHEDULED/CANCELLED 无需（也无法）做约束收缩；
-- 若回滚前已存在 SCHEDULED 任务，回滚后旧版本应用将视其为未知状态（按仓库 down
-- 迁移惯例仅做结构回滚，不迁移存量数据）。
BEGIN;

ALTER TABLE upgrade_jobs
    DROP COLUMN IF EXISTS scheduled_at;

COMMIT;
