-- 000164 升级任务定时执行（上传时可指定 scheduled_at，到点自动开始升级）：
--   upgrade_jobs.scheduled_at 记录定时开始时间（NULL = 立即执行，存量行为不变）；
--   任务状态机扩 SCHEDULED（定时待到点）/CANCELLED（已取消，终态）。
--   status 列无 CHECK 约束（见 000010_stage6.up.sql，仅注释列举合法值），
--   新状态无需约束变更，合法性由应用层状态机白名单保证。
BEGIN;

ALTER TABLE upgrade_jobs
    ADD COLUMN IF NOT EXISTS scheduled_at timestamptz;

COMMENT ON COLUMN upgrade_jobs.scheduled_at IS '定时执行时间（到点自动进入正常执行流程）；NULL = 立即执行';

COMMIT;
