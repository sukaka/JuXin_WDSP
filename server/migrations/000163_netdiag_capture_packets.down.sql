-- 回滚 000163：移除 netdiag_jobs.capture_packets（抓包数据包解析列表）。
BEGIN;

ALTER TABLE netdiag_jobs
    DROP COLUMN IF EXISTS capture_packets;

COMMIT;
