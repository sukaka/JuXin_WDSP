-- 000168 回滚：移除执行覆盖观测摄入三表（明细 / 阶段计数快照 / 分钟聚合）。
BEGIN;

DROP TABLE IF EXISTS coverage_minute_agg;
DROP TABLE IF EXISTS coverage_counter_snapshots;
DROP TABLE IF EXISTS coverage_observations;

COMMIT;
