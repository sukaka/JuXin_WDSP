-- 000185 升级任务执行器等待截止列（NG-REL-02 批次 C 实证发现 F7 修复）：
-- 执行器中断（无结果文件）+ API 重启的组合下，进程内 30 分钟等待定时器随进程
-- 丢失，APPLYING 任务曾因此滞留无兜底。本列在进入 APPLYING 时持久化等待截止
-- 时刻（executor_deadline = 进入 APPLYING 时刻 + 执行器等待上限），API 启动后
-- 的兜底清扫以该持久事实为准：超期且无结果文件的 APPLYING 任务标记
-- FAILED/EXECUTOR_TIMEOUT 并留审计与告警，不自动重跑、不假装成功。
-- 旧行（本列引入前已进入 APPLYING）executor_deadline 为 NULL，清扫查询
-- 退化为 started_at + 等待上限（见 upgrades.Store.ListExpiredApplyingJobs）。
BEGIN;

ALTER TABLE upgrade_jobs ADD COLUMN IF NOT EXISTS executor_deadline TIMESTAMPTZ;

COMMIT;
