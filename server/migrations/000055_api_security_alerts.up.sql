-- 000055 API 安全告警接线（W6-B / P1-08）：system_alerts 静默能力列。
--
-- 任务书编号 000052 已被 000052_application_deployment_mode 占用（并行分片），
-- 000053/000054 亦为并行分片（api_scan）所得，本分片顺延至 000055，内容不变。
--
-- 背景：system_alerts（000010）仅有运维类告警与 OPEN/ACKNOWLEDGED/RESOLVED/IGNORED
-- 四态状态机，无静默（Silenced）能力。本迁移补单列 silenced_until 承载实例级静默：
--   1. 静默期间告警保持原状态，仍按既有合并/冷却/抖动机制记录（occurrence_count
--      累计、last_seen_at 刷新），即「仍记录」；
--   2. 同指纹（alert_type+component）告警在静默期内新建时跳过 syslog 外发通知，
--      即「不重复通知」（评估引擎 Raise 新建路径经 HasActiveSilence 判定）；
--   3. 列表三态视图（Active/Silenced/History）由 status 与 silenced_until 推导，
--      不扩展状态词表：
--        Active   = OPEN/ACKNOWLEDGED 且（未静默或静默已到期）
--        Silenced = OPEN/ACKNOWLEDGED 且 silenced_until > now()
--        History  = RESOLVED/IGNORED
BEGIN;

ALTER TABLE system_alerts
    ADD COLUMN IF NOT EXISTS silenced_until TIMESTAMPTZ;

COMMENT ON COLUMN system_alerts.silenced_until IS
    '静默截止时刻（NULL = 未静默）；静默期内告警仍记录，同指纹新建告警不重复通知';

COMMIT;
