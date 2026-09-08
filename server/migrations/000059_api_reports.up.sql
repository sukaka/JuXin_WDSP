-- 000059 API 安全报告类型词表扩展（WDSP 任务书 P1-06，W7-RPT 分片）。
--
-- 背景：report_jobs.report_type 为 VARCHAR(10) 纯文本列（000010 建表，无 CHECK
-- 约束，类型合法性由 reports 包代码词表保证），故 API 报告类型接入无需新表、
-- 无需改列宽——四个新类型 API_ASSET / API_RISK / API_WEAK / API_SENS 均在 10
-- 字符以内。本迁移仅将列注释词表扩展落库（原列无 COMMENT，本迁移建立；
-- 回滚时重置为 NULL），与 000045 asset_status 词表迁移同一纪律。
--
-- 新词表语义（reports/api.go）：
--   API_ASSET  API 资产周报（端点总数/新增/确认率/Shadow/Zombie/Deprecated）
--   API_RISK   API 风险周报（findings 新增/关闭/类型分布/Top 端点与主体）
--   API_WEAK   API 弱点整改报告（状态分布/超期未修/复测记录）
--   API_SENS   API 敏感数据报告（类型分布/涉敏端点 Top/新增趋势）
BEGIN;

COMMENT ON COLUMN report_jobs.report_type IS
    'DAILY / WEEKLY / MONTHLY / CUSTOM / INCIDENT / API_ASSET / API_RISK / API_WEAK / API_SENS';

COMMIT;
