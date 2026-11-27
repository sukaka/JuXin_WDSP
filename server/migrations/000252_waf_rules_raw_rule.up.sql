-- 000252 WAF 规则表增加原始 SecRule 指令原文列，供管理端「防护规则库」与「防护策略」详情查看实际检测规则与正则表达式。
BEGIN;

ALTER TABLE waf_rules
    ADD COLUMN IF NOT EXISTS raw_rule TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN waf_rules.raw_rule IS '同步时从 .conf 提取的原始 SecRule 指令原文（保留多行格式与链式子规则）';

COMMIT;
