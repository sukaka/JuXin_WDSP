-- 000226 WAF 规则自动解析元数据（方案 A）与人工中文说明覆盖表（方案 B）。
--
--   1. waf_rules.parsed_spec：同步 .conf 规则文件时自动提取的 SecRule 结构化事实
--      （目标变量、算子、解码变换、偏执级别、处置动作、skipAfter/ctl 与规则中文注释），
--      使热投递的新规则包或升级后的 CRS 新规则无需改代码即可拥有精准中文详述。
--   2. waf_rule_descriptions：管理员在界面手工维护的规则中文说明覆盖表（按 rule_id 唯一），
--      独立于 waf_rules 版本行，不受后续 CRS 同步或升级覆盖；空字段自动继承系统默认说明。
BEGIN;

ALTER TABLE waf_rules
    ADD COLUMN IF NOT EXISTS parsed_spec JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN waf_rules.parsed_spec IS '同步时从 .conf 自动解析的 SecRule 结构化元数据与中文注释（供新规则免改代码生成中文详述）';

CREATE TABLE IF NOT EXISTS waf_rule_descriptions (
    rule_id         INTEGER      PRIMARY KEY,
    summary         TEXT         NOT NULL DEFAULT '',
    detection_logic TEXT         NOT NULL DEFAULT '',
    risk_impact     TEXT         NOT NULL DEFAULT '',
    tuning_advice   TEXT         NOT NULL DEFAULT '',
    updated_by      UUID,
    updated_by_name VARCHAR(64)  NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE waf_rule_descriptions IS 'WAF 规则人工中文详细说明覆盖表（按 rule_id 持久保存，不受规则同步覆盖）';

COMMIT;
