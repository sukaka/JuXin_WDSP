-- 000147 字段间关系扩展（阶段8 任务书 §23）：api_parameter_relations.relation_type
-- 词表 CHECK 在 000068 四值基础上新增 5 类值比较关系（人工确认后经发布通道下发，
-- 网关侧只产 OBSERVE 级信号、任何模式下不阻断）：
--   EQUALS        等值（两端值字符串相等）；
--   GREATER_THAN / LESS_THAN   数值大小比较（两端值可解析为数值才判定）；
--   TIME_BEFORE  / TIME_AFTER  时间先后（两端值可解析为时间才判定）。
-- 判定规则与证据格式（不落明文值）见 gateway/dynamic_security/detectors/relationvalue.go。
BEGIN;

ALTER TABLE api_parameter_relations
    DROP CONSTRAINT IF EXISTS chk_api_parameter_relations_type;

ALTER TABLE api_parameter_relations
    ADD CONSTRAINT chk_api_parameter_relations_type
    CHECK (relation_type IN ('REQUIRES', 'EXCLUDES', 'MUTEX', 'CO_OCCURS',
                             'EQUALS', 'GREATER_THAN', 'LESS_THAN', 'TIME_BEFORE', 'TIME_AFTER'));

COMMIT;
