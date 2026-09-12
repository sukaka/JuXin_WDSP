-- 000154 字段间关系扩展（阶段8 任务书 §23 剩余 5 类收口）：api_parameter_relations.relation_type
-- 词表 CHECK 在 000147 九值基础上新增 1 类值比较关系（人工确认后经发布通道下发，
-- 网关侧只产 OBSERVE 级信号、任何模式下不阻断）：
--   NOT_EQUALS  不等值（两端值字符串须不相等，EQUALS 严格对偶；字符串比较无类型要求）。
-- 判定规则与证据格式（不落明文值）见 gateway/dynamic_security/detectors/relationvalue.go。
-- §23 其余 4 类（数量一致/汇总关系/父子对象/租户/所有者）请求内无可判定证据
-- （数组长度与元素值不留存；父子/租户/所有者需身份与对象归属基线），不纳入词表不硬造，
-- 降级论证见 relationvalue.go 头注释。
BEGIN;

ALTER TABLE api_parameter_relations
    DROP CONSTRAINT IF EXISTS chk_api_parameter_relations_type;

ALTER TABLE api_parameter_relations
    ADD CONSTRAINT chk_api_parameter_relations_type
    CHECK (relation_type IN ('REQUIRES', 'EXCLUDES', 'MUTEX', 'CO_OCCURS',
                             'EQUALS', 'NOT_EQUALS', 'GREATER_THAN', 'LESS_THAN', 'TIME_BEFORE', 'TIME_AFTER'));

COMMIT;
