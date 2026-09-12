-- 000159 字段间关系扩展（阶段8 任务书 §23 收口）：api_parameter_relations.relation_type
-- 词表 CHECK 在 000154 十值基础上新增 2 类数组聚合关系（人工确认后经发布通道下发，
-- 网关侧只产 OBSERVE 级信号、任何模式下不阻断）：
--   COUNT_MATCHES  数量一致（A 整数值 == B 数组长度，item_count == len(items)）；
--   SUM_MATCHES    汇总关系（A 数值 == B 数组元素数值和，total == Σ items[].price，
--                  浮点混合容差 1e-9；数组截断/聚合超预算时不判定）。
-- 判定规则、parser 数组长度/聚合量留存口径与证据格式（不落明文值与求和结果）见
-- gateway/dynamic_security/detectors/relationvalue.go 头注释与 parser/parse.go。
-- §23 剩余 3 类（父子对象/租户/所有者）请求内无可判定证据（需外部归属与身份基线），
-- 归 AUTHZ/BOLA 线，不纳入词表不硬造，降级论证见 relationvalue.go 头注释。
BEGIN;

ALTER TABLE api_parameter_relations
    DROP CONSTRAINT IF EXISTS chk_api_parameter_relations_type;

ALTER TABLE api_parameter_relations
    ADD CONSTRAINT chk_api_parameter_relations_type
    CHECK (relation_type IN ('REQUIRES', 'EXCLUDES', 'MUTEX', 'CO_OCCURS',
                             'EQUALS', 'NOT_EQUALS', 'GREATER_THAN', 'LESS_THAN', 'TIME_BEFORE', 'TIME_AFTER',
                             'COUNT_MATCHES', 'SUM_MATCHES'));

COMMIT;
