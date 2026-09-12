-- 000132 WAF 安全事件最终处置列（WDSP P0-04，任务书
-- docs/tasks/wdsp-p0/P0-04_DECISION_SCOPED_EXCEPTIONS.md §4）。
--   security_events.final_decision：可选 JSONB 对象，结构与 api_runtime_events 同契约
--   （迁移 000131 注释）。WAF 侧由 eventparser 从 Coraza 审计证据构建
--   （executor_module=WAF、rule_refs 取自真实命中规则、matched_exceptions 取
--   例外标记规则 tag 中的 exc:<uuid>/excv:<version>），管理端 normalize 落库。
--   可空：历史事件无此证据，不回填猜测结果。
--   分区表：ALTER 父表自动级联各分区。
BEGIN;

ALTER TABLE security_events
    ADD COLUMN IF NOT EXISTS final_decision JSONB;

COMMIT;
