-- 000130 down：移除例外范围契约扩展列。
-- 注意：NEEDS_REVIEW 标记随之丢弃，回退后历史配置审查状态需重新评估。
BEGIN;

ALTER TABLE exception_policies
    DROP COLUMN IF EXISTS unsupported_reasons,
    DROP COLUMN IF EXISTS compiled_fingerprint,
    DROP COLUMN IF EXISTS validation_status,
    DROP COLUMN IF EXISTS source_event_id,
    DROP COLUMN IF EXISTS resolved_rule_ids,
    DROP COLUMN IF EXISTS api_rule_refs,
    DROP COLUMN IF EXISTS target_engine;

COMMIT;
