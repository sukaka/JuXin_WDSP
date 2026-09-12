-- 000146 回滚：移除 Prompt 版本对抗测试结果列。
-- 回滚后发布门退化为仅校验 test_result（旧版代码语义），已落库的对抗明细随列删除。
BEGIN;

ALTER TABLE ai_prompt_versions
    DROP COLUMN IF EXISTS adversarial_result,
    DROP COLUMN IF EXISTS adversarial_detail;

COMMIT;
