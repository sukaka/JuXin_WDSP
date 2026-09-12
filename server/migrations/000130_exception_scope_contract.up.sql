-- 000130 例外范围契约扩展列（WDSP P0-04，任务书
-- docs/tasks/wdsp-p0/P0-04_DECISION_SCOPED_EXCEPTIONS.md §5.1）。
--   target_engine        WAF / API（默认 WAF，历史数据语义不变）
--   api_rule_refs        API 引擎目标规则引用 [{detector_id, rule_id, model_version?}]
--   resolved_rule_ids    RuleTags 在启用/发布时展开并冻结的有界规则 ID 集
--   source_event_id      从事件创建例外的来源事件（可信绑定，禁止客户端伪造）
--   validation_status    VALID / NEEDS_REVIEW（历史配置审查标记，不改动 status 本身）
--   compiled_fingerprint 编译摘要（保存/启用/预览时重算，发布前比对防预览后篡改）
--   unsupported_reasons  不支持字段/动作的可读原因（历史配置迁移报告素材）
-- 历史数据标记规则（只标记、不启用/不关闭、不重新解释范围）：
--   NEEDS_REVIEW := 动作为 LOG_ONLY/ADJUST_SCORE（整请求 DetectionOnly 语义，P0 不再支持新启用）
--                   或 scope_type='GLOBAL'（不再允许新建/启用无应用绑定的防护例外）
--                   或 APPLICATION 但 application_id 为空（绑定缺失，发布侧本就 fail-closed）
--                   或 WAF 引擎下 rule_ids/rule_tags 均为空（无目标规则，ctl 零动作）
BEGIN;

ALTER TABLE exception_policies
    ADD COLUMN IF NOT EXISTS target_engine        VARCHAR(8)  NOT NULL DEFAULT 'WAF',
    ADD COLUMN IF NOT EXISTS api_rule_refs        JSONB       NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS resolved_rule_ids    JSONB       NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS source_event_id      UUID,
    ADD COLUMN IF NOT EXISTS validation_status    VARCHAR(16) NOT NULL DEFAULT 'VALID',
    ADD COLUMN IF NOT EXISTS compiled_fingerprint VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS unsupported_reasons  JSONB       NOT NULL DEFAULT '[]';

UPDATE exception_policies
SET validation_status = 'NEEDS_REVIEW',
    unsupported_reasons = (
        SELECT COALESCE(jsonb_agg(r), '[]'::jsonb) FROM (
            SELECT '动作 LOG_ONLY/ADJUST_SCORE 为整请求仅观察语义，P0-04 起不支持新启用，请改为精确目标排除' AS r
            WHERE exception_policies.exception_action IN ('LOG_ONLY', 'ADJUST_SCORE')
            UNION ALL
            SELECT 'GLOBAL 作用域无应用绑定，P0-04 起不允许新建/启用；历史记录保留可读'
            WHERE exception_policies.scope_type = 'GLOBAL'
            UNION ALL
            SELECT 'APPLICATION 作用域缺少应用绑定，发布侧 fail-closed 不会下发'
            WHERE exception_policies.scope_type = 'APPLICATION' AND exception_policies.application_id IS NULL
            UNION ALL
            SELECT 'WAF 例外缺少目标规则（rule_ids/rule_tags 均为空），编译产物无任何 ctl 动作'
            WHERE COALESCE(exception_policies.target_engine, 'WAF') = 'WAF'
              AND exception_policies.rule_ids = '[]'::jsonb AND exception_policies.rule_tags = '[]'::jsonb
        ) reasons
    )
WHERE deleted_at IS NULL
  AND (
        exception_action IN ('LOG_ONLY', 'ADJUST_SCORE')
        OR scope_type = 'GLOBAL'
        OR (scope_type = 'APPLICATION' AND application_id IS NULL)
        OR (rule_ids = '[]'::jsonb AND rule_tags = '[]'::jsonb)
      );

COMMIT;
