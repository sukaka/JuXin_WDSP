-- 000068 参数条件关系确认闭环（W11-REL / P0-02 残余，任务书 §45）：
-- api_parameter_relations 由迁移 000018 建立，CO_OCCURS 候选由
-- apimodels.RefreshParameterRelationCandidates 真实产生，但缺「人工确认 → 发布下发 →
-- 网关强制检测」通路。本迁移补齐确认语义：
--   confirmed     人工确认标记（候选 FALSE → 确认 TRUE；只有 confirmed 关系进入强制检测）；
--   confirmed_by  确认操作者（可空，口径同 api_model_versions.confirmed_by，无 FK）；
--   confirmed_at  确认时间（撤回确认时与 confirmed_by 一并清空）；
--   relation_type 词表 CHECK：保留 000018 注释记载词汇（REQUIRES/EXCLUDES/CO_OCCURS），
--                 新增 MUTEX（互斥，语义等同 EXCLUDES；网关按同一检测处理）。
BEGIN;

ALTER TABLE api_parameter_relations
    ADD COLUMN IF NOT EXISTS confirmed    BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS confirmed_by UUID,
    ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMPTZ;

ALTER TABLE api_parameter_relations
    ADD CONSTRAINT chk_api_parameter_relations_type
    CHECK (relation_type IN ('REQUIRES', 'EXCLUDES', 'MUTEX', 'CO_OCCURS'));

-- 发布通道按「FORMAL 版本 + confirmed」取数（部分索引避免全表扫）
CREATE INDEX IF NOT EXISTS idx_api_parameter_relations_confirmed
    ON api_parameter_relations (model_version_id) WHERE confirmed;

COMMENT ON COLUMN api_parameter_relations.confirmed IS
    '人工确认标记（000068）：只有 confirmed=true 的关系经发布通道下发网关进入强制检测';
COMMENT ON COLUMN api_parameter_relations.confirmed_by IS '确认操作者（撤回确认时清空）';
COMMENT ON COLUMN api_parameter_relations.confirmed_at IS '确认时间（撤回确认时清空）';

COMMIT;
