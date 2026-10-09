-- 000174 授权显式阻断资格（NG-AZ-03，docs/nextgen/NG-AZ-03-verified-violation.md §1.3/D10）。
--
--   api_object_models.enforcement：per-endpoint 阻断开关（OBSERVE（缺省）| PROTECT）；
--     切换 PROTECT 的 §8.4 强制前置四要素同列落库：
--     enforcement_owner（业务负责人标识，非空 ≤128）、evidence_source（证据来源声明，
--     词表 AUTHORITY_SYNC|MANUAL_CONFIRMED）、on_unknown（UNKNOWN 处理方式声明，
--     首批仅 ALLOW_UNKNOWN——明确 UNKNOWN 永不阻断的预期管理）。
--     四列默认 OBSERVE/空值——未配置行为与历史版本逐字节一致（NG-T-C01）。
--   api_role_baselines.enforcement：BFLA 侧 per-角色基线行阻断开关（同值域同缺省；
--     无行级配置时端点继承 object model 值——继承语义在网关消费侧实现）。
--   切换 PROTECT 的服务端强制校验在应用层（apisecurity/object_models_update.go），
--   DDL 只承载词表与缺省，不内嵌四要素必填（历史行与 OBSERVE 行合法存在）。
BEGIN;

ALTER TABLE api_object_models
    ADD COLUMN IF NOT EXISTS enforcement TEXT NOT NULL DEFAULT 'OBSERVE',
    ADD COLUMN IF NOT EXISTS enforcement_owner TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS evidence_source TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS on_unknown TEXT NOT NULL DEFAULT 'ALLOW_UNKNOWN';

ALTER TABLE api_object_models DROP CONSTRAINT IF EXISTS api_object_models_enforcement_check;
ALTER TABLE api_object_models
    ADD CONSTRAINT api_object_models_enforcement_check
    CHECK (enforcement IN ('OBSERVE','PROTECT'));

ALTER TABLE api_object_models DROP CONSTRAINT IF EXISTS api_object_models_evidence_source_check;
ALTER TABLE api_object_models
    ADD CONSTRAINT api_object_models_evidence_source_check
    CHECK (evidence_source IN ('','AUTHORITY_SYNC','MANUAL_CONFIRMED'));

ALTER TABLE api_object_models DROP CONSTRAINT IF EXISTS api_object_models_on_unknown_check;
ALTER TABLE api_object_models
    ADD CONSTRAINT api_object_models_on_unknown_check
    CHECK (on_unknown = 'ALLOW_UNKNOWN');

COMMENT ON COLUMN api_object_models.enforcement IS 'NG-AZ-03 D3：per-endpoint 阻断开关（OBSERVE 缺省 | PROTECT；切换 PROTECT 须同请求提供 enforcement_owner/evidence_source/on_unknown 三要素）';
COMMENT ON COLUMN api_object_models.enforcement_owner IS '§8.4 切换 PROTECT 业务负责人标识（切换后保留供审计）';
COMMENT ON COLUMN api_object_models.evidence_source IS '§8.4 证据来源声明（AUTHORITY_SYNC|MANUAL_CONFIRMED）';
COMMENT ON COLUMN api_object_models.on_unknown IS '§8.4 UNKNOWN 处理方式声明（首批仅 ALLOW_UNKNOWN：UNKNOWN 永不阻断）';

ALTER TABLE api_role_baselines
    ADD COLUMN IF NOT EXISTS enforcement TEXT NOT NULL DEFAULT 'OBSERVE';
ALTER TABLE api_role_baselines DROP CONSTRAINT IF EXISTS api_role_baselines_enforcement_check;
ALTER TABLE api_role_baselines
    ADD CONSTRAINT api_role_baselines_enforcement_check
    CHECK (enforcement IN ('OBSERVE','PROTECT'));
COMMENT ON COLUMN api_role_baselines.enforcement IS 'NG-AZ-03 D3：BFLA 侧 per-角色基线阻断开关（OBSERVE 缺省 | PROTECT；无行级配置时端点继承 object model 值）';

-- D1 决策词表加值：api_authorization_decisions.decision CHECK 放宽加第四值
-- VERIFIED_VIOLATION（判定结论非动作；final_action 词表与历史行不变——
-- 词表扩展非结构迁移，与「落库零迁移（历史行零变更）」语义一致）。
ALTER TABLE api_authorization_decisions DROP CONSTRAINT IF EXISTS api_authorization_decisions_decision_check;
ALTER TABLE api_authorization_decisions
    ADD CONSTRAINT api_authorization_decisions_decision_check
    CHECK (decision IN ('ALLOW','OBSERVE_VIOLATION','UNKNOWN','VERIFIED_VIOLATION'));

COMMIT;
