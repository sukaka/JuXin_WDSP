-- 000175 PROTECT 切换业务确认单（NG-AZ-04，docs/nextgen/NG-AZ-04-protect-wizard.md §1.4/D4）。
--
--   api_authz_enforcement_confirmations：确认单把「谁、何时、基于哪份影响面、确认了什么
--   语义」落成不可篡改记录；PATCH enforcement=PROTECT 强制引用 confirm_token（校验+
--   切换+消费同一事务，apisecurity/object_models_update.go）。
--   生命周期：影响评估签发（confirm_token 一次性，15 分钟 TTL）→ 向导签署（signed_at，
--   四要素同批回填）→ PATCH 消费（consumed_at + consumed_audit_id 溯源）。
--   与 §1.4 冻结 DDL 的一处现实调整（偏差登记）：enforcement_owner/evidence_source
--   可空——签发（影响评估响应）先于四要素填写（向导第 3 步）与签署（第 4 步），
--   签署端点强制非空+词表校验；on_unknown 首批唯一值 ALLOW_UNKNOWN 签发即默认。
BEGIN;

CREATE TABLE IF NOT EXISTS api_authz_enforcement_confirmations (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    confirm_token    UUID NOT NULL UNIQUE,             -- 一次性签署令牌（影响评估响应签发）
    application_id   UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    endpoint_id      UUID NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    object_segment   TEXT NOT NULL DEFAULT '',         -- 确认粒度 = 对象模型行（端点×对象段）
    window_days      INTEGER NOT NULL CHECK (window_days BETWEEN 1 AND 30),
    impact_snapshot  JSONB NOT NULL,                   -- 签署时刻影响评估摘要全量（§1.3 响应无 token 键）
    confirm_text     TEXT NOT NULL DEFAULT '',         -- 冻结确认语义文案（签署时按 v1 模板生成落库）
    enforcement_owner TEXT NOT NULL DEFAULT '',        -- 四要素（签署时必填非空 ≤128；签发时 ''=未填写）
    evidence_source  TEXT NOT NULL DEFAULT ''          -- 签署时必填词表；''=未签署填写
        CHECK (evidence_source IN ('','AUTHORITY_SYNC','MANUAL_CONFIRMED')),
    on_unknown       TEXT NOT NULL DEFAULT 'ALLOW_UNKNOWN'
        CHECK (on_unknown = 'ALLOW_UNKNOWN'),
    confirmed_by     UUID,                             -- 签署人（签署时回填；签发时为 NULL）
    confirmed_by_name TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    token_expires_at TIMESTAMPTZ NOT NULL,             -- 签发后 15 分钟
    signed_at        TIMESTAMPTZ,                      -- 向导第 4 步签署时刻（NULL=未签署）
    consumed_at      TIMESTAMPTZ,                      -- PATCH 消费时刻（NULL=未消费）
    consumed_audit_id TEXT NOT NULL DEFAULT ''         -- 消费它的切换请求 request_id（审计按 request_id 反查，溯源闭环）
);
CREATE INDEX IF NOT EXISTS idx_authz_enf_confirm_endpoint
    ON api_authz_enforcement_confirmations (endpoint_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_authz_enf_confirm_app_time
    ON api_authz_enforcement_confirmations (application_id, created_at DESC);
COMMENT ON TABLE api_authz_enforcement_confirmations IS 'NG-AZ-04 D4：PROTECT 切换业务确认单（签发→签署→消费生命周期；确认单留存不删，历史事实与「回滚不回退事实」同纪律）';

COMMIT;
