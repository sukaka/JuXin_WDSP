-- 000039 API 弱点中心（WDSP 任务书 P0-13：Risk/Weakness 分离）。
--
-- 语义边界：api_runtime_findings / api_runtime_events 承载「运行时风险信号」
-- （一次性异常，谁、何时、命中了什么）；api_weaknesses 承载「长期缺陷」
-- （需要确认→指派→整改→复测→关闭的弱点，跨天持续跟踪）。
-- 弱点由 apiweakness.Sweeper 周期扫描派生（同端点同 weakness_code upsert），
-- 整改/复测轨迹落 api_weakness_actions（只增不改，与操作审计互补）。
BEGIN;

CREATE TABLE IF NOT EXISTS api_weaknesses (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id   UUID REFERENCES api_endpoints(id) ON DELETE SET NULL, -- 端点删除后弱点保留为历史
    weakness_code TEXT        NOT NULL,        -- UNAUTHENTICATED_SENSITIVE_API / DEPRECATED_STILL_CALLED / SENSITIVE_IN_QUERY / SCHEMA_DRIFT_PERSISTENT / ...
    weakness_name TEXT        NOT NULL DEFAULT '',
    category      TEXT        NOT NULL DEFAULT '',        -- AUTHN / LIFECYCLE / SENSITIVE / SCHEMA
    severity      TEXT        NOT NULL DEFAULT 'MEDIUM',  -- INFO / LOW / MEDIUM / HIGH / CRITICAL
    status        TEXT        NOT NULL DEFAULT 'NEW',
    evidence_json JSONB       NOT NULL DEFAULT '{}',      -- 仅脱敏摘要（规则/计数/窗口），不落原始请求数据
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    trigger_count INTEGER     NOT NULL DEFAULT 1,         -- 派生扫描命中次数（同端点同 code 每轮 +1）
    owner         TEXT        NOT NULL DEFAULT '',        -- 整改负责人（assign 指定）
    due_date      TIMESTAMPTZ,                            -- 整改期限
    fixed_at      TIMESTAMPTZ,                            -- 整改完成时间
    retested_at   TIMESTAMPTZ,                            -- 最近一次复测时间
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_api_weaknesses_status CHECK (status IN ('NEW','CONFIRMED','TO_FIX','FIXED','REPRODUCED','IGNORED','ARCHIVED')),
    -- 派生 upsert 锚点：同端点同弱点码唯一（endpoint_id 为 NULL 的手工条目不参与 upsert，PG 唯一约束对 NULL 放行）
    CONSTRAINT uq_api_weaknesses_endpoint_code UNIQUE (endpoint_id, weakness_code)
);
CREATE INDEX IF NOT EXISTS idx_api_weaknesses_status ON api_weaknesses (status, severity);
CREATE INDEX IF NOT EXISTS idx_api_weaknesses_endpoint ON api_weaknesses (endpoint_id, status);
CREATE INDEX IF NOT EXISTS idx_api_weaknesses_last_seen ON api_weaknesses (last_seen DESC);

-- 整改 / 复测历史（只增不改）
CREATE TABLE IF NOT EXISTS api_weakness_actions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    weakness_id UUID NOT NULL REFERENCES api_weaknesses(id) ON DELETE CASCADE,
    action      TEXT        NOT NULL,                -- DERIVED / CONFIRM / ASSIGN / MARK_FIXED / RETEST_PASS / RETEST_FAIL / IGNORE / ARCHIVE / REPRODUCED
    actor       TEXT        NOT NULL DEFAULT 'system', -- system（派生扫描）/ 用户名
    note        TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_weakness_actions_weakness ON api_weakness_actions (weakness_id, created_at DESC);

COMMIT;
