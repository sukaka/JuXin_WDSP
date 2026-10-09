-- 000176 强流程定义（NG-FLOW-01，docs/nextgen/NG-FLOW-strong-flow.md §1.1/D1）。
--
--   api_strong_flow_definitions：流程定义（版本化——编辑产新草稿 version+1、
--     激活即冻结不可变、RETIRED 单向终态；同（应用,名称）同时刻恰一个 ACTIVE，
--     部分唯一索引承载）。instance_key_param 为实例引用来源（批准的参数提取器键，
--     形态 "query:<名>" / "path:<段序>"——与对象模型 object_segment 同词表纪律）。
--   api_strong_flow_steps：定义步骤（success_rule 三形态可组合与：状态码集合 /
--     body JSONPath 子集等值 / GraphQL errors 为空；运行期解析属 FLOW-03，本表只
--     承载冻结形状）。timeout/lease 夹紧由库层 CHECK 恒约束（应用层先校验 400）。
--   与既有流程观察（api_flow_baselines，七类 OBSERVE 信号）物理隔离——无实例
--   概念、无导入路径（§1.2：旧观察状态不得导入为可信已完成步骤）。
--   权限沿用 api_flow.read / api_flow.manage（迁移 000155 已种，零新增权限点）。
BEGIN;

CREATE TABLE IF NOT EXISTS api_strong_flow_definitions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id     UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    name               VARCHAR(255) NOT NULL,
    version            INTEGER NOT NULL CHECK (version >= 1),   -- 单调递增（同名草稿 max+1）
    status             TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','ACTIVE','RETIRED')),
    binding_path_prefix TEXT NOT NULL,                          -- 端点组前缀（步骤端点须归属其下）
    instance_key_param TEXT NOT NULL,                           -- 实例引用来源（query:<名>/path:<段序>）
    mode               TEXT NOT NULL DEFAULT 'OBSERVE' CHECK (mode IN ('OBSERVE','PROTECT')),
    created_by         UUID,
    created_by_name    TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at       TIMESTAMPTZ,
    CONSTRAINT uq_strong_flow_def_app_name_version UNIQUE (application_id, name, version)
);
-- 同（应用,名称）同时刻恰一个 ACTIVE（激活新版本时同事务 RETIRED 旧 ACTIVE）
CREATE UNIQUE INDEX IF NOT EXISTS uq_strong_flow_def_active
    ON api_strong_flow_definitions (application_id, name) WHERE status='ACTIVE';
CREATE INDEX IF NOT EXISTS idx_strong_flow_def_app ON api_strong_flow_definitions (application_id, status);
COMMENT ON TABLE api_strong_flow_definitions IS 'NG-FLOW-01：强流程定义（版本化；激活即冻结；与 api_flow_baselines 观察态物理隔离）';

CREATE TABLE IF NOT EXISTS api_strong_flow_steps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    definition_id   UUID NOT NULL REFERENCES api_strong_flow_definitions(id) ON DELETE CASCADE,
    step_key        TEXT NOT NULL,
    endpoint_key    VARCHAR(560) NOT NULL,          -- 须归属绑定前缀下已 CONFIRMED 端点（应用层核对）
    sequence        INTEGER NOT NULL CHECK (sequence >= 1),
    success_rule    JSONB NOT NULL,                 -- 三形态可组合与（status_codes/body_jsonpath_equals/graphql_errors_empty）
    timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds BETWEEN 15 AND 600),
    retry_semantics TEXT NOT NULL CHECK (retry_semantics IN ('IDEMPOTENT','NOT_RETRYABLE','REQUIRES_REVIEW')),
    parallel_group  TEXT NOT NULL DEFAULT '',       -- 同组步骤 sequence 相邻；空=串行
    lease_seconds   INTEGER NOT NULL CHECK (lease_seconds BETWEEN 15 AND 300),
    allows_202      BOOLEAN NOT NULL DEFAULT FALSE, -- 异步受理：202=已受理待完成，不自动完成
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_strong_flow_step UNIQUE (definition_id, step_key),
    CONSTRAINT uq_strong_flow_step_seq UNIQUE (definition_id, sequence)  -- sequence 定义内唯一（严格递增即首步唯一最小的承载）
);
CREATE INDEX IF NOT EXISTS idx_strong_flow_steps_def ON api_strong_flow_steps (definition_id, sequence);
COMMENT ON TABLE api_strong_flow_steps IS 'NG-FLOW-01：强流程步骤（冻结形状；成功判定式运行期解析属 FLOW-03）';

COMMIT;
