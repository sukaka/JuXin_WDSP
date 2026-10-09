-- 000177 强流程实例与步骤事件（NG-FLOW-02，docs/nextgen/NG-FLOW-strong-flow.md §1.2/D2/D8）。
--
--   api_strong_flow_instances：实例行。definition_version 实例创建时冻结
--     （NG-T-F06：定义升级后存量实例按旧版本走完，绝不强行换图）；
--     instance_key 为 sfref: 前缀域隔离 HMAC（strongflow.InstanceRefHMAC 域
--     「jiuzhang-wdsp-strongflow-sfref-v1\x00」，与 objref 域物理区分）；
--     tenant_ref/principal_ref 只落脱敏引用不落明文（§14.3）；status 五态
--     （ACTIVE/CONFIRMED/INDETERMINATE/CANCELLED/FAILED）；version 乐观锁
--     （FLOW-03 管理恢复 resolve 的版本冲突拒绝承载）；terminated_at 终态时刻。
--   api_strong_flow_step_events：步骤事件溯源（RESERVE/COMMIT/RELEASE/EXPIRE
--     与 INSTANCE_* 状态推进全量落行——事实链可回放对账）。幂等去重选型
--     （冻结）：UNIQUE(instance_id, step_key, action, fencing_token)——同一逻辑
--     事件（同步骤同动作同 fencing）重放/重发去重；lease 过期后重 reserve 得新
--     fencing 产生新行（不覆盖）；实例动作（INSTANCE_*）fencing_token=0 固定。
--     不用 request_id 做唯一：同一请求可携带多步事件，request_id 只作关联列。
BEGIN;

CREATE TABLE IF NOT EXISTS api_strong_flow_instances (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id     UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    definition_id      UUID NOT NULL REFERENCES api_strong_flow_definitions(id) ON DELETE CASCADE,
    definition_version INTEGER NOT NULL,                -- 实例创建时冻结版本（F06 不换图）
    instance_key       VARCHAR(128) NOT NULL,           -- sfref: 前缀域隔离 HMAC
    tenant_ref         VARCHAR(128) NOT NULL DEFAULT '', -- 可信租户引用（脱敏形态）
    principal_ref      VARCHAR(128) NOT NULL DEFAULT '', -- 可信主体引用（脱敏形态）
    status             TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE','CONFIRMED','INDETERMINATE','CANCELLED','FAILED')),
    version            INTEGER NOT NULL DEFAULT 1,      -- 乐观锁（FLOW-03 resolve 版本冲突承载）
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    terminated_at      TIMESTAMPTZ,
    CONSTRAINT uq_strong_flow_instance UNIQUE (definition_id, definition_version, instance_key)
);
CREATE INDEX IF NOT EXISTS idx_strong_flow_inst_app ON api_strong_flow_instances (application_id, status, created_at DESC);
COMMENT ON TABLE api_strong_flow_instances IS 'NG-FLOW-02：强流程实例（版本冻结/五态/乐观锁；热状态在 Valkey，本表为事实源——D8 持久化边界）';

CREATE TABLE IF NOT EXISTS api_strong_flow_step_events (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id   UUID NOT NULL REFERENCES api_strong_flow_instances(id) ON DELETE CASCADE,
    step_key      TEXT NOT NULL DEFAULT '',             -- 实例动作（INSTANCE_*）为空串
    action        TEXT NOT NULL CHECK (action IN (
        'RESERVE','COMMIT','RELEASE','EXPIRE',
        'INSTANCE_NEW','INSTANCE_CONFIRMED','INSTANCE_INDETERMINATE','INSTANCE_CANCELLED','INSTANCE_FAILED')),
    fencing_token BIGINT NOT NULL DEFAULT 0,            -- 实例动作固定 0；步骤动作=预留时发放的单调序号
    result        TEXT NOT NULL CHECK (result IN ('OK','CONFLICT','REJECTED','UNKNOWN')),
    reason_code   TEXT NOT NULL DEFAULT '',             -- 违规/失败/披露原因码（FLOW-* 词表）
    request_id    VARCHAR(64) NOT NULL DEFAULT '',      -- 关联 api_runtime_events.request_id
    occurred_at   TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_strong_flow_step_event UNIQUE (instance_id, step_key, action, fencing_token)
);
CREATE INDEX IF NOT EXISTS idx_strong_flow_step_events_inst ON api_strong_flow_step_events (instance_id, occurred_at);
COMMENT ON TABLE api_strong_flow_step_events IS 'NG-FLOW-02：强流程步骤事件溯源（幂等键 instance+step+action+fencing；采集重放去重）';

COMMIT;
