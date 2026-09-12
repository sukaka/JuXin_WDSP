-- 000155 业务流程基线管理面（阶段8 §44 发布下发面，对应网关 detectors/flow.go 契约）。
--   1. api_flow_baselines：流程粒度基线主表。flow_id 为下发契约键（全局唯一，
--      网关侧会话键组成部分）；enabled=FALSE 的行不进入发布载荷；version 为乐观锁
--      版本戳（PUT 携带 expected_version，冲突 409），每次编辑 +1。
--   2. api_flow_baseline_steps：流程步骤（绑定端点，endpoint_key 经 api_endpoints
--      关联解析——与 api_role_baselines 同一先例）。predecessors 为同流程 step_id
--      列表（AND 语义，空 = 无前置约束）；state_from/state_to 为空 = 该步骤不参与
--      状态机判定（与网关降级口径一致）。同流程内 step_id 唯一（部分校验由应用层
--      承担：前置引用须指向同流程已声明步骤且不得自引用）。
--   3. 权限点 api_flow.read / api_flow.manage，授权口径与 000046/000048 一致。
BEGIN;

CREATE TABLE IF NOT EXISTS api_flow_baselines (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_id     VARCHAR(128) NOT NULL UNIQUE,       -- 流程标识（发布契约键）
    name        VARCHAR(255) NOT NULL DEFAULT '',   -- 展示名
    description TEXT         NOT NULL DEFAULT '',
    enabled     BOOLEAN      NOT NULL DEFAULT TRUE, -- 仅启用行进入发布载荷
    version     INTEGER      NOT NULL DEFAULT 1,    -- 乐观锁版本戳（编辑 +1）
    created_by  TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_flow_baselines_enabled ON api_flow_baselines (enabled);

CREATE TABLE IF NOT EXISTS api_flow_baseline_steps (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_baseline_id UUID        NOT NULL REFERENCES api_flow_baselines(id) ON DELETE CASCADE,
    step_id          VARCHAR(128) NOT NULL,          -- 步骤标识（流程内唯一）
    endpoint_id      UUID        NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    sequence         INTEGER     NOT NULL,           -- 流程内单调序号（逆序判定基准）
    predecessors     TEXT[]      NOT NULL DEFAULT '{}', -- 期望前置步骤 step_id 列表（AND 语义）
    terminal         BOOLEAN     NOT NULL DEFAULT FALSE,  -- 是否流程终点（描述性字段）
    state_from       VARCHAR(64) NOT NULL DEFAULT '',     -- 要求的对象前置状态（空 = 不参与状态判定）
    state_to         VARCHAR(64) NOT NULL DEFAULT '',     -- 步骤完成后的对象状态（空 = 不推进状态）
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_api_flow_baseline_steps UNIQUE (flow_baseline_id, step_id)
);
CREATE INDEX IF NOT EXISTS idx_api_flow_baseline_steps_flow ON api_flow_baseline_steps (flow_baseline_id, sequence);
CREATE INDEX IF NOT EXISTS idx_api_flow_baseline_steps_endpoint ON api_flow_baseline_steps (endpoint_id);

-- 流程基线管理权限点（查看/管理）
INSERT INTO permissions (code, name, module, description) VALUES
('api_flow.read',   '查看流程基线', 'api', '查看业务流程基线与步骤定义'),
('api_flow.manage', '管理流程基线', 'api', '维护业务流程基线（创建/编辑/启停/删除）')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：全部 2 个权限点（与 000048 口径一致，AUDIT_ADMIN/SYSTEM_ADMIN 不授权）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('api_flow.read', 'api_flow.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
