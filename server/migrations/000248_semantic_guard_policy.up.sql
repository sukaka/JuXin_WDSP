-- 000248 本地离线 ONNX/SLM 语义防火墙策略与版本历史（Phase 9C-2）：
--   a) semantic_guard_policies：应用级语义防火墙策略当前草稿（application_id UNIQUE + version 乐观锁）
--   b) semantic_guard_policy_versions：不可变语义防火墙策略版本历史（UNIQUE(application_id, version)，审计溯源）
--   c) permissions / role_permissions：种子化 semantic_guard.read 与 semantic_guard.manage（遵循 000232 三权边界）
BEGIN;

-- a) 应用级本地离线语义防火墙策略（当前草稿）
CREATE TABLE IF NOT EXISTS semantic_guard_policies (
    id                        UUID             PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id            UUID             NOT NULL UNIQUE REFERENCES applications(id) ON DELETE CASCADE,
    mode                      VARCHAR(16)      NOT NULL DEFAULT 'OFF'
                              CHECK (mode IN ('OFF', 'OBSERVE', 'PROTECT')),
    version                   INT              NOT NULL DEFAULT 1,
    socket_path               VARCHAR(256)     NOT NULL DEFAULT '/var/run/caddy/sidecars/semantic.sock',
    timeout_ms                INT              NOT NULL DEFAULT 15
                              CHECK (timeout_ms >= 5 AND timeout_ms <= 200),
    max_concurrency           INT              NOT NULL DEFAULT 32
                              CHECK (max_concurrency >= 1 AND max_concurrency <= 256),
    max_input_runes           INT              NOT NULL DEFAULT 4096
                              CHECK (max_input_runes >= 256 AND max_input_runes <= 8192),
    block_threshold           DOUBLE PRECISION NOT NULL DEFAULT 0.85
                              CHECK (block_threshold >= 0.5 AND block_threshold <= 0.99),
    observe_threshold         DOUBLE PRECISION NOT NULL DEFAULT 0.50
                              CHECK (observe_threshold >= 0.1 AND observe_threshold <= 0.99),
    fail_policy               VARCHAR(16)      NOT NULL DEFAULT 'FAIL_OPEN'
                              CHECK (fail_policy IN ('FAIL_OPEN', 'FAIL_CLOSED')),
    inspect_llm_prompts       BOOLEAN          NOT NULL DEFAULT TRUE,
    inspect_mcp_content       BOOLEAN          NOT NULL DEFAULT TRUE,
    inspect_web_grayzone      BOOLEAN          NOT NULL DEFAULT TRUE,
    circuit_failure_threshold INT              NOT NULL DEFAULT 5
                              CHECK (circuit_failure_threshold >= 1 AND circuit_failure_threshold <= 100),
    circuit_open_seconds      INT              NOT NULL DEFAULT 30
                              CHECK (circuit_open_seconds >= 5 AND circuit_open_seconds <= 300),
    updated_by                VARCHAR(128)     NOT NULL DEFAULT '',
    created_at                TIMESTAMPTZ      NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ      NOT NULL DEFAULT now(),
    CONSTRAINT chk_semantic_guard_thresholds CHECK (observe_threshold <= block_threshold)
);

COMMENT ON TABLE semantic_guard_policies IS
    '应用级本地离线 ONNX/SLM 语义防火墙策略草稿（Unix Socket 边车超时、并发、阈值、检测通道与熔断护栏）';

-- b) 应用级本地离线语义防火墙策略不可变版本历史
CREATE TABLE IF NOT EXISTS semantic_guard_policy_versions (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id  UUID         NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    version         INT          NOT NULL,
    mode            VARCHAR(16)  NOT NULL
                    CHECK (mode IN ('OFF', 'OBSERVE', 'PROTECT')),
    policy_snapshot JSONB        NOT NULL DEFAULT '{}'::jsonb,
    reason          TEXT         NOT NULL,
    created_by      VARCHAR(128) NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (application_id, version)
);

COMMENT ON TABLE semantic_guard_policy_versions IS
    '应用级本地离线 ONNX/SLM 语义防火墙策略不可变版本历史（每次草稿保存追加一行，供版本溯源与审计对照）';

-- c) 权限种子（遵循 000232 三权边界：业务防护策略归安全管理员 SECURITY_ADMIN，审计管理员 AUDIT_ADMIN 只读）
INSERT INTO permissions (code, name, module, description) VALUES
('semantic_guard.read', '查看本地语义防火墙', 'security', '查看本地离线 ONNX/SLM 语义防火墙边车健康状态与应用级语义防护策略'),
('semantic_guard.manage', '管理本地语义防火墙', 'security', '管理应用级本地离线 ONNX/SLM 语义防火墙策略、评分阈值与熔断护栏')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('semantic_guard.read', 'semantic_guard.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('semantic_guard.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
