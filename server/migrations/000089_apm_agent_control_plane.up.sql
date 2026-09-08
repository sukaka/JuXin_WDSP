-- 000089 APM 阶段2 上半：Agent 控制面（设计 docs/BUSINESS_PERFORMANCE_APM_DESIGN.md
-- §8.3 生命周期状态机 / §9 注册认证与策略下发 / §12.3 威胁模型 / §16.2 管理接口）。
--
--   1) apm_services：OTel service.name 与现有 application 的映射（应用可空——
--      注册令牌未绑定应用时先落 UNCLAIMED，待管理员认领/绑定；应用硬删除时置空保留观测历史）；
--   2) apm_agents：Agent 实例登记（状态机存态不含 OFFLINE——离线由查询侧按
--      last_heartbeat_at 超时推导；REVOKED 为终态）；
--   3) apm_enrollment_tokens：一次性注册令牌（只存 SHA-256 摘要，永不存原文；
--      绑定应用/环境/允许语言/有效期，使用即作废）；
--   4) apm_agent_policies：签名策略版本（同一 scope 版本单调递增，唯一约束兜底；
--      signature 为管理面内置 CA 密钥的 Ed25519 签名 hex）；
--   5) apm_agent_cert_revocations：按证书 SHA-256 指纹的撤销列表（撤销 Agent、
--      证书轮换旧证、重新注册顶替旧实例均入此表，机器侧认证必查）；
--   6) 权限种子：apm.agents.manage / apm.settings.manage。本批两个权限点均为
--      管理写类（对照 000084 manage-only 批次先例）：SECURITY_ADMIN 全量；
--      AUDIT_ADMIN 不授（其 APM 只读面已由 000088 三个 read 权限点承载，
--      manage 权限点含写能力，授出即突破三权分离）；SYSTEM_ADMIN 不含；
--   7) 补阶段1 遗留：apm_alert 组设置种子行（阈值与 systemalerts/endpoint_perf.go
--      消费侧默认值一致），使系统设置 Update API 可在线调整（白名单同步登记）。
BEGIN;

-- ---------- apm_services ----------
CREATE TABLE IF NOT EXISTS apm_services (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name   VARCHAR(128) NOT NULL,
    environment    VARCHAR(64)  NOT NULL DEFAULT 'production',
    application_id UUID REFERENCES applications(id) ON DELETE SET NULL,
    claim_status   VARCHAR(16)  NOT NULL DEFAULT 'UNCLAIMED'
                   CHECK (claim_status IN ('UNCLAIMED', 'CLAIMED')),
    first_seen_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (service_name, environment)
);

-- ---------- apm_agents ----------
CREATE TABLE IF NOT EXISTS apm_agents (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id        UUID NOT NULL REFERENCES apm_services(id) ON DELETE CASCADE,
    instance_id       VARCHAR(128) NOT NULL,
    language          VARCHAR(32)  NOT NULL,
    agent_version     VARCHAR(64)  NOT NULL DEFAULT '',
    sdk_version       VARCHAR(64)  NOT NULL DEFAULT '',
    -- §8.3 状态机存态：ENROLLING/CONNECTED_BASELINE/DIAGNOSING/REVOKED；
    -- OFFLINE 不落库（查询侧按心跳超时推导），REVOKED 为终态
    status            VARCHAR(24)  NOT NULL DEFAULT 'ENROLLING'
                      CHECK (status IN ('ENROLLING', 'CONNECTED_BASELINE', 'DIAGNOSING', 'REVOKED')),
    cert_fingerprint  CHAR(64)     NOT NULL UNIQUE,  -- 当前生效客户端证书 SHA-256（hex）
    cert_not_after    TIMESTAMPTZ  NOT NULL,
    last_heartbeat_at TIMESTAMPTZ,
    node_info         JSONB        NOT NULL DEFAULT '{}'::jsonb,  -- 自报节点信息（hostname/ip/os 等，仅展示，不入鉴权）
    registered_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    revoked_at        TIMESTAMPTZ,
    revoke_reason     TEXT         NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_apm_agents_service ON apm_agents (service_id, instance_id);
CREATE INDEX IF NOT EXISTS idx_apm_agents_status ON apm_agents (status);

-- ---------- apm_enrollment_tokens ----------
CREATE TABLE IF NOT EXISTS apm_enrollment_tokens (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash       CHAR(64) NOT NULL UNIQUE,   -- SHA-256 hex；不存令牌原文
    application_id   UUID REFERENCES applications(id) ON DELETE CASCADE,
    environment      VARCHAR(64) NOT NULL DEFAULT 'production',
    allowed_languages JSONB     NOT NULL DEFAULT '[]'::jsonb,  -- 空数组 = 不限制语言
    expires_at       TIMESTAMPTZ NOT NULL,
    used_at          TIMESTAMPTZ,                -- 使用即作废（原子置位防重放/并发复用）
    used_by_agent_id UUID,
    note             TEXT NOT NULL DEFAULT '',
    created_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_apm_enrollment_tokens_expires ON apm_enrollment_tokens (expires_at) WHERE used_at IS NULL;

-- ---------- apm_agent_policies ----------
CREATE TABLE IF NOT EXISTS apm_agent_policies (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope      VARCHAR(160) NOT NULL,   -- 'global' 或 'application:<uuid>'
    version    BIGINT       NOT NULL,   -- 同一 scope 内单调递增（唯一约束 + 事务内 max+1）
    policy     JSONB        NOT NULL,
    signature  TEXT         NOT NULL,   -- Ed25519 签名 hex（域分隔前缀 + 规范 JSON 信封）
    key_id     VARCHAR(64)  NOT NULL DEFAULT 'apm-agent-ca',  -- 验签密钥标识（内置 CA 公钥）
    issued_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ  NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (scope, version)
);

-- ---------- apm_agent_cert_revocations ----------
CREATE TABLE IF NOT EXISTS apm_agent_cert_revocations (
    cert_fingerprint CHAR(64) PRIMARY KEY,   -- 被撤销证书 SHA-256（hex）
    agent_id         UUID NOT NULL REFERENCES apm_agents(id) ON DELETE CASCADE,
    revoked_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason           TEXT NOT NULL DEFAULT ''  -- revoked / rotated / superseded
);

-- ---------- APM 权限种子（manage 类；SECURITY_ADMIN 全量，AUDIT_ADMIN/SYSTEM_ADMIN 不授） ----------
INSERT INTO permissions (code, name, module, description) VALUES
('apm.agents.manage',   '管理APM探针',   'apm', '创建一次性注册令牌、查看Agent列表、撤销Agent（高风险操作）'),
('apm.settings.manage', '管理APM采集策略', 'apm', '读写APM Agent基线采集策略（签名版本单调递增，高风险操作）')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('apm.agents.manage', 'apm.settings.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- ---------- apm_alert 组设置种子（阶段1 遗留补齐；默认值与 endpoint_perf.go 消费侧一致） ----------
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('apm_alert', 'endpoint_p95_ms',     '2000', 'integer', FALSE, 'APM端点p95耗时告警阈值（毫秒）'),
('apm_alert', 'endpoint_error_rate', '0.2',  'number',  FALSE, 'APM端点5xx错误率告警阈值（0-1）'),
('apm_alert', 'min_requests',        '60',   'integer', FALSE, 'APM端点告警窗口最小请求量护栏'),
('apm_alert', 'sustain_minutes',     '3',    'integer', FALSE, 'APM端点告警持续超阈分钟桶数护栏')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
