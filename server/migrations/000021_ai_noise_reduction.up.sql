-- 阶段7 增量：AI 自动降噪（确定性指纹聚类 + 可选 LLM 误报评分 + 降噪推荐草稿）
-- 边界：聚类/计数/折叠全自动；涉及处置的产物一律 DRAFT，不自动改事件处置、不自动封禁、不自动启用例外。

BEGIN;

-- ---------- 降噪簇 ----------
CREATE TABLE IF NOT EXISTS ai_noise_clusters (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source           VARCHAR(8)  NOT NULL,              -- WAF / API
    fingerprint_hash VARCHAR(64) NOT NULL,              -- sha256(source|host|normalized_uri|rule_id或detector_code|client_ip)
    application_id   UUID,
    host             VARCHAR(255) NOT NULL DEFAULT '',
    normalized_uri   TEXT         NOT NULL DEFAULT '',
    rule_id          INTEGER,
    detector_code    VARCHAR(64),
    client_ip        INET,
    event_count      INTEGER      NOT NULL DEFAULT 0,
    first_seen       TIMESTAMPTZ  NOT NULL,
    last_seen        TIMESTAMPTZ  NOT NULL,
    status           VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',    -- ACTIVE / SUPPRESSED / RESOLVED
    ai_verdict       VARCHAR(32)  NOT NULL DEFAULT 'UNKNOWN',   -- TRUE_POSITIVE / LIKELY_FALSE_POSITIVE / UNKNOWN
    ai_confidence    NUMERIC(4,3),
    ai_summary       TEXT         NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ai_noise_clusters_fingerprint ON ai_noise_clusters (source, fingerprint_hash);
CREATE INDEX IF NOT EXISTS idx_ai_noise_clusters_status ON ai_noise_clusters (status, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_ai_noise_clusters_verdict ON ai_noise_clusters (ai_verdict, last_seen DESC);

-- ---------- 簇内事件关联 ----------
-- event_id 为 security_events.id / api_runtime_events.id（前者为分区表无法建外键，仅逻辑关联）
CREATE TABLE IF NOT EXISTS ai_noise_cluster_events (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id        UUID NOT NULL REFERENCES ai_noise_clusters(id) ON DELETE CASCADE,
    event_id          UUID NOT NULL,
    source            VARCHAR(8) NOT NULL,              -- WAF / API
    is_representative BOOLEAN NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ai_noise_cluster_events ON ai_noise_cluster_events (cluster_id, event_id, source);
CREATE INDEX IF NOT EXISTS idx_ai_noise_cluster_events_cluster ON ai_noise_cluster_events (cluster_id, created_at);

-- ---------- 扫描运行记录 ----------
CREATE TABLE IF NOT EXISTS ai_noise_sweep_runs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at       TIMESTAMPTZ  NOT NULL,
    finished_at      TIMESTAMPTZ,
    scanned_events   INTEGER      NOT NULL DEFAULT 0,
    new_clusters     INTEGER      NOT NULL DEFAULT 0,
    updated_clusters INTEGER      NOT NULL DEFAULT 0,
    llm_calls        INTEGER      NOT NULL DEFAULT 0,
    tokens_used      INTEGER      NOT NULL DEFAULT 0,
    status           VARCHAR(16)  NOT NULL DEFAULT 'SUCCESS',   -- SUCCESS / FAILED / PARTIAL
    error            TEXT         NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_noise_sweep_runs_time ON ai_noise_sweep_runs (started_at DESC);

-- ---------- 权限种子 ----------
INSERT INTO permissions (code, name, module, description) VALUES
('ai.noise_reduction.use',    '使用AI自动降噪', 'ai', '查看降噪簇/统计/扫描历史与簇状态流转'),
('ai.noise_reduction.manage', '管理AI自动降噪', 'ai', '手动触发降噪扫描与修改降噪设置')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：使用（查看 + 簇状态流转）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN (
  'ai.noise_reduction.use'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 系统管理员：使用 + 管理（手动扫描与设置）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN (
  'ai.noise_reduction.use','ai.noise_reduction.manage'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
