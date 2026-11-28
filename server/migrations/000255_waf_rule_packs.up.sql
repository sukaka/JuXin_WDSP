-- 000255 纯离线 WAF 规则包热更新（阶段 R1）：
--   a) waf_rule_packs：规则包档案主表（含内嵌 Ed25519 验签元信息、预检差异报告与持久化签名归档路径）
--   b) waf_rule_pack_jobs：规则包应用 / 回滚执行任务表（串联 gateway_publish_tasks 与自动元数据同步报告）
--   c) waf_rule_pack_node_states：HA 逐节点执行明细表（为 R2 hasyncd 协同预留完整落库模型）
--   d) waf_rules 增量列：is_active + last_rulepack_version（支持跨 CRS 版本软归档，保留历史事件/漏洞档案溯源）
--   e) gateway_config_versions 补充 rulepack_version 列（供规则包快照 GC 保护与配置回滚一致性校验）
--   f) 权限种子：waf_rules.pack.manage（遵循 000232 三权边界：业务防护规则归 SECURITY_ADMIN，AUDIT_ADMIN 保持 waf_rules.read 只读）
BEGIN;

-- a) 规则包档案表
CREATE TABLE IF NOT EXISTS waf_rule_packs (
    id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    rulepack_version   VARCHAR(64)  NOT NULL UNIQUE,
    crs_version        VARCHAR(32)  NOT NULL,
    min_system_version VARCHAR(32)  NOT NULL DEFAULT '',
    coraza_compat      VARCHAR(64)  NOT NULL DEFAULT '',
    is_builtin         BOOLEAN      NOT NULL DEFAULT FALSE,
    file_name          VARCHAR(255) NOT NULL,
    file_size          BIGINT       NOT NULL DEFAULT 0 CHECK (file_size >= 0),
    file_sha256        VARCHAR(64)  NOT NULL DEFAULT '',
    manifest_sha256    VARCHAR(64)  NOT NULL DEFAULT '',
    manifest_json      JSONB        NOT NULL DEFAULT '{}'::jsonb,
    preview_report     JSONB        NOT NULL DEFAULT '{}'::jsonb,
    archive_path       TEXT         NOT NULL DEFAULT '',
    status             VARCHAR(24)  NOT NULL
                       CHECK (status IN ('VERIFIED', 'REJECTED', 'APPLIED', 'SUPERSEDED', 'ROLLED_BACK')),
    reject_reason      TEXT         NOT NULL DEFAULT '',
    uploaded_by        UUID         NULL REFERENCES users(id) ON DELETE SET NULL,
    uploaded_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    applied_by         UUID         NULL REFERENCES users(id) ON DELETE SET NULL,
    applied_at         TIMESTAMPTZ  NULL,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE waf_rule_packs IS
    '纯离线 WAF 规则包档案表（记录验签通过/拒绝/生效/历史替代/回滚的全量规则包快照）';

-- 数据库级保证同一时刻最多一个激活规则包
CREATE UNIQUE INDEX IF NOT EXISTS uq_waf_rule_packs_single_applied
    ON waf_rule_packs (status)
    WHERE status = 'APPLIED';

CREATE INDEX IF NOT EXISTS idx_waf_rule_packs_created_at
    ON waf_rule_packs (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_waf_rule_packs_status
    ON waf_rule_packs (status, updated_at DESC);

-- b) 规则包应用 / 回滚执行任务表
CREATE TABLE IF NOT EXISTS waf_rule_pack_jobs (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type          VARCHAR(16) NOT NULL CHECK (job_type IN ('APPLY', 'ROLLBACK')),
    target_pack_id    UUID        NOT NULL REFERENCES waf_rule_packs(id) ON DELETE RESTRICT,
    previous_pack_id  UUID        NULL REFERENCES waf_rule_packs(id) ON DELETE SET NULL,
    publish_task_id   UUID        NULL REFERENCES gateway_publish_tasks(id) ON DELETE SET NULL,
    status            VARCHAR(32) NOT NULL
                      CHECK (status IN (
                          'PENDING', 'STAGING_LOCAL', 'STAGING_STANDBY',
                          'PUBLISHING', 'ACTIVATING', 'SYNCING_METADATA',
                          'SUCCESS', 'ROLLING_BACK', 'ROLLED_BACK', 'FAILED'
                      )),
    current_step      VARCHAR(64) NOT NULL DEFAULT '',
    progress          INT         NOT NULL DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
    allow_degraded_ha BOOLEAN     NOT NULL DEFAULT FALSE,
    degraded_reason   TEXT        NOT NULL DEFAULT '',
    sync_report       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    failure_code      VARCHAR(64) NOT NULL DEFAULT '',
    failure_message   TEXT        NOT NULL DEFAULT '',
    requested_by      UUID        NULL REFERENCES users(id) ON DELETE SET NULL,
    request_id        VARCHAR(64) NOT NULL DEFAULT '',
    started_at        TIMESTAMPTZ NULL,
    finished_at       TIMESTAMPTZ NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE waf_rule_pack_jobs IS
    '纯离线 WAF 规则包应用与回滚执行任务表（记录阶段状态、关联配置发布任务与规则元数据同步报告）';

CREATE INDEX IF NOT EXISTS idx_waf_rule_pack_jobs_created_at
    ON waf_rule_pack_jobs (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_waf_rule_pack_jobs_status
    ON waf_rule_pack_jobs (status)
    WHERE status NOT IN ('SUCCESS', 'ROLLED_BACK', 'FAILED');

-- c) HA 逐节点执行明细表
CREATE TABLE IF NOT EXISTS waf_rule_pack_node_states (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id          UUID         NOT NULL REFERENCES waf_rule_pack_jobs(id) ON DELETE CASCADE,
    node_id         UUID         NULL,
    node_name       VARCHAR(128) NOT NULL,
    role            VARCHAR(16)  NOT NULL CHECK (role IN ('PRIMARY', 'STANDBY')),
    stage_status    VARCHAR(24)  NOT NULL DEFAULT 'PENDING'
                    CHECK (stage_status IN ('PENDING', 'SUCCESS', 'FAILED', 'SKIPPED')),
    load_status     VARCHAR(24)  NOT NULL DEFAULT 'PENDING'
                    CHECK (load_status IN ('PENDING', 'SUCCESS', 'FAILED', 'SKIPPED')),
    activate_status VARCHAR(24)  NOT NULL DEFAULT 'PENDING'
                    CHECK (activate_status IN ('PENDING', 'SUCCESS', 'FAILED', 'SKIPPED')),
    error_code      VARCHAR(64)  NOT NULL DEFAULT '',
    error_message   TEXT         NOT NULL DEFAULT '',
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE waf_rule_pack_node_states IS
    'HA 集群规则包逐节点落盘、配置加载与切换明细表';

CREATE INDEX IF NOT EXISTS idx_waf_rule_pack_node_states_job
    ON waf_rule_pack_node_states (job_id, role, node_name);

-- d) waf_rules 增量列（软归档旧版本，保留历史安全事件与漏洞档案溯源）
ALTER TABLE waf_rules
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS last_rulepack_version VARCHAR(64) NOT NULL DEFAULT '';

COMMENT ON COLUMN waf_rules.is_active IS '是否属于当前生效规则包（跨 CRS 版本升级或规则下线时置 FALSE 软归档，不物理删除）';
COMMENT ON COLUMN waf_rules.last_rulepack_version IS '最近一次同步该规则的规则包版本号';

CREATE INDEX IF NOT EXISTS idx_waf_rules_active_attack
    ON waf_rules (is_active, attack_type);

-- e) gateway_config_versions 补充 rulepack_version 列
ALTER TABLE gateway_config_versions
    ADD COLUMN IF NOT EXISTS rulepack_version VARCHAR(64) NOT NULL DEFAULT '';

COMMENT ON COLUMN gateway_config_versions.rulepack_version IS '该配置版本生成时绑定的规则包版本号（用于规则快照 GC 保护与配置回滚一致性校验）';

-- f) 权限种子（遵循 000232 三权边界：规则防护管理归 SECURITY_ADMIN，AUDIT_ADMIN 沿用 waf_rules.read 只读）
INSERT INTO permissions (code, name, module, description) VALUES
('waf_rules.pack.manage', '离线规则包更新管理', 'waf_rules', '上传、预检、应用与回滚纯离线 WAF 规则包，及补发 HA 节点规则快照')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('waf_rules.pack.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
