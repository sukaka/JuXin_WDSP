-- AUTHZ-01: trusted object relations and OBSERVE authorization decisions.
BEGIN;

ALTER TABLE api_role_baselines
    ADD COLUMN IF NOT EXISTS identity_assurance TEXT NOT NULL DEFAULT 'OBSERVED'
        CHECK (identity_assurance IN ('OBSERVED', 'VERIFIED'));

ALTER TABLE api_object_models
    ADD COLUMN IF NOT EXISTS publishable BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS required_relation TEXT,
    ADD COLUMN IF NOT EXISTS owner_exclusive BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE api_object_models
    DROP CONSTRAINT IF EXISTS ck_api_object_models_required_relation;
ALTER TABLE api_object_models
    ADD CONSTRAINT ck_api_object_models_required_relation
    CHECK (required_relation IS NULL OR required_relation IN ('OWNER'));

CREATE TABLE IF NOT EXISTS api_object_relation_candidates (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id              UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    endpoint_id                 UUID REFERENCES api_endpoints(id) ON DELETE SET NULL,
    object_type                 TEXT NOT NULL,
    object_ref                  VARCHAR(160) NOT NULL CHECK (object_ref LIKE 'objref:%'),
    principal_id               VARCHAR(128),
    tenant_id                  VARCHAR(128),
    legacy_identity_fingerprint VARCHAR(128),
    source                     TEXT NOT NULL DEFAULT 'OBSERVED_ACCESS'
                               CHECK (source IN ('OBSERVED_ACCESS')),
    status                     TEXT NOT NULL DEFAULT 'PENDING'
                               CHECK (status IN ('PENDING','REJECTED','FROZEN','CONFIRMED')),
    source_count               INTEGER NOT NULL DEFAULT 1 CHECK (source_count > 0),
    observation_count          BIGINT NOT NULL DEFAULT 1 CHECK (observation_count > 0),
    first_seen                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    confidence_inputs          JSONB NOT NULL DEFAULT '{}',
    evidence_ref               TEXT,
    reject_reason              TEXT,
    reviewed_by                TEXT,
    reviewed_at                TIMESTAMPTZ,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_authz_candidate_identity_domain CHECK (
        (principal_id IS NOT NULL AND legacy_identity_fingerprint IS NULL)
        OR (principal_id IS NULL AND legacy_identity_fingerprint IS NOT NULL)
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_authz_candidate_verified
    ON api_object_relation_candidates(application_id, object_type, object_ref, principal_id)
    WHERE principal_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_authz_candidate_legacy
    ON api_object_relation_candidates(application_id, object_type, object_ref, legacy_identity_fingerprint)
    WHERE legacy_identity_fingerprint IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_authz_candidate_status
    ON api_object_relation_candidates(application_id, status, last_seen DESC);

-- 每个运行时事件只为候选关系记账一次。独立回执避免时间水位在同一微秒批次
-- 截断时漏数，也避免同一 OBSERVED_ACCESS 来源被重复清扫抬高 source_count。
CREATE TABLE IF NOT EXISTS api_authz_candidate_event_receipts (
    event_id      UUID PRIMARY KEY REFERENCES api_runtime_events(id) ON DELETE CASCADE,
    processed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_object_relations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id  UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    object_type     TEXT NOT NULL,
    object_ref      VARCHAR(160) NOT NULL CHECK (object_ref LIKE 'objref:%'),
    principal_id    VARCHAR(128) NOT NULL,
    tenant_id       VARCHAR(128),
    relation        TEXT NOT NULL CHECK (relation IN ('OWNER','SHARED_WITH','DELEGATED_TO','SUPPORT_ACCESS')),
    source          TEXT NOT NULL CHECK (source IN ('MANUAL','IMPORT','CREATE_BINDING')),
    status          TEXT NOT NULL DEFAULT 'CONFIRMED' CHECK (status IN ('CONFIRMED','REVOKED','EXPIRED')),
    valid_from      TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until     TIMESTAMPTZ,
    evidence_ref    TEXT,
    confirmed_by    TEXT NOT NULL,
    confirmed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason          TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_authz_relation_validity CHECK (valid_until IS NULL OR valid_until > valid_from),
    CONSTRAINT uq_authz_relation UNIQUE (application_id, object_type, object_ref, principal_id, relation)
);
CREATE INDEX IF NOT EXISTS idx_authz_relation_compile
    ON api_object_relations(application_id, object_type, status, valid_from, valid_until);

CREATE TABLE IF NOT EXISTS api_authorization_decisions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    decision_id     UUID NOT NULL,
    application_id  UUID REFERENCES applications(id) ON DELETE SET NULL,
    endpoint_key    VARCHAR(560) NOT NULL DEFAULT '',
    policy_version  TEXT NOT NULL DEFAULT '',
    decision        TEXT NOT NULL CHECK (decision IN ('ALLOW','OBSERVE_VIOLATION','UNKNOWN')),
    checks          JSONB NOT NULL DEFAULT '[]',
    evidence        JSONB NOT NULL DEFAULT '{}',
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_api_authorization_decision UNIQUE (decision_id)
);
CREATE INDEX IF NOT EXISTS idx_authz_decision_app_time
    ON api_authorization_decisions(application_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS api_authz_migration_state (
    migration_key TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('PENDING','RUNNING','COMPLETED','FAILED')),
    rows_migrated BIGINT NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO api_authz_migration_state(migration_key, status)
VALUES ('legacy_object_ownership_v1', 'PENDING')
ON CONFLICT (migration_key) DO NOTHING;

INSERT INTO permissions (code, name, module, description) VALUES
('api_authorization.relation_manage', '管理对象授权关系', 'api', '确认、拒绝候选及维护可信对象授权关系'),
('api_authorization.evidence_read', '查看授权证据', 'api', '查看授权决策中的脱敏证据详情')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.code = 'SECURITY_ADMIN'
  AND p.code IN ('api_authorization.relation_manage','api_authorization.evidence_read')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code = 'api_authorization.evidence_read'
ON CONFLICT DO NOTHING;

COMMIT;
