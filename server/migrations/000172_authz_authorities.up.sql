-- 000172 权威关系接入（NG-AZ-01，docs/nextgen/NG-AZ-01-authority-ingest.md 冻结设计）。
--
--   权威来源登记/密钥轮换/导入批次/幂等消费/水位缺口/冲突六表 + 关系表溯源：
--   - api_object_relations.source 词表扩 AUTHORITY_SYNC（权威同步通道；与手工/导入/
--     建绑三通道区分）+ source_id/source_event_id/source_batch_id 三溯源列（可空，
--     非权威行保持空）；权威 GRANT 落 CONFIRMED 行即随既有快照发布链下发网关，
--     不重建关系 CRUD；
--   - api_authority_sources：来源登记（状态 ACTIVE/DISABLED、范围授权 scopes
--     {tenant_domains,object_types}、max_event_age_seconds 可空=不限、乐观锁 version）；
--   - api_authority_source_keys：验签公钥轮换（key_id 维度 ACTIVE/RETIRED + retired_at
--     支撑轮换窗口判定；与发布签名密钥/对象 HMAC 密钥三把钥匙不混用）；
--   - api_authority_import_batches：批次审计（APPLIED/REJECTED + counts + error——
--     拒绝批次同样留痕，不属于关系原子区）；
--   - api_authority_applied_events：幂等消费（(source_id,event_id) 主键 +
--     (source_id,sequence) 唯一——重放与重复序号双重水压）；
--   - api_authority_watermarks：每来源一行（last_sequence/last_event_id/
--     revocation_watermark 单调不下降、gap_from 可空=无缺口）；
--   - api_authority_conflicts：同 (object_type,tenant_domain,object_ref) 多有效 OWNER
--     冲突状态（不按最后到达者覆盖；OPEN/RESOLVED；principals 为去重数组）。
--   权限种子（仅 SECURITY_ADMIN；AUDIT/SYSTEM 不授——读沿用 api_authorization.read）：
--     api_authorization.authority_manage（来源登记/启停/范围/钥匙轮换）；
--     api_authorization.authority_import（离线签名批次导入）。
BEGIN;

-- ---------- 关系表溯源（权威通道词表 + 三列） ----------
ALTER TABLE api_object_relations DROP CONSTRAINT IF EXISTS api_object_relations_source_check;
ALTER TABLE api_object_relations
    ADD CONSTRAINT api_object_relations_source_check
    CHECK (source IN ('MANUAL','IMPORT','CREATE_BINDING','AUTHORITY_SYNC'));
ALTER TABLE api_object_relations ADD COLUMN IF NOT EXISTS source_id UUID;
ALTER TABLE api_object_relations ADD COLUMN IF NOT EXISTS source_event_id VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE api_object_relations ADD COLUMN IF NOT EXISTS source_batch_id UUID;
CREATE INDEX IF NOT EXISTS idx_authz_relation_authority
    ON api_object_relations (source_id, application_id, status) WHERE source = 'AUTHORITY_SYNC';

-- ---------- 来源登记 ----------
CREATE TABLE IF NOT EXISTS api_authority_sources (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                   TEXT NOT NULL UNIQUE,
    status                 TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED')),
    scopes                 JSONB NOT NULL DEFAULT '{"tenant_domains":[],"object_types":[]}'::jsonb,
    max_event_age_seconds  BIGINT,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    version                INT NOT NULL DEFAULT 1
);
COMMENT ON TABLE api_authority_sources IS '权威关系来源登记（NG-AZ-01）：scopes 范围授权 {tenant_domains,object_types}；未登记/停用来源的导入一律拒收';

CREATE TABLE IF NOT EXISTS api_authority_source_keys (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id      UUID NOT NULL REFERENCES api_authority_sources(id) ON DELETE CASCADE,
    key_id         VARCHAR(64) NOT NULL,
    public_key_hex VARCHAR(64) NOT NULL,
    status         TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','RETIRED')),
    retired_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_authority_source_key UNIQUE (source_id, key_id)
);
COMMENT ON TABLE api_authority_source_keys IS '来源验签公钥（Ed25519 32 字节 hex；轮换窗口：RETIRED 键仅验 issued_at ≤ retired_at + 来源最大事件年龄（缺省 24h）的事件）';

-- ---------- 导入批次与幂等消费 ----------
CREATE TABLE IF NOT EXISTS api_authority_import_batches (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id  UUID NOT NULL REFERENCES api_authority_sources(id) ON DELETE CASCADE,
    mode       TEXT NOT NULL CHECK (mode IN ('snapshot','delta')),
    status     TEXT NOT NULL CHECK (status IN ('APPLIED','REJECTED')),
    counts     JSONB NOT NULL DEFAULT '{}'::jsonb,
    error      TEXT NOT NULL DEFAULT '',
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_authority_batches_source_time
    ON api_authority_import_batches (source_id, created_at DESC);

CREATE TABLE IF NOT EXISTS api_authority_applied_events (
    source_id   UUID NOT NULL REFERENCES api_authority_sources(id) ON DELETE CASCADE,
    event_id    VARCHAR(128) NOT NULL,
    sequence    BIGINT NOT NULL CHECK (sequence > 0),
    batch_id    UUID NOT NULL,
    change_type TEXT NOT NULL CHECK (change_type IN ('GRANT','REVOKE')),
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (source_id, event_id),
    CONSTRAINT uq_authority_applied_sequence UNIQUE (source_id, sequence)
);
COMMENT ON TABLE api_authority_applied_events IS '权威事件幂等消费账本（event_id 主键 + sequence 唯一——重复/乱序/缺口判定的事实源）';

-- ---------- 水位与缺口 ----------
CREATE TABLE IF NOT EXISTS api_authority_watermarks (
    source_id            UUID PRIMARY KEY REFERENCES api_authority_sources(id) ON DELETE CASCADE,
    last_sequence        BIGINT NOT NULL DEFAULT 0,
    last_event_id        VARCHAR(128) NOT NULL DEFAULT '',
    revocation_watermark BIGINT NOT NULL DEFAULT 0,
    gap_from             BIGINT,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE api_authority_watermarks IS '来源水位（last_sequence/revocation_watermark 单调不下降；gap_from 可空=无缺口，缺口即 AUTHZ_SOURCE_GAP）';

-- ---------- 冲突状态 ----------
CREATE TABLE IF NOT EXISTS api_authority_conflicts (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL,
    object_type    TEXT NOT NULL,
    tenant_domain  VARCHAR(128) NOT NULL DEFAULT '',
    object_ref     VARCHAR(160) NOT NULL,
    principals     JSONB NOT NULL DEFAULT '[]'::jsonb,
    status         TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','RESOLVED')),
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_authority_conflict_object UNIQUE (object_type, tenant_domain, object_ref)
);
COMMENT ON TABLE api_authority_conflicts IS '权威冲突状态：同对象两个不同 principal 的有效 OWNER（不按最后到达者覆盖；冲突对象不参与 VERIFIED_VIOLATION 判定）';

-- ---------- 权限种子（仅 SECURITY_ADMIN） ----------
INSERT INTO permissions (code, name, module, description) VALUES
('api_authorization.authority_manage', '管理权威关系来源', 'api', '权威来源登记/启停/范围授权/验签钥匙轮换（NG-AZ-01）'),
('api_authorization.authority_import', '导入权威关系批次', 'api', '离线签名批次导入（五步校验链；NG-AZ-01）')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('api_authorization.authority_manage','api_authorization.authority_import')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员不授（写动作）；系统管理员不授（安全运营域，同 000169 口径）。

COMMIT;
