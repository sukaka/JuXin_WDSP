-- 000183 机器身份登记（NG-ID g1 批次 B1，设计 docs/nextgen/NG-ID-g1-machine-identity.md
-- §1.2/D2）：machine_identities（身份）+ machine_identity_keys（公钥）两表
--（000181 mcp_tool_catalogs 同迁移两表先例）。
--
-- 语义边界（设计冻结）：
--   - 身份：identity_name 唯一（≤128）；tenant_id 可空（跨租户共享身份为 NULL+显式）；
--     principal_binding 可空（声明绑定 JWT VerifiedPrincipalID 指纹值——声明即强制一致，
--     不一致 401 MID-PRINCIPAL-MISMATCH，§1.1）；status ENABLED|DISABLED；
--     bot_challenge_exempt 缺省 false（Bot 精确豁免前提之一，§1.7）；version 乐观锁；
--   - 公钥：identity_id FK CASCADE；kid 身份内唯一（≤128）；alg CHECK 词表
--     ed25519|ecdsa-p256-sha256|rsa-pss-sha512（hmac-sha256 共享密钥形态与
--     rsa-v1_5-sha256（RFC 9421 标注不推荐）排除）；public_key_pem 明文（公钥非秘密）；
--     status 状态机 ACTIVE（可签发可验证）|RETIRED（重叠窗口内仅验证，窗口终点
--     retire_overlap_until）|REVOKED（立即拒验）；revoked_seq 撤销时水位值（溯源）；
--   - 公钥唯一来源=管理面静态离线导入（§1.3）；指纹（sha256 前 16 hex）由管理面
--     现算（不落列——逻辑模型四表冻结无指纹列，发布段形状亦无指纹键）。
BEGIN;

CREATE TABLE IF NOT EXISTS machine_identities (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_name        VARCHAR(128) NOT NULL,
    tenant_id            VARCHAR(128),
    principal_binding    VARCHAR(128),
    status               VARCHAR(16) NOT NULL DEFAULT 'ENABLED',
    bot_challenge_exempt BOOLEAN NOT NULL DEFAULT false,
    version              INTEGER NOT NULL DEFAULT 1,
    created_by           TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_machine_identities_name UNIQUE (identity_name),
    CONSTRAINT chk_machine_identities_status CHECK (status IN ('ENABLED','DISABLED'))
);

CREATE TABLE IF NOT EXISTS machine_identity_keys (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id          UUID NOT NULL REFERENCES machine_identities(id) ON DELETE CASCADE,
    kid                  VARCHAR(128) NOT NULL,
    alg                  VARCHAR(32) NOT NULL,
    public_key_pem       TEXT NOT NULL,
    status               VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
    not_before           TIMESTAMPTZ,
    not_after            TIMESTAMPTZ,
    retire_overlap_until TIMESTAMPTZ,
    revoked_seq          BIGINT,
    created_by           TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_machine_identity_keys_kid UNIQUE (identity_id, kid),
    CONSTRAINT chk_machine_identity_keys_alg
        CHECK (alg IN ('ed25519','ecdsa-p256-sha256','rsa-pss-sha512')),
    CONSTRAINT chk_machine_identity_keys_status CHECK (status IN ('ACTIVE','RETIRED','REVOKED')),
    CONSTRAINT chk_machine_identity_keys_validity
        CHECK (not_before IS NULL OR not_after IS NULL OR not_before < not_after)
);

CREATE INDEX IF NOT EXISTS idx_machine_identity_keys_identity ON machine_identity_keys (identity_id, kid);

COMMENT ON TABLE machine_identities IS '机器身份登记（NG-ID g1：HTTP Message Signatures 可信身份；可选叠加缺省 OFF）';
COMMENT ON TABLE machine_identity_keys IS '机器身份公钥（管理面静态离线导入；ACTIVE/RETIRED/REVOKED 状态机+重叠窗口+revoked_seq 水位溯源）';

COMMIT;
