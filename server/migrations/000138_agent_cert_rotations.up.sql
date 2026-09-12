-- 000138 WDSP 机器身份证书轮换幂等响应。
-- 同一 Agent、旧指纹和 CSR 公钥只保留一次已签发身份，响应丢失后可安全重放。
BEGIN;

CREATE TABLE IF NOT EXISTS agent_cert_rotations (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id           UUID        NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    old_fingerprint    TEXT        NOT NULL,
    public_key_sha256  TEXT        NOT NULL,
    new_fingerprint    TEXT        NOT NULL,
    agent_cert_pem     TEXT        NOT NULL,
    ca_cert_pem        TEXT        NOT NULL,
    old_not_before     TIMESTAMPTZ NOT NULL,
    grace_until        TIMESTAMPTZ NOT NULL,
    new_not_after      TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_agent_cert_rotations_request
        UNIQUE (agent_id, old_fingerprint, public_key_sha256)
);

CREATE INDEX IF NOT EXISTS idx_agent_cert_rotations_agent
    ON agent_cert_rotations (agent_id, old_fingerprint);

COMMIT;
