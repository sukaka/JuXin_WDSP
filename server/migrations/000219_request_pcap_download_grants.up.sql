-- PCAP完整性核验结果与一次性下载授权；不保存会话Token、明文密码或明文DEK。
BEGIN;

ALTER TABLE request_pcap_artifacts
    ADD COLUMN integrity_status VARCHAR(24) NOT NULL DEFAULT 'UNVERIFIED'
        CHECK (integrity_status IN ('UNVERIFIED','PASS','FAILED','KEY_UNAVAILABLE')),
    ADD COLUMN last_verified_at TIMESTAMPTZ,
    ADD COLUMN verification_error_code VARCHAR(64);

CREATE TABLE request_pcap_download_grants (
    id                  UUID PRIMARY KEY,
    artifact_id         UUID NOT NULL REFERENCES request_pcap_artifacts(id) ON DELETE RESTRICT,
    request_id          VARCHAR(64) NOT NULL,
    user_id             UUID NOT NULL,
    session_id          VARCHAR(128) NOT NULL,
    reason              VARCHAR(500) NOT NULL,
    source_ip           INET,
    expires_at          TIMESTAMPTZ NOT NULL,
    consumed_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at)
);
CREATE INDEX idx_request_pcap_grants_artifact ON request_pcap_download_grants (artifact_id,created_at DESC);
CREATE INDEX idx_request_pcap_grants_expiry ON request_pcap_download_grants (expires_at) WHERE consumed_at IS NULL;
CREATE INDEX idx_request_pcap_grants_user ON request_pcap_download_grants (user_id,created_at DESC);

COMMIT;
