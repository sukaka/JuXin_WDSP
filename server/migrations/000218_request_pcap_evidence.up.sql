-- 请求级 PCAP 证据元数据、独立权限与默认关闭策略。PCAP正文和明文密钥不入库。
BEGIN;

CREATE TABLE request_pcap_artifacts (
    id                      UUID PRIMARY KEY,
    gateway_node_id         VARCHAR(64) NOT NULL,
    capture_point           VARCHAR(32) NOT NULL,
    state                   VARCHAR(24) NOT NULL CHECK (state IN ('HOT','MIGRATING','WARM','EXPIRING','EXPIRED','UNAVAILABLE')),
    storage_tier            VARCHAR(16) NOT NULL CHECK (storage_tier IN ('HOT','WARM','COLD')),
    capture_started_at      TIMESTAMPTZ NOT NULL,
    capture_ended_at        TIMESTAMPTZ NOT NULL,
    packet_count            BIGINT NOT NULL CHECK (packet_count >= 0),
    dropped_count           BIGINT NOT NULL CHECK (dropped_count >= 0),
    truncated               BOOLEAN NOT NULL DEFAULT FALSE,
    plaintext_size_bytes    BIGINT NOT NULL CHECK (plaintext_size_bytes >= 0),
    ciphertext_size_bytes   BIGINT NOT NULL CHECK (ciphertext_size_bytes > 0),
    plaintext_sha256        VARCHAR(64) NOT NULL CHECK (plaintext_sha256 ~ '^[0-9a-f]{64}$'),
    ciphertext_sha256       VARCHAR(64) NOT NULL CHECK (ciphertext_sha256 ~ '^[0-9a-f]{64}$'),
    encryption_algorithm    VARCHAR(32) NOT NULL CHECK (encryption_algorithm = 'AES-256-GCM'),
    chunk_size_bytes        INTEGER NOT NULL CHECK (chunk_size_bytes > 0 AND chunk_size_bytes <= 16777216),
    chunk_count             BIGINT NOT NULL CHECK (chunk_count >= 0),
    wrapped_dek             BYTEA NOT NULL CHECK (octet_length(wrapped_dek) > 0 AND octet_length(wrapped_dek) <= 4096),
    key_id                  VARCHAR(128) NOT NULL,
    policy_version          VARCHAR(128),
    manifest_json           JSONB NOT NULL,
    expires_at              TIMESTAMPTZ NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (capture_ended_at >= capture_started_at),
    CHECK (expires_at > capture_ended_at)
);
CREATE INDEX idx_request_pcap_artifacts_retention ON request_pcap_artifacts (state, expires_at);
CREATE INDEX idx_request_pcap_artifacts_node_time ON request_pcap_artifacts (gateway_node_id, capture_started_at DESC);

CREATE TABLE request_pcap_links (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id         UUID NOT NULL REFERENCES request_pcap_artifacts(id) ON DELETE RESTRICT,
    request_id          VARCHAR(64) NOT NULL,
    trace_id            VARCHAR(32) CHECK (trace_id IS NULL OR (trace_id ~ '^[0-9a-f]{32}$' AND trace_id <> '00000000000000000000000000000000')),
    application_id      UUID,
    match_status        VARCHAR(16) NOT NULL CHECK (match_status IN ('PENDING','MATCHED','AMBIGUOUS','UNMATCHED','FAILED')),
    match_basis         VARCHAR(64) NOT NULL,
    coverage            VARCHAR(16) NOT NULL CHECK (coverage IN ('REQUEST','CONNECTION','UNKNOWN')),
    candidate_count     INTEGER NOT NULL CHECK (candidate_count >= 0),
    first_packet_no     BIGINT CHECK (first_packet_no IS NULL OR first_packet_no > 0),
    last_packet_no      BIGINT CHECK (last_packet_no IS NULL OR last_packet_no >= first_packet_no),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    UNIQUE (artifact_id, request_id, coverage)
);
CREATE INDEX idx_request_pcap_links_request ON request_pcap_links (request_id, match_status);
CREATE INDEX idx_request_pcap_links_trace ON request_pcap_links (trace_id) WHERE trace_id IS NOT NULL;
CREATE INDEX idx_request_pcap_links_expiry ON request_pcap_links (expires_at);

CREATE TABLE request_pcap_custody_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id         UUID NOT NULL REFERENCES request_pcap_artifacts(id) ON DELETE RESTRICT,
    occurred_at         TIMESTAMPTZ NOT NULL,
    event_type          VARCHAR(32) NOT NULL,
    actor               VARCHAR(128) NOT NULL,
    previous_hash       VARCHAR(64),
    event_hash          VARCHAR(64) NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
    details_json        JSONB NOT NULL DEFAULT '{}',
    UNIQUE (artifact_id, event_hash)
);
CREATE INDEX idx_request_pcap_custody_artifact ON request_pcap_custody_events (artifact_id, occurred_at);

INSERT INTO permissions (code, name, module, description) VALUES
('request_pcap.read', '查看请求PCAP状态', 'request_pcap', '查看捕获、关联、完整性与非内容清单'),
('request_pcap.download', '下载请求PCAP证据', 'request_pcap', '申请并执行受控请求PCAP派生下载'),
('request_pcap.manage', '管理请求PCAP策略', 'request_pcap', '修改抓包范围、冷热配额和保留期'),
('request_pcap.verify', '核验请求PCAP完整性', 'request_pcap', '执行有界证据完整性核验')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.code LIKE 'request_pcap.%'
WHERE r.code='SECURITY_ADMIN'
ON CONFLICT (role_id,permission_id) DO NOTHING;

INSERT INTO system_settings (setting_group,setting_key,setting_value,value_type,is_sensitive,description) VALUES
('request_pcap','enabled','false','boolean',FALSE,'请求PCAP证据总开关；默认关闭，须完成容量验收后启用'),
('request_pcap','capture_mode','"EVIDENCE"','string',FALSE,'FULL全量或EVIDENCE事件留存；不得混淆覆盖范围'),
('request_pcap','hot_max_age_seconds','3600','integer',FALSE,'SSD热分片最长保留秒数（须同时受容量限制）'),
('request_pcap','hot_max_bytes','10737418240','integer',FALSE,'SSD热区分片硬配额字节数；独立于系统根分区'),
('request_pcap','warm_retention_days','7','integer',FALSE,'SAS温证据保留天数；到期流程与日志分离'),
('request_pcap','segment_max_bytes','268435456','integer',FALSE,'单个PCAP分片最大字节数候选值，须按压测调整'),
('request_pcap','segment_max_seconds','60','integer',FALSE,'单个PCAP分片最长写入秒数候选值，须按压测调整')
ON CONFLICT (setting_group,setting_key) DO NOTHING;

COMMIT;
