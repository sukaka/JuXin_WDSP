-- 000134 安全回归证据登记与发布门禁（WDSP P1-04 R3；任务书
-- docs/tasks/wdsp-p1/P1-04_RULE_MODEL_REGRESSION.md §6.2/§7）。
--   security_regression_objects：受控证据对象登记（对象 ID 服务端生成；
--     写入仅经受控登记接口，流式 sha256，按 kind 限额；内容存受控本地目录，
--     原始大文件不进数据库行；sha256/size 登记后不可变，只读读取不泄露越权对象）。
--   security_regression_runs：不可变运行摘要（run_id 唯一；declared_status 为
--     验证服务声明值，verification_status 为服务端独立核验结论——客户端提交
--     status=PASS 不能直接成为后端通过状态；签名 key_id/算法、候选指纹、
--     语料/计划/构建指纹、执行计数与导入时门禁策略版本一并留存）。
--   security_regression_cases：用例索引/差异（UNIQUE(run_ref, case_id) 保用例
--     唯一性；不含原始请求/响应正文，仅存状态与差异摘要）。
--   security_regression_run_objects：运行 ↔ 证据对象引用（导入逐块校验后落
--     关联；事务失败整体回滚，不残留可用的半份报告）。
--   security_regression_policy：发布门禁策略单行（mode 默认 OFF；version 乐观锁，
--     PUT 携带 expected_version 冲突 409；有效期秒数，建议 7 天）。
--   security_regression_gate_decisions：每次发布的门禁判定留痕（OFF 不记录；
--     OBSERVE 记录放行结论；ENFORCE 记录放行/阻止及逐项原因；追加式不可变）。
BEGIN;

CREATE TABLE IF NOT EXISTS security_regression_objects (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind         VARCHAR(16)  NOT NULL
                 CHECK (kind IN ('MANIFEST', 'CASES_CHUNK', 'REPORT', 'PERF', 'LOG')),
    sha256       CHAR(64)     NOT NULL,
    size_bytes   BIGINT       NOT NULL CHECK (size_bytes >= 0),
    storage_path TEXT         NOT NULL,
    state        VARCHAR(16)  NOT NULL DEFAULT 'REGISTERED'
                 CHECK (state IN ('REGISTERED', 'CONSUMED')),
    uploaded_by  VARCHAR(255) NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sreg_objects_sha256 ON security_regression_objects (sha256);

CREATE TABLE IF NOT EXISTS security_regression_runs (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id               VARCHAR(128) NOT NULL UNIQUE,
    manifest_sha256      CHAR(64)     NOT NULL,
    level                VARCHAR(16)  NOT NULL
                         CHECK (level IN ('SMOKE', 'FULL', 'RELEASE')),
    declared_status      VARCHAR(16)  NOT NULL
                         CHECK (declared_status IN ('PASS', 'FAIL', 'SKIP', 'BLOCKED', 'NOT_RUN')),
    verification_status  VARCHAR(16)  NOT NULL DEFAULT 'PENDING'
                         CHECK (verification_status IN ('PENDING', 'PASSED', 'FAILED')),
    verification_reasons JSONB        NOT NULL DEFAULT '[]'::jsonb,
    signature_algorithm  VARCHAR(32)  NOT NULL,
    signature_key_id     VARCHAR(128) NOT NULL,
    config_fingerprint   VARCHAR(160) NOT NULL,
    build_digest         VARCHAR(160) NOT NULL DEFAULT '',
    compiler             VARCHAR(160) NOT NULL DEFAULT '',
    corpus_id            VARCHAR(128) NOT NULL,
    corpus_version       INT          NOT NULL DEFAULT 0,
    corpus_sha256        CHAR(64)     NOT NULL,
    plan_sha256          CHAR(64)     NOT NULL,
    planned_count        INT          NOT NULL DEFAULT 0,
    executed_count       INT          NOT NULL DEFAULT 0,
    skipped_count        INT          NOT NULL DEFAULT 0,
    blocked_count        INT          NOT NULL DEFAULT 0,
    not_run_count        INT          NOT NULL DEFAULT 0,
    passed_count         INT          NOT NULL DEFAULT 0,
    failed_count         INT          NOT NULL DEFAULT 0,
    mandatory_total      INT          NOT NULL DEFAULT 0,
    mandatory_failed     INT          NOT NULL DEFAULT 0,
    run_started_at       TIMESTAMPTZ,
    run_finished_at      TIMESTAMPTZ,
    policy_version       INT          NOT NULL DEFAULT 0,
    imported_by          VARCHAR(255) NOT NULL DEFAULT '',
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sreg_runs_fingerprint ON security_regression_runs (config_fingerprint);
CREATE INDEX IF NOT EXISTS idx_sreg_runs_created ON security_regression_runs (created_at DESC);

CREATE TABLE IF NOT EXISTS security_regression_cases (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_ref      UUID         NOT NULL REFERENCES security_regression_runs(id) ON DELETE CASCADE,
    case_id      VARCHAR(160) NOT NULL,
    case_version INT          NOT NULL DEFAULT 0,
    family       VARCHAR(128) NOT NULL DEFAULT '',
    truth        VARCHAR(16)  NOT NULL DEFAULT 'UNKNOWN'
                 CHECK (truth IN ('BENIGN', 'ATTACK', 'UNKNOWN')),
    criticality  VARCHAR(16)  NOT NULL DEFAULT 'OPTIONAL'
                 CHECK (criticality IN ('MANDATORY', 'OPTIONAL')),
    status       VARCHAR(16)  NOT NULL
                 CHECK (status IN ('PASS', 'FAIL', 'SKIP', 'BLOCKED', 'NOT_RUN')),
    diff_summary JSONB        NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (run_ref, case_id)
);
CREATE INDEX IF NOT EXISTS idx_sreg_cases_run ON security_regression_cases (run_ref);

CREATE TABLE IF NOT EXISTS security_regression_run_objects (
    run_ref    UUID        NOT NULL REFERENCES security_regression_runs(id) ON DELETE CASCADE,
    object_ref UUID        NOT NULL REFERENCES security_regression_objects(id),
    role       VARCHAR(16) NOT NULL
               CHECK (role IN ('MANIFEST', 'CASES_CHUNK', 'REPORT', 'PERF', 'LOG')),
    sha256     CHAR(64)    NOT NULL,
    UNIQUE (run_ref, object_ref)
);

CREATE TABLE IF NOT EXISTS security_regression_policy (
    id                     SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    mode                   VARCHAR(16) NOT NULL DEFAULT 'OFF'
                           CHECK (mode IN ('OFF', 'OBSERVE', 'ENFORCE')),
    required_level         VARCHAR(16) NOT NULL DEFAULT 'FULL'
                           CHECK (required_level IN ('SMOKE', 'FULL', 'RELEASE')),
    required_corpus_id     VARCHAR(128) NOT NULL DEFAULT '',
    evidence_max_age_seconds BIGINT    NOT NULL DEFAULT 604800
                           CHECK (evidence_max_age_seconds BETWEEN 86400 AND 2592000),
    version                INT          NOT NULL DEFAULT 1,
    updated_by             VARCHAR(255) NOT NULL DEFAULT '',
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT now()
);
INSERT INTO security_regression_policy (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS security_regression_gate_decisions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    publish_task_id UUID,
    version_id      UUID,
    fingerprint     VARCHAR(160) NOT NULL,
    mode            VARCHAR(16)  NOT NULL
                    CHECK (mode IN ('OFF', 'OBSERVE', 'ENFORCE')),
    decision        VARCHAR(16)  NOT NULL
                    CHECK (decision IN ('ALLOW', 'BLOCK', 'RECORD')),
    restore_channel BOOLEAN      NOT NULL DEFAULT false,
    reasons         JSONB        NOT NULL DEFAULT '[]'::jsonb,
    run_ref         UUID         REFERENCES security_regression_runs(id),
    policy_version  INT          NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sreg_gate_task ON security_regression_gate_decisions (publish_task_id);

COMMIT;
