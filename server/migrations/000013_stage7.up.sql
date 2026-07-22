-- 阶段7 初始迁移：AI模型网关、会话与消息、任务与调度、Agent/Tool、Prompt、Memory、推荐、压缩、评估、用量与审计

BEGIN;

-- ---------- 模型供应商与模型 ----------
CREATE TABLE IF NOT EXISTS ai_model_providers (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name           VARCHAR(100) NOT NULL,
    provider_type  VARCHAR(30)  NOT NULL,           -- openai_compatible / anthropic / ollama / local
    base_url       VARCHAR(255) NOT NULL,
    api_key_reference VARCHAR(100) NOT NULL DEFAULT '',  -- 密钥引用名（密文存 ai_provider_secrets）
    status         VARCHAR(20)  NOT NULL DEFAULT 'ENABLED',
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ai_model_providers_name ON ai_model_providers (name);

-- 供应商密钥（AES-256-GCM 加密存储，永不回传前端）
CREATE TABLE IF NOT EXISTS ai_provider_secrets (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reference     VARCHAR(100) NOT NULL UNIQUE,     -- 引用名（如 provider 的 api_key_reference）
    encrypted_key TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS ai_models (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id                 UUID NOT NULL REFERENCES ai_model_providers(id),
    model_code                  VARCHAR(100) NOT NULL,
    display_name                VARCHAR(100) NOT NULL,
    context_window              INTEGER NOT NULL DEFAULT 8192,
    max_output_tokens           INTEGER NOT NULL DEFAULT 2048,
    supports_tools              BOOLEAN NOT NULL DEFAULT FALSE,
    supports_streaming          BOOLEAN NOT NULL DEFAULT TRUE,
    supports_structured_output  BOOLEAN NOT NULL DEFAULT FALSE,
    supports_embeddings         BOOLEAN NOT NULL DEFAULT FALSE,
    priority                    INTEGER NOT NULL DEFAULT 100,
    timeout_seconds             INTEGER NOT NULL DEFAULT 60,
    cost_input_unit             NUMERIC(12,8) NOT NULL DEFAULT 0,   -- 每千输入Token成本单位
    cost_output_unit            NUMERIC(12,8) NOT NULL DEFAULT 0,
    status                      VARCHAR(20) NOT NULL DEFAULT 'ENABLED',
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ai_models_provider_code ON ai_models (provider_id, model_code);

-- ---------- 会话与消息 ----------
CREATE TABLE IF NOT EXISTS ai_sessions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL,
    title              VARCHAR(200) NOT NULL DEFAULT '新会话',
    status             VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE',  -- ACTIVE / ARCHIVED
    project_scope      VARCHAR(50)  NOT NULL DEFAULT '',
    application_ids    JSONB,
    context_summary    TEXT NOT NULL DEFAULT '',
    context_token_count INTEGER NOT NULL DEFAULT 0,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived_at        TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_ai_sessions_user ON ai_sessions (user_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS ai_messages (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id        UUID NOT NULL REFERENCES ai_sessions(id) ON DELETE CASCADE,
    role              VARCHAR(20) NOT NULL,              -- user / assistant / system / tool
    content           TEXT NOT NULL,
    content_masked    BOOLEAN NOT NULL DEFAULT FALSE,
    model_id          UUID,
    prompt_version_id UUID,
    input_tokens      INTEGER NOT NULL DEFAULT 0,
    output_tokens     INTEGER NOT NULL DEFAULT 0,
    finish_reason     VARCHAR(20) NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_messages_session ON ai_messages (session_id, created_at);

-- ---------- 任务与调度 ----------
CREATE TABLE IF NOT EXISTS ai_tasks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES ai_sessions(id) ON DELETE CASCADE,
    task_type       VARCHAR(40) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- PENDING/PLANNING/RUNNING/WAITING_TOOL/COMPOSING/SUCCESS/PARTIAL_SUCCESS/FAILED/CANCELLED
    risk_level      VARCHAR(20) NOT NULL DEFAULT 'LOW',
    plan_summary    TEXT NOT NULL DEFAULT '',
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    failure_code    VARCHAR(50) NOT NULL DEFAULT '',
    failure_message VARCHAR(500) NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_tasks_session ON ai_tasks (session_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_tasks_status ON ai_tasks (status, created_at DESC);

CREATE TABLE IF NOT EXISTS ai_agent_runs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id        UUID NOT NULL REFERENCES ai_tasks(id) ON DELETE CASCADE,
    agent_id       UUID NOT NULL,
    status         VARCHAR(20) NOT NULL DEFAULT 'RUNNING', -- RUNNING / SUCCESS / FAILED / CANCELLED
    input_summary  VARCHAR(500) NOT NULL DEFAULT '',
    output_summary VARCHAR(1000) NOT NULL DEFAULT '',
    started_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at    TIMESTAMPTZ,
    model_id       UUID,
    input_tokens   INTEGER NOT NULL DEFAULT 0,
    output_tokens  INTEGER NOT NULL DEFAULT 0,
    error_code     VARCHAR(50) NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_agent_runs_task ON ai_agent_runs (task_id, created_at);

CREATE TABLE IF NOT EXISTS ai_tool_calls (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id          UUID NOT NULL REFERENCES ai_tasks(id) ON DELETE CASCADE,
    agent_run_id     UUID,
    tool_id          VARCHAR(100) NOT NULL,
    tool_version     VARCHAR(20) NOT NULL DEFAULT '1.0',
    risk_level       VARCHAR(20) NOT NULL DEFAULT 'READ_ONLY',
    input_summary    VARCHAR(500) NOT NULL DEFAULT '',
    output_reference VARCHAR(100) NOT NULL DEFAULT '',
    status           VARCHAR(20) NOT NULL DEFAULT 'SUCCESS', -- SUCCESS / FAILED / TIMEOUT / DENIED
    duration_ms      INTEGER NOT NULL DEFAULT 0,
    error_code       VARCHAR(50) NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_tool_calls_task ON ai_tool_calls (task_id, created_at);

-- ---------- Agent 与 Tool 注册 ----------
CREATE TABLE IF NOT EXISTS ai_agents (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code             VARCHAR(50) NOT NULL UNIQUE,
    name             VARCHAR(100) NOT NULL,
    description      VARCHAR(500) NOT NULL DEFAULT '',
    prompt_id        UUID,
    allowed_tool_ids JSONB NOT NULL DEFAULT '[]',
    status           VARCHAR(20) NOT NULL DEFAULT 'ENABLED',
    version          INTEGER NOT NULL DEFAULT 1,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_tools (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code                VARCHAR(100) NOT NULL UNIQUE,
    name                VARCHAR(100) NOT NULL,
    description         VARCHAR(500) NOT NULL DEFAULT '',
    version             VARCHAR(20) NOT NULL DEFAULT '1.0',
    risk_level          VARCHAR(20) NOT NULL DEFAULT 'READ_ONLY', -- READ_ONLY / DRAFT_ONLY
    required_permission VARCHAR(100) NOT NULL DEFAULT '',
    input_schema        JSONB NOT NULL DEFAULT '{}',
    output_schema       JSONB NOT NULL DEFAULT '{}',
    timeout_seconds     INTEGER NOT NULL DEFAULT 30,
    max_results         INTEGER NOT NULL DEFAULT 100,
    status              VARCHAR(20) NOT NULL DEFAULT 'ENABLED',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- Prompt 管理 ----------
CREATE TABLE IF NOT EXISTS ai_prompts (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code               VARCHAR(50) NOT NULL UNIQUE,
    name               VARCHAR(100) NOT NULL,
    prompt_type        VARCHAR(20) NOT NULL,  -- SYSTEM / ORCHESTRATOR / AGENT / TOOL / TASK / SAFETY / EVALUATION
    status             VARCHAR(20) NOT NULL DEFAULT 'DRAFT', -- DRAFT / TESTING / ACTIVE / DISABLED / ARCHIVED
    current_version_id UUID,
    created_by         UUID,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by         UUID,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_prompt_versions (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    prompt_id      UUID NOT NULL REFERENCES ai_prompts(id),
    version_number INTEGER NOT NULL,
    content        TEXT NOT NULL,
    content_hash   VARCHAR(64) NOT NULL,
    change_summary VARCHAR(500) NOT NULL DEFAULT '',
    test_result    VARCHAR(20) NOT NULL DEFAULT '',
    created_by     UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_by   UUID,
    published_at   TIMESTAMPTZ,
    is_current     BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (prompt_id, version_number)
);
CREATE INDEX IF NOT EXISTS idx_ai_prompt_versions_prompt ON ai_prompt_versions (prompt_id, version_number DESC);

-- ---------- Memory ----------
CREATE TABLE IF NOT EXISTS ai_memories (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL,
    memory_scope    VARCHAR(20) NOT NULL,     -- SESSION / PROJECT / LONG_TERM
    scope_reference VARCHAR(100) NOT NULL DEFAULT '',
    content         TEXT NOT NULL,
    confidence_type VARCHAR(20) NOT NULL,     -- USER_CONFIRMED / SYSTEM_CONFIRMED / AI_INFERRED
    source_type     VARCHAR(20) NOT NULL DEFAULT 'MANUAL', -- MANUAL / CONVERSATION / TASK
    source_reference VARCHAR(100) NOT NULL DEFAULT '',
    status          VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE / DISABLED
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_memories_user ON ai_memories (user_id, memory_scope, status);

-- ---------- 推荐与草稿 ----------
CREATE TABLE IF NOT EXISTS ai_recommendations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id             UUID REFERENCES ai_tasks(id),
    recommendation_type VARCHAR(30) NOT NULL,  -- EXCEPTION / BLACKLIST / CC_POLICY / CUSTOM_RULE / POLICY_CHANGE
    target_type         VARCHAR(30) NOT NULL DEFAULT '',
    target_id           VARCHAR(100) NOT NULL DEFAULT '',
    summary             VARCHAR(1000) NOT NULL DEFAULT '',
    evidence_references JSONB NOT NULL DEFAULT '[]',
    risk_level          VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    status              VARCHAR(20) NOT NULL DEFAULT 'DRAFT', -- DRAFT / PENDING_REVIEW / ACCEPTED / REJECTED / EXPIRED
    draft_reference     VARCHAR(100) NOT NULL DEFAULT '',
    created_by_ai       BOOLEAN NOT NULL DEFAULT TRUE,
    reviewed_by         UUID,
    reviewed_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_recommendations_status ON ai_recommendations (status, created_at DESC);

-- ---------- 上下文压缩 ----------
CREATE TABLE IF NOT EXISTS ai_context_compressions (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id           UUID NOT NULL REFERENCES ai_sessions(id) ON DELETE CASCADE,
    before_tokens        INTEGER NOT NULL,
    after_tokens         INTEGER NOT NULL,
    summary              TEXT NOT NULL DEFAULT '',
    preserved_references JSONB NOT NULL DEFAULT '[]',
    compression_reason   VARCHAR(50) NOT NULL DEFAULT '',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_compressions_session ON ai_context_compressions (session_id, created_at DESC);

-- ---------- 反馈 ----------
CREATE TABLE IF NOT EXISTS ai_feedback (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id    UUID NOT NULL REFERENCES ai_sessions(id) ON DELETE CASCADE,
    message_id    UUID NOT NULL REFERENCES ai_messages(id) ON DELETE CASCADE,
    user_id       UUID NOT NULL,
    rating        INTEGER NOT NULL,          -- 1 / -1
    feedback_type VARCHAR(30) NOT NULL DEFAULT 'GENERAL', -- GENERAL / WRONG_FACT / MISSING_EVIDENCE / HALLUCINATION / OTHER
    comment       VARCHAR(500) NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_feedback_message ON ai_feedback (message_id);

-- ---------- 评估 ----------
CREATE TABLE IF NOT EXISTS ai_evaluation_sets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code        VARCHAR(50) NOT NULL UNIQUE,
    name        VARCHAR(100) NOT NULL,
    description VARCHAR(500) NOT NULL DEFAULT '',
    cases       JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_evaluation_runs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evaluation_set_id UUID NOT NULL REFERENCES ai_evaluation_sets(id),
    model_id          UUID,
    prompt_version_id UUID,
    status            VARCHAR(20) NOT NULL DEFAULT 'RUNNING', -- RUNNING / SUCCESS / FAILED
    score             NUMERIC(5,2),
    details           JSONB NOT NULL DEFAULT '{}',
    started_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- 用量与成本 ----------
CREATE TABLE IF NOT EXISTS ai_usage_records (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL,
    session_id     UUID,
    task_id        UUID,
    model_id       UUID,
    input_tokens   INTEGER NOT NULL DEFAULT 0,
    output_tokens  INTEGER NOT NULL DEFAULT 0,
    tool_calls     INTEGER NOT NULL DEFAULT 0,
    estimated_cost NUMERIC(12,8) NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_usage_user_time ON ai_usage_records (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_usage_time ON ai_usage_records (created_at DESC);

-- ---------- AI 审计（独立链路，复用哈希链思想） ----------
CREATE TABLE IF NOT EXISTS ai_audit_records (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id          UUID,
    username         VARCHAR(64) NOT NULL DEFAULT '',
    role_codes       VARCHAR(100) NOT NULL DEFAULT '',
    session_id       UUID,
    task_id          UUID,
    action           VARCHAR(40) NOT NULL,   -- chat / tool_call / draft_create / model_test / prompt_publish / ...
    task_type        VARCHAR(40) NOT NULL DEFAULT '',
    agent_code       VARCHAR(50) NOT NULL DEFAULT '',
    tool_code        VARCHAR(100) NOT NULL DEFAULT '',
    model_code       VARCHAR(100) NOT NULL DEFAULT '',
    prompt_version   VARCHAR(20) NOT NULL DEFAULT '',
    input_tokens     INTEGER NOT NULL DEFAULT 0,
    output_tokens    INTEGER NOT NULL DEFAULT 0,
    duration_ms      INTEGER NOT NULL DEFAULT 0,
    estimated_cost   NUMERIC(12,8) NOT NULL DEFAULT 0,
    request_summary  VARCHAR(500) NOT NULL DEFAULT '',
    result_summary   VARCHAR(1000) NOT NULL DEFAULT '',
    draft_reference  VARCHAR(100) NOT NULL DEFAULT '',
    confirm_result   VARCHAR(30) NOT NULL DEFAULT '',
    previous_hash    VARCHAR(64) NOT NULL DEFAULT '',
    record_hash      VARCHAR(64) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ai_audit_time ON ai_audit_records (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_audit_user ON ai_audit_records (user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_audit_session ON ai_audit_records (session_id);

COMMIT;
