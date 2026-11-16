BEGIN;

CREATE TABLE IF NOT EXISTS security_risk_policy_overrides (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id         UUID NOT NULL UNIQUE REFERENCES applications(id) ON DELETE CASCADE,
    enabled                BOOLEAN NOT NULL,
    mode                   VARCHAR(16) NOT NULL CHECK (mode IN ('OBSERVE', 'PROTECT')),
    version                INT NOT NULL DEFAULT 1 CHECK (version > 0),
    block_threshold        INT NOT NULL CHECK (block_threshold BETWEEN 1 AND 100),
    rate_limit_threshold   INT NOT NULL CHECK (rate_limit_threshold BETWEEN 1 AND 100),
    rate_limit_rps         INT NOT NULL CHECK (rate_limit_rps BETWEEN 1 AND 100000),
    signal_window_seconds  INT NOT NULL CHECK (signal_window_seconds BETWEEN 1 AND 604800),
    scores                 JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(scores) = 'object'),
    risk_levels            JSONB NOT NULL CHECK (jsonb_typeof(risk_levels) = 'object'),
    updated_by             VARCHAR(255),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (rate_limit_threshold < block_threshold)
);

COMMENT ON TABLE security_risk_policy_overrides IS '按应用覆盖身份风险策略；未配置的应用继承 GLOBAL，显式禁用覆盖不继承处置';

COMMIT;
