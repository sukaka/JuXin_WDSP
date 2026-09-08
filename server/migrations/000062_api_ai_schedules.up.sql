-- 000062 API 安全补全第八波：AI 定时运营任务（apiops 包，P1-02 续，
-- 设计稿 docs/API_AI_OPERATIONS.md §六 Schedules）。
--
-- 语义边界：api_ai_schedules 承载「内置运营任务的定时计划」（任务类型为代码内词表，
-- 非自由文本）；api_ai_schedule_runs 承载每次触发的执行记录（状态/摘要/结构化产物）。
-- 产物纪律：任务只产出报告（summary + report_json），不执行任何业务变更——
-- 无自动确认/发布/封禁/状态流转路径（设计稿 §八 AI 不得清单）。
BEGIN;

CREATE TABLE IF NOT EXISTS api_ai_schedules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_type   VARCHAR(64)  NOT NULL,        -- 内置任务类型词表（见 CHECK，与 apiops 注册表一致）
    name        VARCHAR(128) NOT NULL,
    cron_expr   VARCHAR(64)  NOT NULL,        -- 标准五段 cron（分 时 日 月 周）或 @hourly/@daily/@weekly/@monthly/@yearly
    enabled     BOOLEAN      NOT NULL DEFAULT FALSE, -- 新建默认停用，人工启用后方参与调度
    config_json JSONB        NOT NULL DEFAULT '{}',  -- 任务入参（window_hours/limit/due_within_days，白名单校验）
    next_run_at TIMESTAMPTZ,                     -- 到期游标（调度器选取依据；NULL 表示未排期）
    last_run_at TIMESTAMPTZ,
    last_status VARCHAR(16)  NOT NULL DEFAULT '',    -- '' / SUCCESS / FAILED
    last_error  TEXT         NOT NULL DEFAULT '',    -- 失败原因落列，不静默吞错
    created_by  UUID,                              -- 计划属主（创建人用户 ID，留痕用）
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT chk_api_ai_schedules_task_type CHECK (task_type IN (
        'API_ASSET_DIGEST','SHADOW_REVIEW','WEAKNESS_FOLLOW','RISK_DIGEST','SENSITIVE_DIGEST')),
    CONSTRAINT chk_api_ai_schedules_last_status CHECK (last_status IN ('','SUCCESS','FAILED'))
);
CREATE INDEX IF NOT EXISTS idx_api_ai_schedules_due ON api_ai_schedules (enabled, next_run_at);

-- 执行记录：每次触发一行（含手动立即执行），与计划表级联删除
CREATE TABLE IF NOT EXISTS api_ai_schedule_runs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schedule_id UUID        NOT NULL REFERENCES api_ai_schedules(id) ON DELETE CASCADE,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    status      VARCHAR(16) NOT NULL DEFAULT 'RUNNING', -- RUNNING / SUCCESS / FAILED
    summary     TEXT        NOT NULL DEFAULT '',        -- 中文摘要（LLM 润色可选，失败时回退纯模板文本）
    report_json JSONB       NOT NULL DEFAULT '{}',      -- 结构化产物（计数 + 清单，可回放）
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_api_ai_schedule_runs_status CHECK (status IN ('RUNNING','SUCCESS','FAILED'))
);
CREATE INDEX IF NOT EXISTS idx_api_ai_schedule_runs_schedule ON api_ai_schedule_runs (schedule_id, started_at DESC);

COMMIT;
