-- 定时报告计划（定时自动创建报告 + 可选邮件发送）
BEGIN;

CREATE TABLE IF NOT EXISTS report_schedules (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name              VARCHAR(64)  NOT NULL,
    report_type       VARCHAR(16)  NOT NULL,               -- DAILY / WEEKLY / MONTHLY（CUSTOM 不支持定时）
    content_scope     VARCHAR(16)  NOT NULL DEFAULT 'WAF_API',
    application_ids   JSONB        NOT NULL DEFAULT '[]',
    template_id       UUID,
    file_format       VARCHAR(10)  NOT NULL DEFAULT 'pdf',
    time_of_day       VARCHAR(5)   NOT NULL,               -- HH:MM（UTC）
    day_of_week       SMALLINT     NOT NULL DEFAULT 1,     -- WEEKLY 用，1=周一..7=周日
    day_of_month      SMALLINT     NOT NULL DEFAULT 1,     -- MONTHLY 用，1-28（防月末歧义）
    send_email        BOOLEAN      NOT NULL DEFAULT FALSE,
    emails            JSONB        NOT NULL DEFAULT '[]',
    enabled           BOOLEAN      NOT NULL DEFAULT TRUE,
    next_run_at       TIMESTAMPTZ,
    last_run_at       TIMESTAMPTZ,
    last_job_id       UUID,
    last_email_status VARCHAR(16)  NOT NULL DEFAULT '',    -- SENT / FAILED / ''
    last_email_error  VARCHAR(512) NOT NULL DEFAULT '',
    created_by        UUID,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_report_schedules_due ON report_schedules (enabled, next_run_at);

-- 报告任务来源计划追溯（NULL 为手工创建）
ALTER TABLE report_jobs ADD COLUMN IF NOT EXISTS schedule_id UUID;

COMMIT;
