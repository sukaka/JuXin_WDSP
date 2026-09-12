-- 报告内容范围（WAF / API / WAF_API）：report_jobs.content_scope
BEGIN;

ALTER TABLE report_jobs ADD COLUMN IF NOT EXISTS content_scope VARCHAR(16) NOT NULL DEFAULT '';

COMMIT;
