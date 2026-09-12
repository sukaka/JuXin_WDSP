-- 安全事件请求/响应头体留痕（一期：溯源取证）
-- 来源：Coraza 审计日志 B(请求头)/C(完整请求体)/E(中断响应体)/F(响应头) 段。
-- 采集侧脱敏（敏感请求头掩码）并截断（头体各 64KB），数据库只存脱敏后内容。

BEGIN;

ALTER TABLE security_events
    ADD COLUMN IF NOT EXISTS request_headers        JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS request_body           TEXT  NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS request_body_truncated BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS response_headers       JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS response_body          TEXT  NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS response_body_truncated BOOLEAN NOT NULL DEFAULT false;

COMMIT;
