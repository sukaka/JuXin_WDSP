-- 回滚：移除安全事件请求/响应头体留痕列

BEGIN;

ALTER TABLE security_events
    DROP COLUMN IF EXISTS request_headers,
    DROP COLUMN IF EXISTS request_body,
    DROP COLUMN IF EXISTS request_body_truncated,
    DROP COLUMN IF EXISTS response_headers,
    DROP COLUMN IF EXISTS response_body,
    DROP COLUMN IF EXISTS response_body_truncated;

COMMIT;
