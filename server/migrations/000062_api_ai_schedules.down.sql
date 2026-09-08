-- 000062 回滚：删除 AI 定时运营任务两表
BEGIN;

DROP TABLE IF EXISTS api_ai_schedule_runs;
DROP TABLE IF EXISTS api_ai_schedules;

COMMIT;
