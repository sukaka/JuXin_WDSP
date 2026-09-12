-- 000092 回滚：删除 apm_slos 表
BEGIN;

DROP TABLE IF EXISTS apm_slos;

COMMIT;
