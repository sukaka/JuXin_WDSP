-- 000111 回滚：删除证书撤销表与 agents 证书列
BEGIN;

DROP TABLE IF EXISTS agent_cert_revocations;
ALTER TABLE agents DROP COLUMN IF EXISTS agent_cert_fingerprint;
ALTER TABLE agents DROP COLUMN IF EXISTS agent_cert_not_after;

COMMIT;
