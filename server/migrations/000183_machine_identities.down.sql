-- 000183 回滚：移除机器身份登记两表。
BEGIN;

DROP TABLE IF EXISTS machine_identity_keys;
DROP TABLE IF EXISTS machine_identities;

COMMIT;
