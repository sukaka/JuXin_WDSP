-- 000106 down：移除 attack_session 自动化攻击标注两列。
BEGIN;

ALTER TABLE attack_session DROP COLUMN IF EXISTS automation_suspected;
ALTER TABLE attack_session DROP COLUMN IF EXISTS automation_basis;

COMMIT;
