-- 000184 回滚：移除机器身份绑定与撤销水位两表（000183 身份/键表不受影响）。
BEGIN;

DROP TABLE IF EXISTS machine_identity_bindings;
DROP TABLE IF EXISTS machine_identity_revocation_watermark;

COMMIT;
