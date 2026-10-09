-- 000173 回滚：移除租约列、节点 ACK 表与手工撤销水位表。
BEGIN;

ALTER TABLE applications DROP COLUMN IF EXISTS authz_lease_seconds;
ALTER TABLE api_object_models DROP CONSTRAINT IF EXISTS api_object_models_on_lease_expired_check;
ALTER TABLE api_object_models DROP COLUMN IF EXISTS on_lease_expired;

DROP TABLE IF EXISTS api_node_authz_acks;
DROP TABLE IF EXISTS api_authz_manual_revocation_seq;

COMMIT;
