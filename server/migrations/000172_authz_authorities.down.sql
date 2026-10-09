-- 000172 回滚：移除权威关系接入六表、关系表溯源列/词表与权限种子。
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('api_authorization.authority_manage','api_authorization.authority_import')
);
DELETE FROM permissions WHERE code IN ('api_authorization.authority_manage','api_authorization.authority_import');

DROP TABLE IF EXISTS api_authority_conflicts;
DROP TABLE IF EXISTS api_authority_watermarks;
DROP TABLE IF EXISTS api_authority_applied_events;
DROP TABLE IF EXISTS api_authority_import_batches;
DROP TABLE IF EXISTS api_authority_source_keys;
DROP TABLE IF EXISTS api_authority_sources;

-- 存在 AUTHORITY_SYNC 行时本语句因 CHECK 违例失败（回滚不静默删除授权数据——
-- 操作员须先清理权威关系行）；无则恢复三词表约束并移除溯源列
ALTER TABLE api_object_relations DROP CONSTRAINT IF EXISTS api_object_relations_source_check;
ALTER TABLE api_object_relations
    ADD CONSTRAINT api_object_relations_source_check
    CHECK (source IN ('MANUAL','IMPORT','CREATE_BINDING'));

DROP INDEX IF EXISTS idx_authz_relation_authority;
ALTER TABLE api_object_relations DROP COLUMN IF EXISTS source_batch_id;
ALTER TABLE api_object_relations DROP COLUMN IF EXISTS source_event_id;
ALTER TABLE api_object_relations DROP COLUMN IF EXISTS source_id;

COMMIT;
