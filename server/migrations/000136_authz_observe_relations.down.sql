BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
    SELECT id FROM permissions WHERE code IN (
        'api_authorization.relation_manage', 'api_authorization.evidence_read'
    )
);
DELETE FROM permissions WHERE code IN (
    'api_authorization.relation_manage', 'api_authorization.evidence_read'
);

DROP TABLE IF EXISTS api_authz_migration_state;
DROP TABLE IF EXISTS api_authorization_decisions;
DROP TABLE IF EXISTS api_object_relations;
DROP TABLE IF EXISTS api_authz_candidate_event_receipts;
DROP TABLE IF EXISTS api_object_relation_candidates;

ALTER TABLE api_object_models DROP CONSTRAINT IF EXISTS ck_api_object_models_required_relation;
ALTER TABLE api_object_models
    DROP COLUMN IF EXISTS owner_exclusive,
    DROP COLUMN IF EXISTS required_relation,
    DROP COLUMN IF EXISTS publishable;
ALTER TABLE api_role_baselines DROP COLUMN IF EXISTS identity_assurance;

COMMIT;
