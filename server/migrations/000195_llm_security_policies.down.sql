BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
    SELECT id FROM permissions WHERE code IN ('api_llm_security.read','api_llm_security.manage')
);
DELETE FROM permissions WHERE code IN ('api_llm_security.read','api_llm_security.manage');

DROP TABLE IF EXISTS api_llm_security_policy_versions;
DROP TABLE IF EXISTS api_llm_security_policies;

COMMIT;
