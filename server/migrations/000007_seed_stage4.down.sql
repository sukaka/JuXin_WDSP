-- 回滚 000007_seed_stage4

BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE module IN ('policies','waf_rules','custom_rules','exceptions','security_events'));
DELETE FROM permissions WHERE module IN ('policies','waf_rules','custom_rules','exceptions','security_events');
DELETE FROM protection_policies WHERE code IN ('relaxed','standard','strict');

COMMIT;
