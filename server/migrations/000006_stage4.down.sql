-- 回滚 000006_stage4

BEGIN;

DROP TABLE IF EXISTS event_parse_failures;
DROP TABLE IF EXISTS event_collector_checkpoints;
DROP TABLE IF EXISTS policy_versions;
DROP TABLE IF EXISTS security_event_actions;
DROP TABLE IF EXISTS security_event_notes;
DROP TABLE IF EXISTS security_event_matches;
DROP TABLE IF EXISTS security_events;
DROP TABLE IF EXISTS exception_policies;
DROP TABLE IF EXISTS custom_rules;
DROP TABLE IF EXISTS rule_overrides;
DROP TABLE IF EXISTS waf_rules;
DROP TABLE IF EXISTS application_policies;
DROP TABLE IF EXISTS protection_policies;

COMMIT;
