-- 回滚 000004_stage3

BEGIN;

DROP TABLE IF EXISTS gateway_validation_results;
DROP TABLE IF EXISTS gateway_publish_tasks;
DROP TABLE IF EXISTS gateway_config_versions;
DROP TABLE IF EXISTS application_certificates;
DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS upstream_health_records;
DROP TABLE IF EXISTS upstreams;
DROP TABLE IF EXISTS application_domains;
DROP TABLE IF EXISTS applications;

COMMIT;
