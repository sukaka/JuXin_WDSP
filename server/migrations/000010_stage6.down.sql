-- 阶段6 回滚：删除指标聚合、报告、告警、监控、备份恢复、升级、交付检查相关表

BEGIN;

DROP TABLE IF EXISTS delivery_check_results CASCADE;
DROP TABLE IF EXISTS delivery_checks CASCADE;
DROP TABLE IF EXISTS upgrade_jobs CASCADE;
DROP TABLE IF EXISTS upgrade_packages CASCADE;
DROP TABLE IF EXISTS restore_jobs CASCADE;
DROP TABLE IF EXISTS backup_files CASCADE;
DROP TABLE IF EXISTS backup_jobs CASCADE;
DROP TABLE IF EXISTS system_alert_notes CASCADE;
DROP TABLE IF EXISTS system_alerts CASCADE;
DROP TABLE IF EXISTS report_archives CASCADE;
DROP TABLE IF EXISTS report_jobs CASCADE;
DROP TABLE IF EXISTS report_templates CASCADE;
DROP TABLE IF EXISTS aggregation_jobs CASCADE;
DROP TABLE IF EXISTS system_health_snapshots CASCADE;
DROP TABLE IF EXISTS uri_security_summaries CASCADE;
DROP TABLE IF EXISTS source_ip_summaries CASCADE;
DROP TABLE IF EXISTS rule_hit_summaries CASCADE;
DROP TABLE IF EXISTS application_security_summaries CASCADE;
DROP TABLE IF EXISTS metric_daily_aggregates CASCADE;
DROP TABLE IF EXISTS metric_hour_aggregates CASCADE;
DROP TABLE IF EXISTS metric_minute_aggregates CASCADE;

COMMIT;
