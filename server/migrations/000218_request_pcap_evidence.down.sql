-- 仅用于尚无真实证据的测试/回滚环境；生产存在证据时禁止自动执行破坏性down。
BEGIN;

DELETE FROM system_settings WHERE setting_group='request_pcap';
DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code LIKE 'request_pcap.%'
);
DELETE FROM permissions WHERE code LIKE 'request_pcap.%';
DROP TABLE IF EXISTS request_pcap_custody_events;
DROP TABLE IF EXISTS request_pcap_links;
DROP TABLE IF EXISTS request_pcap_artifacts;

COMMIT;
