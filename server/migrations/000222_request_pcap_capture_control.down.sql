BEGIN;
DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code='request_pcap.capture_control');
DELETE FROM permissions WHERE code='request_pcap.capture_control';
COMMIT;
