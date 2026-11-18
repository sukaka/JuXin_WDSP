BEGIN;
DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code='request_pcap.manage');
DELETE FROM permissions WHERE code='request_pcap.manage';
COMMIT;
