BEGIN;
DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code IN ('request_pcap.read','request_pcap.verify','request_pcap.download'));
DELETE FROM permissions WHERE code IN ('request_pcap.read','request_pcap.verify','request_pcap.download');
COMMIT;
