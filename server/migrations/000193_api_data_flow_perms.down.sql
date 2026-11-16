BEGIN;
DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('api_data_flow.read','api_data_flow.evidence.read')
);
DELETE FROM permissions WHERE code IN ('api_data_flow.read','api_data_flow.evidence.read');
COMMIT;
