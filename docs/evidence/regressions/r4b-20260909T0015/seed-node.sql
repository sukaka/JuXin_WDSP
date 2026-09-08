INSERT INTO api_gateway_nodes (node_name, admin_addr, sync_enabled, status)
VALUES ('r4b-bad-node', 'http://127.0.0.1:19999', true, 'OFFLINE')
ON CONFLICT DO NOTHING;
