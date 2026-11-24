BEGIN;

ALTER TABLE gateway_node_interfaces
    DROP COLUMN IF EXISTS ip_addresses;

COMMIT;
