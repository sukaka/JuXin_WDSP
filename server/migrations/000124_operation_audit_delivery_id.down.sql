DROP INDEX IF EXISTS idx_operation_audits_delivery_id;

ALTER TABLE operation_audits
    DROP COLUMN IF EXISTS delivery_id;
