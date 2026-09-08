ALTER TABLE operation_audits
    ADD COLUMN IF NOT EXISTS delivery_id UUID;

CREATE UNIQUE INDEX IF NOT EXISTS idx_operation_audits_delivery_id
    ON operation_audits (delivery_id);
