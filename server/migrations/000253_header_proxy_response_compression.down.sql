BEGIN;

ALTER TABLE app_header_configs
    DROP COLUMN IF EXISTS response_compression_encodings,
    DROP COLUMN IF EXISTS response_compression_enabled;

COMMIT;
