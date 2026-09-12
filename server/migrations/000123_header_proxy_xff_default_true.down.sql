BEGIN;

ALTER TABLE app_header_configs ALTER COLUMN xff_overwrite SET DEFAULT FALSE;

COMMIT;
