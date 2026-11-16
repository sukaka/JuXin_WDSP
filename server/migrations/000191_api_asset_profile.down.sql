ALTER TABLE api_assets
    DROP COLUMN IF EXISTS organization,
    DROP COLUMN IF EXISTS business_system,
    DROP COLUMN IF EXISTS technical_owner,
    DROP COLUMN IF EXISTS data_owner,
    DROP COLUMN IF EXISTS data_level,
    DROP COLUMN IF EXISTS api_level,
    DROP COLUMN IF EXISTS auth_type;
