-- API 资产档案扩展：所属单位/业务系统/三类负责人/数据等级/API 等级/认证方式。
-- 枚举（data_level/api_level/auth_type）在应用层校验，不落 CHECK。
ALTER TABLE api_assets
    ADD COLUMN IF NOT EXISTS organization     VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS business_system  VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS technical_owner  VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS data_owner       VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS data_level       VARCHAR(32)  NOT NULL DEFAULT 'UNKNOWN',
    ADD COLUMN IF NOT EXISTS api_level        VARCHAR(32)  NOT NULL DEFAULT 'UNKNOWN',
    ADD COLUMN IF NOT EXISTS auth_type        VARCHAR(32)  NOT NULL DEFAULT '';
