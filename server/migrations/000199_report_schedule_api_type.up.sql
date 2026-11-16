BEGIN;

ALTER TABLE report_schedules
    ADD COLUMN IF NOT EXISTS api_report_type TEXT NOT NULL DEFAULT ''
        CHECK (api_report_type IN ('', 'API_ASSET', 'API_RISK', 'API_WEAK', 'API_SENS'));

COMMENT ON COLUMN report_schedules.api_report_type IS '可选 API 专项报告类型：API_ASSET/API_RISK/API_WEAK/API_SENS；空串保持普通周期报告';

COMMIT;
