-- API 安全补全第十四批（P2-07 源码发现接入）：api_import_specs 增加来源列。
-- 词表：UPLOAD（粘贴/文件上传）/ URL（URL 拉取）/ SOURCE_CODE（tools/apisrc 源码扫描）/
-- TRAFFIC_GENERATED / SCANNER / MANUAL_EDITOR（后三者预留）。
BEGIN;

ALTER TABLE api_import_specs ADD COLUMN IF NOT EXISTS source VARCHAR(32) NOT NULL DEFAULT 'UPLOAD';

COMMENT ON COLUMN api_import_specs.source IS
  '规范来源：UPLOAD / URL / SOURCE_CODE / TRAFFIC_GENERATED / SCANNER / MANUAL_EDITOR';

COMMIT;
