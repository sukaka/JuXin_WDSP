-- 000073 down：回退 W16-TABLES 配套 schema（与 up 成对）。
--
-- api_endpoint_path_segments 段形为派生数据（本波之前为零写入方空表，可由
-- api_endpoints 重建），down 整表清空；api_object_models 三个观测列随列删除丢弃；
-- 分类种子仅删除本迁移登记的内置行（自定义行与其他内置行不动）；
-- api_request_schemas 表注释还原为空。
BEGIN;

DELETE FROM api_endpoint_path_segments;

DELETE FROM api_classifications
WHERE is_builtin AND code IN (
    'IDENTITY_AUTH', 'USER_ACCOUNT', 'ORG_PERMISSION', 'DATA_RESOURCE',
    'PROCESS_APPROVAL', 'TRANSACTION_FUND', 'FILE_CONTENT', 'QUERY_ANALYTICS',
    'IMPORT_EXPORT', 'MESSAGE_NOTIFICATION', 'EXTERNAL_INTEGRATION', 'SYSTEM_CONFIG',
    'SYSTEM_OPS', 'DEVICE_IOT', 'AI_INTELLIGENCE', 'PRIVACY_COMPLIANCE');

COMMENT ON TABLE api_request_schemas IS NULL;

ALTER TABLE api_object_models
    DROP COLUMN IF EXISTS first_seen,
    DROP COLUMN IF EXISTS last_seen,
    DROP COLUMN IF EXISTS sample_count;

COMMIT;
