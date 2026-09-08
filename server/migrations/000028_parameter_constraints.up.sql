-- 000028 参数约束下发网关（P0-2）：参数行身份唯一索引。
--
-- 身份键 (model_version_id, direction, location, structured_path, parameter_name)：
-- 与任务书第十三章「方向 + 位置 + 结构化路径 + 字段名」对齐；
-- 仅用 parameter_name 会在嵌套同名叶字段（buyer.name / seller.name）上误合并。
-- Confirm 物化与后续学习写入均按该键幂等（物化侧按 structured_path 先查后插，见
-- server/internal/apimodels/parameters.go materializeRequestParameters）。
--
-- 既有库可能已被种子/手工 SQL 写入重复行，唯一索引直接创建会失败，
-- 故先查重：无重复时建唯一索引（同时承担物化幂等与查询加速）；
-- 有重复时退化为普通索引并 WARNING（幂等由物化侧先查后插保证，
-- 重复数据需人工清理后可手工补建唯一索引）。

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM api_parameter_models
        GROUP BY model_version_id, direction, location, structured_path, parameter_name
        HAVING count(*) > 1
        LIMIT 1
    ) THEN
        RAISE WARNING 'api_parameter_models 存在身份键重复行，退化创建普通索引（唯一索引需人工去重后补建）';
        CREATE INDEX IF NOT EXISTS idx_api_parameter_models_identity
            ON api_parameter_models (model_version_id, direction, location, structured_path, parameter_name);
    ELSE
        CREATE UNIQUE INDEX IF NOT EXISTS ux_api_parameter_models_identity
            ON api_parameter_models (model_version_id, direction, location, structured_path, parameter_name);
    END IF;
END $$;
