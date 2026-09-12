-- 000028 回滚：删除参数行身份索引（两种可能形态一并清理）。

DROP INDEX IF EXISTS ux_api_parameter_models_identity;
DROP INDEX IF EXISTS idx_api_parameter_models_identity;
