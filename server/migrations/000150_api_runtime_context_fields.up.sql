-- 000150 统一上下文 §7 字段落库（阶段8 任务书 §7 RequestContext 补全）。
--   api_runtime_events.device_fingerprint：被动客户端指纹（UA/Accept-Language/
--   Accept-Encoding/Accept 族头的 HMAC-SHA256 截断 16 字节 hex，32 字符；
--   低熵群体特征，非设备唯一标识）。可空：UA 缺失或旧版网关事件落 NULL。
--   api_runtime_events.object_identifiers：可选 JSONB 数组，元素
--   {source, param, value_hash}——归一化路径位置参数与请求体主键字段的对象标识，
--   只记 HMAC 哈希不落明文值。可空：无可识别对象标识或旧版网关事件落 NULL，
--   历史事件不回填。
BEGIN;

ALTER TABLE api_runtime_events
    ADD COLUMN IF NOT EXISTS device_fingerprint VARCHAR(64),
    ADD COLUMN IF NOT EXISTS object_identifiers JSONB;

COMMIT;
