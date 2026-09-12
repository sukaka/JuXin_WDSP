-- 000149 API 运行时事件四级识别标签落库 + §7 遗留 findings 冗余列。
--
--   1. api_runtime_events.api_level：网关 §8.2 四级识别标签（来自统一上下文扩展
--      api.classification），词表 CONFIRMED_API / PROBABLE_API / POSSIBLE_API /
--      NON_API（网关侧 classifier.LevelXxx 常量，与 is_api/api_confidence 同源
--      不同口径：api_confidence 为 0..1 连续置信度，api_level 为离散四级标签）。
--      可空：旧版网关事件未上报或管线未写 api.classification（合成结果/fail-open
--      旁路）时落 NULL，历史事件不回填。列宽 32 与网关 sanitize 上限
--      （apievents maxProtoLen）一致；chk_api_runtime_events_api_level CHECK
--      约束兜底词表（与 000042 status 同一纪律：词表之外拒绝落库）。
--   2. api_runtime_findings.device_fingerprint / object_identifiers：统一 Finding
--      设计（docs/API_UNIFIED_FINDING_DECISION.md）要求发现携带主事件上下文快照，
--      冗余拷贝主事件 §7 字段（口径与 000150 相同：指纹为 HMAC 截断 hex、对象
--      标识只记哈希），消费端按发现查询时无需回连事件表。可空：历史发现不回填，
--      主事件缺字段的发现落 NULL。
BEGIN;

ALTER TABLE api_runtime_events
    ADD COLUMN IF NOT EXISTS api_level VARCHAR(32);

ALTER TABLE api_runtime_events
    ADD CONSTRAINT chk_api_runtime_events_api_level
    CHECK (api_level IS NULL OR api_level IN ('CONFIRMED_API','PROBABLE_API','POSSIBLE_API','NON_API'));

ALTER TABLE api_runtime_findings
    ADD COLUMN IF NOT EXISTS device_fingerprint VARCHAR(64),
    ADD COLUMN IF NOT EXISTS object_identifiers JSONB;

COMMIT;
