-- 000029 运行时事件身份字段（WDSP 身份微模型第一批，服务端持久化）。
--
-- api_runtime_events 增加两个身份列，数据由网关 api-runtime-events JSONL 上报、
-- apiruntime 采集器 ETL 落库：
--   identity_fingerprint  仅由凭据派生的 HMAC-SHA256 指纹（不可逆、不落明文），匿名流量为空串；
--   auth_type             凭据形态：bearer_or_basic / api_key / cookie_session / 空（匿名）。
-- 边界规则（docs/API_MICRO_MODELS.md §2.2）：IP 属于环境维度，身份只由凭据派生，
-- 匿名一律空串，不得以 IP 冒充身份。
BEGIN;

ALTER TABLE api_runtime_events
    ADD COLUMN IF NOT EXISTS identity_fingerprint VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS auth_type            VARCHAR(32)  NOT NULL DEFAULT '';

-- 部分索引：匿名事件（空串指纹）不占索引，按身份过滤（精确匹配）走该索引。
CREATE INDEX IF NOT EXISTS idx_api_runtime_events_identity
    ON api_runtime_events (identity_fingerprint) WHERE identity_fingerprint <> '';

COMMIT;
