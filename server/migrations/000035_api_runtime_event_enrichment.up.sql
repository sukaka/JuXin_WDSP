-- 000035 API 运行时事件审计列补齐（WDSP P0-20 Audit Trace / P0-09 决策溯源）。
--
-- 背景：api_runtime_events 自建表起只有 request_id/endpoint_key/risk_score/risk_level/
-- final_action/details_json/occurred_at（000016/000018）+ 身份列（000029）+ 响应状态码
-- （000030），距任务书 §88 请求级审计差距大：无法回答「谁、从哪个 IP、以什么方法、
-- 访问哪个原始路径、耗时多少、当时生效哪版模型与策略」。
-- 本迁移新增六列（全部可空，不动存量行；旧版网关事件缺字段时落 NULL）：
--   client_ip      真实客户端 IP（文本，可空；与 source_fingerprint 并存：
--                  指纹用于聚合关联，明文 IP 仅供审计溯源，由网关侧按需上报）；
--   method         请求方法（冗余自 endpoint_key 前缀，便于按方法过滤/聚合）；
--   raw_path       原始请求路径（归一化前，path_template 的原始形态）；
--   latency_ms     请求处理耗时（毫秒；旧版网关未上报时 NULL）；
--   model_version  判定所用模型版本（如 schema 冻结版本号，未上报 NULL）；
--   policy_version 判定所运行策略版本（P0-21 端点级 Runtime Policy 就位前可空）。
BEGIN;

ALTER TABLE api_runtime_events
    ADD COLUMN IF NOT EXISTS client_ip      TEXT,
    ADD COLUMN IF NOT EXISTS method         TEXT,
    ADD COLUMN IF NOT EXISTS raw_path       TEXT,
    ADD COLUMN IF NOT EXISTS latency_ms     BIGINT,
    ADD COLUMN IF NOT EXISTS model_version  TEXT,
    ADD COLUMN IF NOT EXISTS policy_version TEXT;

COMMIT;
