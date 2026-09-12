-- 000127 JWT 信任链验证摘要列（WDSP P0-03 集成步骤，任务书
-- docs/tasks/wdsp-p0/P0-03_JWT_TRUST_CHAIN.md §5/§8）。
--   api_runtime_events.jwt_verification：可选 JSONB 对象，承载网关 jwt_trust
--   段验证摘要（status/reason_code/policy_version/issuer_config_id/keyset_version/
--   verified_principal_id/verified_tenant_id/evaluated_at；verified_principal_id
--   为应用隔离 HMAC 主体指纹，verified_tenant_id 为加盐指纹——不落原始 Token、
--   完整 payload、明文 sub/tenant）。
--   可空：旧版网关事件与未经 jwt_trust 范围评估的请求落 NULL，历史事件不回填。
BEGIN;

ALTER TABLE api_runtime_events
    ADD COLUMN IF NOT EXISTS jwt_verification JSONB;

COMMIT;
