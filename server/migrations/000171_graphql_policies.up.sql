-- 000171 GraphQL 成本预算策略（NG-GQL-03 管理面；契约 docs/nextgen/NG-GQL-03-wiring.md）。
--
--   api_graphql_policies：按应用一行的 GraphQL 成本预算策略（无行 = 关闭，全链
--     零行为变化）。config 冻结 JSON 契约（与发布 payload 同构）：
--       limits.max_doc_bytes/max_depth/max_nodes/max_aliases/max_fragment_exp
--       weights.default_field_weight/default_list_bound/introspection_weight/fields
--       budget.per_request_budget/window_seconds/window_budget/anonymous_budget
--       trusted_doc_digests（gqlast.DigestDocument 口径 32 位 hex 白名单）
--     数值校验在服务层（非负 + 上限）；内容纳入 api_policy_version 版本戳随发布下发。
--   权限沿用 api_policy.read / api_policy.edit（任务书口径，无新权限点）。
BEGIN;

CREATE TABLE IF NOT EXISTS api_graphql_policies (
    application_id UUID PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
    enabled        BOOLEAN     NOT NULL DEFAULT false,
    config         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    version        INT         NOT NULL DEFAULT 1,
    updated_by     UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE api_graphql_policies IS 'GraphQL 成本预算策略（NG-GQL-03，按应用一行；无行=关闭零行为变化；config 与发布 payload 同构）';

COMMIT;
