-- 000171 回滚：移除 GraphQL 成本预算策略表。
BEGIN;

DROP TABLE IF EXISTS api_graphql_policies;

COMMIT;
