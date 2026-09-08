#!/usr/bin/env bash
# 用途：向本地演示环境的 PostgreSQL 注入风险身份类型演示数据。
#
# 覆盖 HUMAN/BOT/APPLICATION/SERVICE/AGENT/UNKNOWN 六类身份，
# 供「安全中心 → 风险身份」（/risk-identities）列表与详情页查看。
# 所有标识、IP 和置信度来源均为合成数据，不含真实凭据；本脚本只面向演示环境，禁止用于生产库。
# 幂等可重跑：仅清理 identity_key 为 demo-identity-* 的演示行，再重新写入。
#
# 用法：
#   ./scripts/demo/seed-identity-types-demo.sh
#   PG_CONTAINER=my-postgres ./scripts/demo/seed-identity-types-demo.sh
set -euo pipefail

PG_CONTAINER="${PG_CONTAINER:-jiuzhang-stage5-postgres}"
PG_USER="$(docker exec "$PG_CONTAINER" printenv POSTGRES_USER)"
PG_DB="$(docker exec "$PG_CONTAINER" printenv POSTGRES_DB)"

echo "[seed-identity-types-demo] container=$PG_CONTAINER user=$PG_USER db=$PG_DB"

HAS_V11_IDENTITY_FIELDS="$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -Atqc \
  "SELECT CASE WHEN COUNT(*) = 2 THEN 'true' ELSE 'false' END FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'client_identity' AND column_name IN ('identity_confidence', 'confidence_source')")"

if [[ "$HAS_V11_IDENTITY_FIELDS" == "true" ]]; then
  echo "[seed-identity-types-demo] 检测到 V1.1 身份字段，写入完整置信度证据"
  docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;

-- 只删除本脚本生成的演示身份及其事件，绝不触碰其他身份。
DELETE FROM identity_behavior_events WHERE identity_key LIKE 'demo-identity-%';
DELETE FROM client_identity WHERE identity_key LIKE 'demo-identity-%';

INSERT INTO client_identity (
  identity_key, identity_type, identity_confidence, confidence_source,
  first_seen_at, last_seen_at, primary_ip, account_id,
  risk_score, risk_level, status, request_count
)
VALUES
  ('demo-identity-human',       'HUMAN',       90, '["credential:jwt","fingerprint:browser"]'::jsonb, now() - interval '6 days',  now() - interval '5 minutes', '198.51.100.10', 'demo-account-human', 12, 'LOW',      'ACTIVE', 128),
  ('demo-identity-bot',         'BOT',         85, '["user_agent:automation","behavior:headless"]'::jsonb, now() - interval '5 days',  now() - interval '8 minutes', '198.51.100.11', '',                  68, 'HIGH',     'ACTIVE', 2140),
  ('demo-identity-application', 'APPLICATION', 88, '["credential:api_key"]'::jsonb, now() - interval '4 days',  now() - interval '12 minutes', '198.51.100.12', 'demo-app-client', 24, 'MEDIUM',   'ACTIVE', 860),
  ('demo-identity-service',     'SERVICE',     95, '["credential:mtls_verified"]'::jsonb, now() - interval '4 days',  now() - interval '2 minutes',  '198.51.100.13', 'demo-service',     8, 'LOW',      'ACTIVE', 4200),
  ('demo-identity-agent',       'AGENT',       82, '["credential:oauth_verified"]'::jsonb, now() - interval '2 days',  now() - interval '15 minutes', '198.51.100.15', 'demo-agent',       72, 'CRITICAL', 'ACTIVE', 1780),
  ('demo-identity-unknown',     'UNKNOWN',      0, '[]'::jsonb, now() - interval '1 day',   now() - interval '30 minutes', '198.51.100.16', '',                  0, 'LOW',      'ACTIVE', 34);

-- 为列表页的 IP 数和详情页历史补充合成来源记录。
INSERT INTO identity_ip_history (identity_id, ip, first_seen_at, last_seen_at, request_count)
SELECT id, primary_ip, first_seen_at, last_seen_at, request_count
FROM client_identity
WHERE identity_key LIKE 'demo-identity-%' AND primary_ip <> '';

COMMIT;
SQL
else
  echo "[seed-identity-types-demo] 当前数据库尚未迁移 V1.1 身份字段，使用兼容字段写入类型演示数据"
  docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;

DELETE FROM identity_behavior_events WHERE identity_key LIKE 'demo-identity-%';
DELETE FROM client_identity WHERE identity_key LIKE 'demo-identity-%';

INSERT INTO client_identity (
  identity_key, identity_type, first_seen_at, last_seen_at, primary_ip, account_id,
  risk_score, risk_level, status, request_count
)
VALUES
  ('demo-identity-human',       'HUMAN',       now() - interval '6 days',  now() - interval '5 minutes',  '198.51.100.10', 'demo-account-human', 12, 'LOW',      'ACTIVE', 128),
  ('demo-identity-bot',         'BOT',         now() - interval '5 days',  now() - interval '8 minutes',  '198.51.100.11', '',                  68, 'HIGH',     'ACTIVE', 2140),
  ('demo-identity-application', 'APPLICATION', now() - interval '4 days',  now() - interval '12 minutes', '198.51.100.12', 'demo-app-client', 24, 'MEDIUM',   'ACTIVE', 860),
  ('demo-identity-service',     'SERVICE',     now() - interval '4 days',  now() - interval '2 minutes',  '198.51.100.13', 'demo-service',     8, 'LOW',      'ACTIVE', 4200),
  ('demo-identity-agent',       'AGENT',       now() - interval '2 days',  now() - interval '15 minutes', '198.51.100.15', 'demo-agent',       72, 'CRITICAL', 'ACTIVE', 1780),
  ('demo-identity-unknown',     'UNKNOWN',     now() - interval '1 day',   now() - interval '30 minutes', '198.51.100.16', '',                  0, 'LOW',      'ACTIVE', 34);

INSERT INTO identity_ip_history (identity_id, ip, first_seen_at, last_seen_at, request_count)
SELECT id, primary_ip, first_seen_at, last_seen_at, request_count
FROM client_identity
WHERE identity_key LIKE 'demo-identity-%' AND primary_ip <> '';

COMMIT;
SQL
fi

echo "[seed-identity-types-demo] 已写入 6 类演示身份；打开 /risk-identities 查看。"
