#!/usr/bin/env bash
# 用途：向本地演示环境（stage5 compose 栈）的 PostgreSQL 注入 APM 业务性能演示数据，
#       让「性能总览 / 服务性能 / 端点性能」（APM 无 Agent 模式）有可视化数据。
#
# 说明：
#   - 数据写入 metric_minute_aggregates（近 6 小时，分钟桶）与
#     metric_hour_aggregates（近 72 小时，小时桶），行结构与真实采集器
#     （server/internal/aggregations/accesslog.go、endpoint_red.go）完全一致，
#     APM 查询（server/internal/apm/store.go）不感知差异；
#   - 仅覆盖 shop-mall / user-center / open-gw 三个演示应用的窗口，
#     幂等可重跑（ON CONFLICT 覆盖同键行），真实采集器后续运行会自然覆盖/滚动；
#   - 本脚本只面向演示环境，不得用于生产库。
#
# 用法：
#   ./scripts/demo/seed-apm-demo.sh
#   PG_CONTAINER=my-postgres ./scripts/demo/seed-apm-demo.sh
set -euo pipefail

PG_CONTAINER="${PG_CONTAINER:-jiuzhang-stage5-postgres}"

PG_USER="$(docker exec "$PG_CONTAINER" printenv POSTGRES_USER)"
PG_DB="$(docker exec "$PG_CONTAINER" printenv POSTGRES_DB)"

echo "[seed-apm-demo] container=$PG_CONTAINER user=$PG_USER db=$PG_DB"

docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;

-- ---------- 维度定义 ----------
-- 应用：base = 峰值期每分钟请求数；w = 11 段耗时直方图权重（桶界 5/10/25/50/100/250/500/1000/2500/5000/>5000ms）
--   shop-mall  正常型（p50 ~60ms，p95 ~220ms）
--   user-center 快速型（p50 ~28ms，p95 ~80ms）
--   open-gw    偏慢型（p95 ~500ms，且近 50 分钟制造 5xx 突增，便于演示告警场景）
CREATE TEMP TABLE demo_apps (code text, base float8, w float8[]) ON COMMIT DROP;
INSERT INTO demo_apps VALUES
  ('shop-mall',   620.0, ARRAY[0.020,0.050,0.150,0.250,0.280,0.150,0.060,0.025,0.010,0.004,0.001]),
  ('user-center', 300.0, ARRAY[0.150,0.300,0.350,0.120,0.050,0.020,0.008,0.002,0.000,0.000,0.000]),
  ('open-gw',     460.0, ARRAY[0.030,0.060,0.130,0.180,0.220,0.200,0.130,0.030,0.010,0.008,0.002]);

-- 端点（METHOD /path/{id} 归一化形态，与网关 endpoint_key 口径一致）：base = 峰值每分钟请求数
CREATE TEMP TABLE demo_endpoints (app text, endpoint text, base float8) ON COMMIT DROP;
INSERT INTO demo_endpoints VALUES
  ('shop-mall',   'GET /api/products/{id}',   220.0),
  ('shop-mall',   'GET /api/products',        140.0),
  ('shop-mall',   'POST /api/orders',          90.0),
  ('shop-mall',   'POST /api/cart/items',      70.0),
  ('shop-mall',   'GET /api/users/me',         60.0),
  ('shop-mall',   'POST /api/pay/callback',    40.0),
  ('user-center', 'POST /api/login',          120.0),
  ('user-center', 'GET /api/users/{id}',       90.0),
  ('user-center', 'PUT /api/users/{id}',       50.0),
  ('user-center', 'GET /api/sessions',         40.0),
  ('open-gw',     'POST /openapi/token',      150.0),
  ('open-gw',     'GET /openapi/data/{id}',   200.0),
  ('open-gw',     'POST /openapi/webhook',     70.0),
  ('open-gw',     'GET /healthz',              40.0);

-- 昼夜曲线：15:00 前后为峰值（0.45~1.0），凌晨为低谷
CREATE OR REPLACE FUNCTION pg_temp.day_curve(ts timestamptz) RETURNS float8 AS $$
  SELECT 0.45 + 0.55 * (sin(2*pi()*(extract(hour from ts) + extract(minute from ts)/60.0 - 15)/24.0) + 1)/2;
$$ LANGUAGE sql;

-- ---------- 分钟桶：近 6 小时 ----------
CREATE TEMP TABLE demo_minutes ON COMMIT DROP AS
SELECT generate_series(date_trunc('minute', now()) - interval '6 hours',
                       date_trunc('minute', now()) - interval '1 minute',
                       interval '1 minute') AS b;

-- 应用级请求数（app × status_class）；open-gw 近 50 分钟 5xx 放大 12 倍
INSERT INTO metric_minute_aggregates (bucket_start, metric, labels, value, extra)
SELECT m.b, 'http_requests_total',
       jsonb_build_object('app', a.code, 'status_class', s.cls),
       GREATEST(1, round(a.base * s.ratio * pg_temp.day_curve(m.b) * (0.85 + random()*0.3) *
         CASE WHEN a.code = 'open-gw' AND s.cls = '5xx'
                   AND m.b >= date_trunc('minute', now()) - interval '50 minutes' THEN 12 ELSE 1 END))::float8,
       '{}'::jsonb
FROM demo_minutes m
CROSS JOIN demo_apps a
CROSS JOIN (VALUES ('2xx', 0.955), ('4xx', 0.035), ('5xx', 0.010)) AS s(cls, ratio)
ON CONFLICT (bucket_start, metric, labels)
DO UPDATE SET value = EXCLUDED.value, extra = EXCLUDED.extra, updated_at = now();

-- 应用级耗时直方图（extra.buckets，value = 各桶计数和，与真实采集器一致）
INSERT INTO metric_minute_aggregates (bucket_start, metric, labels, value, extra)
SELECT x.b, 'http_request_duration_ms', jsonb_build_object('app', x.code),
       x.total, jsonb_build_object('buckets', to_jsonb(x.bk))
FROM (
  SELECT m.b, a.code, u.bk, v.total
  FROM demo_minutes m
  CROSS JOIN demo_apps a
  CROSS JOIN LATERAL (SELECT round(a.base * pg_temp.day_curve(m.b) * (0.85 + random()*0.3))::float8 AS n) t
  CROSS JOIN LATERAL (SELECT ARRAY[
    round(t.n*a.w[1])::int, round(t.n*a.w[2])::int, round(t.n*a.w[3])::int, round(t.n*a.w[4])::int,
    round(t.n*a.w[5])::int, round(t.n*a.w[6])::int, round(t.n*a.w[7])::int, round(t.n*a.w[8])::int,
    round(t.n*a.w[9])::int, round(t.n*a.w[10])::int, round(t.n*a.w[11])::int] AS bk) u
  CROSS JOIN LATERAL (SELECT COALESCE(SUM(c),0)::float8 AS total FROM unnest(u.bk) c) v
) x
ON CONFLICT (bucket_start, metric, labels)
DO UPDATE SET value = EXCLUDED.value, extra = EXCLUDED.extra, updated_at = now();

-- 应用级 WAF 阻断/观察数
INSERT INTO metric_minute_aggregates (bucket_start, metric, labels, value, extra)
SELECT m.b, s.metric, jsonb_build_object('app', a.code),
       GREATEST(0, round(a.base * s.ratio * pg_temp.day_curve(m.b) * (0.7 + random()*0.6)))::float8,
       '{}'::jsonb
FROM demo_minutes m
CROSS JOIN demo_apps a
CROSS JOIN (VALUES ('waf_blocks_total', 0.018), ('waf_observes_total', 0.009)) AS s(metric, ratio)
ON CONFLICT (bucket_start, metric, labels)
DO UPDATE SET value = EXCLUDED.value, extra = EXCLUDED.extra, updated_at = now();

-- 端点级请求数（app × endpoint × status_class × action）
INSERT INTO metric_minute_aggregates (bucket_start, metric, labels, value, extra)
SELECT m.b, 'http_endpoint_requests_total',
       jsonb_build_object('app', e.app, 'endpoint', e.endpoint, 'status_class', s.cls, 'action', s.act),
       GREATEST(1, round(e.base * s.ratio * pg_temp.day_curve(m.b) * (0.8 + random()*0.4)))::float8,
       '{}'::jsonb
FROM demo_minutes m
CROSS JOIN demo_endpoints e
CROSS JOIN (VALUES
  ('2xx', 'allow',   0.945),
  ('2xx', 'observe', 0.010),
  ('4xx', 'allow',   0.012),
  ('4xx', 'block',   0.023),
  ('5xx', 'allow',   0.010)) AS s(cls, act, ratio)
ON CONFLICT (bucket_start, metric, labels)
DO UPDATE SET value = EXCLUDED.value, extra = EXCLUDED.extra, updated_at = now();

-- 少量未归类流量（__UNCLASSIFIED__ 治理桶）
INSERT INTO metric_minute_aggregates (bucket_start, metric, labels, value, extra)
SELECT m.b, 'http_endpoint_requests_total',
       jsonb_build_object('app', a.code, 'endpoint', '__UNCLASSIFIED__', 'status_class', '2xx', 'action', 'allow'),
       GREATEST(1, round(a.base * 0.02 * pg_temp.day_curve(m.b) * (0.7 + random()*0.6)))::float8,
       '{}'::jsonb
FROM demo_minutes m CROSS JOIN demo_apps a
ON CONFLICT (bucket_start, metric, labels)
DO UPDATE SET value = EXCLUDED.value, extra = EXCLUDED.extra, updated_at = now();

-- 端点级总耗时 / TTFB 直方图（沿用所属应用的权重形态）
INSERT INTO metric_minute_aggregates (bucket_start, metric, labels, value, extra)
SELECT x.b, x.metric, jsonb_build_object('app', x.app, 'endpoint', x.endpoint),
       x.total, jsonb_build_object('buckets', to_jsonb(x.bk))
FROM (
  SELECT m.b, s.metric, e.app, e.endpoint, u.bk, v.total
  FROM demo_minutes m
  CROSS JOIN demo_endpoints e
  JOIN demo_apps a ON a.code = e.app
  CROSS JOIN (VALUES ('http_endpoint_duration_ms', 1.0), ('http_endpoint_ttfb_ms', 0.55)) AS s(metric, scale)
  CROSS JOIN LATERAL (SELECT round(e.base * s.scale * pg_temp.day_curve(m.b) * (0.8 + random()*0.4))::float8 AS n) t
  CROSS JOIN LATERAL (SELECT ARRAY[
    round(t.n*a.w[1])::int, round(t.n*a.w[2])::int, round(t.n*a.w[3])::int, round(t.n*a.w[4])::int,
    round(t.n*a.w[5])::int, round(t.n*a.w[6])::int, round(t.n*a.w[7])::int, round(t.n*a.w[8])::int,
    round(t.n*a.w[9])::int, round(t.n*a.w[10])::int, round(t.n*a.w[11])::int] AS bk) u
  CROSS JOIN LATERAL (SELECT COALESCE(SUM(c),0)::float8 AS total FROM unnest(u.bk) c) v
) x
ON CONFLICT (bucket_start, metric, labels)
DO UPDATE SET value = EXCLUDED.value, extra = EXCLUDED.extra, updated_at = now();

-- ---------- 小时桶：近 72 小时（>6h 窗口走小时表） ----------
CREATE TEMP TABLE demo_hours ON COMMIT DROP AS
SELECT generate_series(date_trunc('hour', now()) - interval '72 hours',
                       date_trunc('hour', now()) - interval '1 hour',
                       interval '1 hour') AS b;

INSERT INTO metric_hour_aggregates (bucket_start, metric, labels, value, extra)
SELECT m.b, 'http_requests_total',
       jsonb_build_object('app', a.code, 'status_class', s.cls),
       GREATEST(1, round(a.base * 60 * s.ratio * pg_temp.day_curve(m.b) * (0.85 + random()*0.3) *
         CASE WHEN a.code = 'open-gw' AND s.cls = '5xx'
                   AND m.b >= date_trunc('hour', now()) - interval '2 hours' THEN 8 ELSE 1 END))::float8,
       '{}'::jsonb
FROM demo_hours m
CROSS JOIN demo_apps a
CROSS JOIN (VALUES ('2xx', 0.955), ('4xx', 0.035), ('5xx', 0.010)) AS s(cls, ratio)
ON CONFLICT (bucket_start, metric, labels)
DO UPDATE SET value = EXCLUDED.value, extra = EXCLUDED.extra, updated_at = now();

INSERT INTO metric_hour_aggregates (bucket_start, metric, labels, value, extra)
SELECT x.b, 'http_request_duration_ms', jsonb_build_object('app', x.code),
       x.total, jsonb_build_object('buckets', to_jsonb(x.bk))
FROM (
  SELECT m.b, a.code, u.bk, v.total
  FROM demo_hours m
  CROSS JOIN demo_apps a
  CROSS JOIN LATERAL (SELECT round(a.base * 60 * pg_temp.day_curve(m.b) * (0.85 + random()*0.3))::float8 AS n) t
  CROSS JOIN LATERAL (SELECT ARRAY[
    round(t.n*a.w[1])::int, round(t.n*a.w[2])::int, round(t.n*a.w[3])::int, round(t.n*a.w[4])::int,
    round(t.n*a.w[5])::int, round(t.n*a.w[6])::int, round(t.n*a.w[7])::int, round(t.n*a.w[8])::int,
    round(t.n*a.w[9])::int, round(t.n*a.w[10])::int, round(t.n*a.w[11])::int] AS bk) u
  CROSS JOIN LATERAL (SELECT COALESCE(SUM(c),0)::float8 AS total FROM unnest(u.bk) c) v
) x
ON CONFLICT (bucket_start, metric, labels)
DO UPDATE SET value = EXCLUDED.value, extra = EXCLUDED.extra, updated_at = now();

INSERT INTO metric_hour_aggregates (bucket_start, metric, labels, value, extra)
SELECT m.b, s.metric, jsonb_build_object('app', a.code),
       GREATEST(0, round(a.base * 60 * s.ratio * pg_temp.day_curve(m.b) * (0.7 + random()*0.6)))::float8,
       '{}'::jsonb
FROM demo_hours m
CROSS JOIN demo_apps a
CROSS JOIN (VALUES ('waf_blocks_total', 0.018), ('waf_observes_total', 0.009)) AS s(metric, ratio)
ON CONFLICT (bucket_start, metric, labels)
DO UPDATE SET value = EXCLUDED.value, extra = EXCLUDED.extra, updated_at = now();

INSERT INTO metric_hour_aggregates (bucket_start, metric, labels, value, extra)
SELECT m.b, 'http_endpoint_requests_total',
       jsonb_build_object('app', e.app, 'endpoint', e.endpoint, 'status_class', s.cls, 'action', s.act),
       GREATEST(1, round(e.base * 60 * s.ratio * pg_temp.day_curve(m.b) * (0.8 + random()*0.4)))::float8,
       '{}'::jsonb
FROM demo_hours m
CROSS JOIN demo_endpoints e
CROSS JOIN (VALUES
  ('2xx', 'allow',   0.945),
  ('2xx', 'observe', 0.010),
  ('4xx', 'allow',   0.012),
  ('4xx', 'block',   0.023),
  ('5xx', 'allow',   0.010)) AS s(cls, act, ratio)
ON CONFLICT (bucket_start, metric, labels)
DO UPDATE SET value = EXCLUDED.value, extra = EXCLUDED.extra, updated_at = now();

INSERT INTO metric_hour_aggregates (bucket_start, metric, labels, value, extra)
SELECT x.b, x.metric, jsonb_build_object('app', x.app, 'endpoint', x.endpoint),
       x.total, jsonb_build_object('buckets', to_jsonb(x.bk))
FROM (
  SELECT m.b, s.metric, e.app, e.endpoint, u.bk, v.total
  FROM demo_hours m
  CROSS JOIN demo_endpoints e
  JOIN demo_apps a ON a.code = e.app
  CROSS JOIN (VALUES ('http_endpoint_duration_ms', 1.0), ('http_endpoint_ttfb_ms', 0.55)) AS s(metric, scale)
  CROSS JOIN LATERAL (SELECT round(e.base * 60 * s.scale * pg_temp.day_curve(m.b) * (0.8 + random()*0.4))::float8 AS n) t
  CROSS JOIN LATERAL (SELECT ARRAY[
    round(t.n*a.w[1])::int, round(t.n*a.w[2])::int, round(t.n*a.w[3])::int, round(t.n*a.w[4])::int,
    round(t.n*a.w[5])::int, round(t.n*a.w[6])::int, round(t.n*a.w[7])::int, round(t.n*a.w[8])::int,
    round(t.n*a.w[9])::int, round(t.n*a.w[10])::int, round(t.n*a.w[11])::int] AS bk) u
  CROSS JOIN LATERAL (SELECT COALESCE(SUM(c),0)::float8 AS total FROM unnest(u.bk) c) v
) x
ON CONFLICT (bucket_start, metric, labels)
DO UPDATE SET value = EXCLUDED.value, extra = EXCLUDED.extra, updated_at = now();

COMMIT;
SQL

echo "[seed-apm-demo] done. 打开「业务性能 → 性能总览 / 服务性能 / 端点性能」查看。"
