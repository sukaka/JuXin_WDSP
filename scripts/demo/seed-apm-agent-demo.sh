#!/usr/bin/env bash
# 用途：向本地演示环境注入 APM「业务性能」Agent 模式（OTel 数据面）演示数据：
#         - ClickHouse（apm.otel_traces + otel_metrics_gauge/sum/histogram）：
#           调用链检索 / SQL 诊断 / 异常分析 / 依赖分析 / 运行时指标页面的数据；
#         - PostgreSQL（apm_services / apm_agents）：让「服务性能」页
#           observation_mode 显示 agent（判定见 server/internal/apm/store.go）。
#
# 说明：
#   - 行结构严格对齐 deployment/apm/clickhouse/001-003 schema 与
#     server/internal/apm/chstore*.go 的查询列/标签口径；002 聚合表由物化视图
#     从 otel_traces 自动填充，无需单独写入；
#   - 演示 ServiceName 固定为 shop-mall / user-center（对应 applications 表演示应用），
#     实例 ID 固定为 shop-mall-pod-1 / user-center-pod-1；
#   - 幂等可重跑：写入前按演示 ServiceName/实例 ID DELETE 旧演示数据
#     （含各聚合表与 trace_id 索引表），再重新插入；PG 侧先删旧演示 Agent 再插；
#   - 本脚本只面向演示环境，不得用于生产库。
#
# 脚本会自动完成（均有判存，可安全重跑）：
#   1) 启动 ClickHouse 容器（deployment/docker-compose.apm.yml，仅 clickhouse 服务）；
#   2) 将 ClickHouse 接入 stage5 栈网络（api 经容器名解析）；
#   3) 灌入 ClickHouse 演示数据与 PG Agent 登记数据。
# ClickHouse 管理员密码取值顺序：环境变量 CLICKHOUSE_ADMIN_PASSWORD → 仓库根 .env
# 同名变量 → 随机生成（生成时会提示，请自行持久化）。
#
# 用法：
#   ./scripts/demo/seed-apm-agent-demo.sh
#   CH_CONTAINER=my-clickhouse PG_CONTAINER=my-postgres ./scripts/demo/seed-apm-agent-demo.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CH_CONTAINER="${CH_CONTAINER:-jiuzhang-apm-clickhouse}"
PG_CONTAINER="${PG_CONTAINER:-jiuzhang-stage5-postgres}"
STAGE5_NETWORK="${STAGE5_NETWORK:-jiuzhang-stage5_stage5-net}"
APM_COMPOSE="${APM_COMPOSE:-$REPO_ROOT/deployment/docker-compose.apm.yml}"

DEMO_SERVICES="('shop-mall', 'user-center')"

echo "[seed-apm-agent-demo] ch=$CH_CONTAINER pg=$PG_CONTAINER network=$STAGE5_NETWORK"

# ---------- 1) 确保 ClickHouse 容器运行 ----------
if ! docker ps --format '{{.Names}}' | grep -qx "$CH_CONTAINER"; then
  if docker ps -a --format '{{.Names}}' | grep -qx "$CH_CONTAINER"; then
    echo "[seed-apm-agent-demo] 容器已存在但未运行，启动中..."
    docker start "$CH_CONTAINER" >/dev/null
  else
    pw="${CLICKHOUSE_ADMIN_PASSWORD:-}"
    if [ -z "$pw" ] && [ -f "$REPO_ROOT/.env" ]; then
      pw="$(grep '^CLICKHOUSE_ADMIN_PASSWORD=' "$REPO_ROOT/.env" | tail -1 | cut -d= -f2- || true)"
    fi
    if [ -z "$pw" ]; then
      pw="$(openssl rand -hex 12)"
      echo "[seed-apm-agent-demo] 已生成演示密码（请自行持久化，勿用于生产）：CLICKHOUSE_ADMIN_PASSWORD=$pw"
    fi
    echo "[seed-apm-agent-demo] 创建 ClickHouse 容器（compose 仅 clickhouse 服务）..."
    # compose 解析时会插值全部服务（含未启动的 collector-central 的必填变量），给占位值即可
    CLICKHOUSE_ADMIN_PASSWORD="$pw" \
    CLICKHOUSE_APM_WRITER_PASSWORD="${CLICKHOUSE_APM_WRITER_PASSWORD:-$pw}" \
      docker compose -f "$APM_COMPOSE" --profile central up -d clickhouse >/dev/null
  fi
fi

CH_PASS="$(docker exec "$CH_CONTAINER" printenv CLICKHOUSE_PASSWORD)"

# ---------- 2) 接入 stage5 网络（判存） ----------
if ! docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$CH_CONTAINER" | tr ' ' '\n' | grep -qx "$STAGE5_NETWORK"; then
  echo "[seed-apm-agent-demo] 将 $CH_CONTAINER 接入网络 $STAGE5_NETWORK ..."
  docker network connect "$STAGE5_NETWORK" "$CH_CONTAINER" >/dev/null
fi

# ---------- 3) 等待 ClickHouse 就绪 ----------
# 注意：entrypoint 先起服务再跑 initdb.d 建表，仅 SELECT 1 就绪不代表 schema 就绪，
# 必须等关键表存在（首启空卷时 001-003 会依次执行）。
echo "[seed-apm-agent-demo] 等待 ClickHouse 就绪（含 schema 初始化）..."
for i in $(seq 1 90); do
  if docker exec "$CH_CONTAINER" clickhouse-client --password "$CH_PASS" -q \
       "SELECT count() = 2 FROM system.tables WHERE database = 'apm' AND name IN ('otel_traces', 'otel_metrics_histogram')" 2>/dev/null | grep -qx 1; then
    break
  fi
  if [ "$i" = "90" ]; then
    echo "[seed-apm-agent-demo] ERROR: ClickHouse 180s 内未就绪（schema 未初始化）" >&2
    exit 1
  fi
  sleep 2
done

ch() { docker exec -i "$CH_CONTAINER" clickhouse-client --password "$CH_PASS" --multiquery; }

# ---------- 4) 清理旧演示数据（幂等；物化视图聚合表不含原始回溯，需一并删） ----------
echo "[seed-apm-agent-demo] 清理旧演示数据..."
ch <<SQL
DELETE FROM apm.otel_traces_trace_id_ts
  WHERE TraceId IN (SELECT TraceId FROM apm.otel_traces WHERE ServiceName IN $DEMO_SERVICES)
  SETTINGS mutations_sync = 1;
DELETE FROM apm.apm_service_minutes        WHERE ServiceName IN $DEMO_SERVICES SETTINGS mutations_sync = 1;
DELETE FROM apm.apm_endpoint_minutes       WHERE ServiceName IN $DEMO_SERVICES SETTINGS mutations_sync = 1;
DELETE FROM apm.apm_sql_minutes            WHERE ServiceName IN $DEMO_SERVICES SETTINGS mutations_sync = 1;
DELETE FROM apm.apm_service_hours          WHERE ServiceName IN $DEMO_SERVICES SETTINGS mutations_sync = 1;
DELETE FROM apm.apm_endpoint_hours         WHERE ServiceName IN $DEMO_SERVICES SETTINGS mutations_sync = 1;
DELETE FROM apm.apm_service_days           WHERE ServiceName IN $DEMO_SERVICES SETTINGS mutations_sync = 1;
DELETE FROM apm.apm_exception_fingerprints WHERE ServiceName IN $DEMO_SERVICES SETTINGS mutations_sync = 1;
DELETE FROM apm.otel_metrics_gauge         WHERE ServiceName IN $DEMO_SERVICES SETTINGS mutations_sync = 1;
DELETE FROM apm.otel_metrics_sum           WHERE ServiceName IN $DEMO_SERVICES SETTINGS mutations_sync = 1;
DELETE FROM apm.otel_metrics_histogram     WHERE ServiceName IN $DEMO_SERVICES SETTINGS mutations_sync = 1;
DELETE FROM apm.otel_traces                WHERE ServiceName IN $DEMO_SERVICES SETTINGS mutations_sync = 1;
SQL

# ---------- 5) 注入 OTel trace/span 演示数据 ----------
# 10 种 trace 模板（tpl = n % 10，每模板 4 条，共 40 条 trace、~150 span）：
#   0 shop-mall  GET /api/products/{id}      server→internal→pg SELECT + redis GET
#   1 shop-mall  GET /api/products           server→internal→pg SELECT(列表)
#   2 shop-mall  POST /api/orders            server→internal→pg INSERT→http user-center→http pay
#   3 shop-mall  POST /api/orders（支付 502，root/payment Error + exception）
#   4 shop-mall  POST /api/cart/items        server→pg UPDATE
#   5 shop-mall  GET /api/users/me           server→http user-center
#   6 shop-mall  GET /api/products/{id}（redis 超时 3s 慢 trace，redis Error + exception）
#   7 user-center POST /api/login            server→internal→mysql SELECT
#   8 user-center GET /api/users/{id}        server→mysql SELECT
#   9 user-center PUT /api/users/{id}（mysql 死锁，root/db Error + exception）
# 时间分布在最近约 3 小时内（接口限窗 24h）。
echo "[seed-apm-agent-demo] 注入 otel_traces（40 traces）..."
ch <<'SQL'
INSERT INTO apm.otel_traces
  (Timestamp, TraceId, SpanId, ParentSpanId, TraceState, SpanName, SpanKind, ServiceName,
   ResourceAttributes, ScopeName, ScopeVersion, SpanAttributes, Duration, StatusCode, StatusMessage,
   Events.Timestamp, Events.Name, Events.Attributes,
   Links.TraceId, Links.SpanId, Links.TraceState, Links.Attributes)
WITH tr AS (
  SELECT
    number AS n,
    n % 10 AS tpl,
    ['shop-mall','shop-mall','shop-mall','shop-mall','shop-mall','shop-mall','shop-mall',
     'user-center','user-center','user-center'][n % 10 + 1] AS svc,
    if(n % 10 <= 6, 'shop-mall-pod-1', 'user-center-pod-1') AS inst,
    lower(hex(MD5(concat('jz-demo-agent-trace-', toString(n))))) AS tid,
    now64(9) - toIntervalSecond(300 + n * 240 + (n % 7) * 113) AS t0,
    toUInt64((40 + (n * 53) % 240
      + multiIf(n % 10 = 3, 900, n % 10 = 9, 350, n % 10 = 6, 3100, 0)) * 1000000) AS root_dur
  FROM numbers(1, 40)
)
-- ---- 角色1：root server span（每条 trace 一个） ----
SELECT
  t0 AS Timestamp,
  tid AS TraceId,
  substring(lower(hex(MD5(concat(tid, '-root')))), 1, 16) AS SpanId,
  '' AS ParentSpanId,
  '' AS TraceState,
  ['GET /api/products/{id}','GET /api/products','POST /api/orders','POST /api/orders',
   'POST /api/cart/items','GET /api/users/me','GET /api/products/{id}',
   'POST /api/login','GET /api/users/{id}','PUT /api/users/{id}'][tpl + 1] AS SpanName,
  'Server' AS SpanKind,
  svc AS ServiceName,
  map('service.name', svc, 'service.instance.id', inst,
      'deployment.environment.name', 'production', 'telemetry.sdk.language', 'go',
      'service.version', '1.8.2') AS ResourceAttributes,
  'demo/seed-apm-agent' AS ScopeName,
  '1.0.0' AS ScopeVersion,
  map('http.method',
        ['GET','GET','POST','POST','POST','GET','GET','POST','GET','PUT'][tpl + 1],
      'http.route',
        ['/api/products/{id}','/api/products','/api/orders','/api/orders','/api/cart/items',
         '/api/users/me','/api/products/{id}','/api/login','/api/users/{id}','/api/users/{id}'][tpl + 1],
      'http.status_code', multiIf(tpl = 3, '502', tpl = 9, '500', '200'),
      'server.address', svc || '.demo.internal', 'server.port', '8080') AS SpanAttributes,
  root_dur AS Duration,
  multiIf(tpl IN (3, 9), 'Error', 'Unset') AS StatusCode,
  multiIf(tpl = 3, 'payment gateway returned 502', tpl = 9, 'internal server error', '') AS StatusMessage,
  CAST([] AS Array(DateTime64(9))) AS `Events.Timestamp`,
  CAST([] AS Array(String)) AS `Events.Name`,
  CAST([] AS Array(Map(LowCardinality(String), String))) AS `Events.Attributes`,
  CAST([] AS Array(String)) AS `Links.TraceId`,
  CAST([] AS Array(String)) AS `Links.SpanId`,
  CAST([] AS Array(String)) AS `Links.TraceState`,
  CAST([] AS Array(Map(LowCardinality(String), String))) AS `Links.Attributes`
FROM tr
UNION ALL
-- ---- 角色2：internal span（tpl 0,1,2,3,6,7,9） ----
SELECT
  t0 + toIntervalMillisecond(5) AS Timestamp,
  tid AS TraceId,
  substring(lower(hex(MD5(concat(tid, '-r2')))), 1, 16) AS SpanId,
  substring(lower(hex(MD5(concat(tid, '-root')))), 1, 16) AS ParentSpanId,
  '' AS TraceState,
  ['catalog.getProductDetail','catalog.listProducts','order.createOrder','order.createOrder',
   '-','-','catalog.getProductDetail','auth.verifyCredential','-','user.updateProfile'][tpl + 1] AS SpanName,
  'Internal' AS SpanKind,
  svc AS ServiceName,
  map('service.name', svc, 'service.instance.id', inst,
      'deployment.environment.name', 'production', 'telemetry.sdk.language', 'go') AS ResourceAttributes,
  'demo/seed-apm-agent' AS ScopeName,
  '1.0.0' AS ScopeVersion,
  map('code.namespace', svc || '/internal/service') AS SpanAttributes,
  toUInt64(root_dur * 6 / 10) AS Duration,
  'Unset' AS StatusCode,
  '' AS StatusMessage,
  CAST([] AS Array(DateTime64(9))) AS `Events.Timestamp`,
  CAST([] AS Array(String)) AS `Events.Name`,
  CAST([] AS Array(Map(LowCardinality(String), String))) AS `Events.Attributes`,
  CAST([] AS Array(String)) AS `Links.TraceId`,
  CAST([] AS Array(String)) AS `Links.SpanId`,
  CAST([] AS Array(String)) AS `Links.TraceState`,
  CAST([] AS Array(Map(LowCardinality(String), String))) AS `Links.Attributes`
FROM tr WHERE tpl IN (0, 1, 2, 3, 6, 7, 9)
UNION ALL
-- ---- 角色3：db client span（tpl 0,1,2,3,4,6,7,8,9；tpl9 死锁 Error + exception） ----
SELECT
  t0 + toIntervalMillisecond(8) AS Timestamp,
  tid AS TraceId,
  substring(lower(hex(MD5(concat(tid, '-r3')))), 1, 16) AS SpanId,
  if(tpl IN (4, 8),
     substring(lower(hex(MD5(concat(tid, '-root')))), 1, 16),
     substring(lower(hex(MD5(concat(tid, '-r2')))), 1, 16)) AS ParentSpanId,
  '' AS TraceState,
  ['SELECT','SELECT','INSERT','INSERT','UPDATE','','SELECT','SELECT','SELECT','UPDATE'][tpl + 1]
    || ' ' || if(tpl >= 7, 'userdb', 'shop')
    || ['.products','.products','.orders','.orders','.cart_items','','.products',
        '.users','.users','.users'][tpl + 1] AS SpanName,
  'Client' AS SpanKind,
  svc AS ServiceName,
  map('service.name', svc, 'service.instance.id', inst,
      'deployment.environment.name', 'production', 'telemetry.sdk.language', 'go') AS ResourceAttributes,
  'demo/seed-apm-agent' AS ScopeName,
  '1.0.0' AS ScopeVersion,
  map('db.system', if(tpl >= 7, 'mysql', 'postgresql'),
      'db.statement',
        ['SELECT id, name, price, stock FROM products WHERE id = ?',
         'SELECT id, name, price FROM products WHERE category = ? AND enabled = ? ORDER BY created_at DESC LIMIT ?',
         'INSERT INTO orders (order_no, user_id, total_amount, status) VALUES (?, ?, ?, ?)',
         'INSERT INTO orders (order_no, user_id, total_amount, status) VALUES (?, ?, ?, ?)',
         'UPDATE cart_items SET quantity = ?, updated_at = ? WHERE user_id = ? AND sku = ?',
         '',
         'SELECT id, name, price, stock FROM products WHERE id = ?',
         'SELECT id, username, password_hash, status FROM users WHERE username = ?',
         'SELECT id, username, nickname, email, status FROM users WHERE id = ?',
         'UPDATE users SET nickname = ?, updated_at = ? WHERE id = ?'][tpl + 1],
      'db.namespace', if(tpl >= 7, 'userdb', 'shop'),
      'db.operation.name',
        ['SELECT','SELECT','INSERT','INSERT','UPDATE','','SELECT','SELECT','SELECT','UPDATE'][tpl + 1],
      'server.address', if(tpl >= 7, 'mysql-primary', 'pg-primary'),
      'server.port', if(tpl >= 7, '3306', '5432')) AS SpanAttributes,
  if(tpl = 9, toUInt64((250 + (n * 7) % 120) * 1000000),
             toUInt64((2 + (n * 11) % 25) * 1000000)) AS Duration,
  if(tpl = 9, 'Error', 'Unset') AS StatusCode,
  if(tpl = 9, 'Error 1213 (40001): Deadlock found', '') AS StatusMessage,
  if(tpl = 9, [t0 + toIntervalMillisecond(toInt64(250 + (n * 7) % 120))],
             CAST([] AS Array(DateTime64(9)))) AS `Events.Timestamp`,
  if(tpl = 9, ['exception'], CAST([] AS Array(String))) AS `Events.Name`,
  if(tpl = 9,
     [map('exception.type', '*mysql.MySQLError',
          'exception.message', 'Error 1213 (40001): Deadlock found when trying to get lock; try restarting transaction',
          'exception.stacktrace', 'database/sql.(*DB).exec\n\t/usr/local/go/src/database/sql/sql.go:1700\nuser-center/internal/repo.(*UserRepo).UpdateNickname\n\t/app/internal/repo/user.go:88\nuser-center/internal/service.(*UserService).UpdateProfile\n\t/app/internal/service/user.go:45')],
     CAST([] AS Array(Map(LowCardinality(String), String)))) AS `Events.Attributes`,
  CAST([] AS Array(String)) AS `Links.TraceId`,
  CAST([] AS Array(String)) AS `Links.SpanId`,
  CAST([] AS Array(String)) AS `Links.TraceState`,
  CAST([] AS Array(Map(LowCardinality(String), String))) AS `Links.Attributes`
FROM tr WHERE tpl IN (0, 1, 2, 3, 4, 6, 7, 8, 9)
UNION ALL
-- ---- 角色4：redis client span（tpl 0 正常 / tpl 6 超时 3s Error + exception） ----
SELECT
  t0 + toIntervalMillisecond(15) AS Timestamp,
  tid AS TraceId,
  substring(lower(hex(MD5(concat(tid, '-r4')))), 1, 16) AS SpanId,
  substring(lower(hex(MD5(concat(tid, '-r2')))), 1, 16) AS ParentSpanId,
  '' AS TraceState,
  'GET product:cache' AS SpanName,
  'Client' AS SpanKind,
  svc AS ServiceName,
  map('service.name', svc, 'service.instance.id', inst,
      'deployment.environment.name', 'production', 'telemetry.sdk.language', 'go') AS ResourceAttributes,
  'demo/seed-apm-agent' AS ScopeName,
  '1.0.0' AS ScopeVersion,
  map('db.system', 'redis', 'db.statement', 'GET product:?', 'db.namespace', '0',
      'db.operation.name', 'GET', 'server.address', 'redis-master', 'server.port', '6379') AS SpanAttributes,
  if(tpl = 6, toUInt64(3000 * 1000000), toUInt64((1 + n % 3) * 1000000)) AS Duration,
  if(tpl = 6, 'Error', 'Unset') AS StatusCode,
  if(tpl = 6, 'redis: i/o timeout', '') AS StatusMessage,
  if(tpl = 6, [t0 + toIntervalMillisecond(3015)], CAST([] AS Array(DateTime64(9)))) AS `Events.Timestamp`,
  if(tpl = 6, ['exception'], CAST([] AS Array(String))) AS `Events.Name`,
  if(tpl = 6,
     [map('exception.type', '*net.OpError',
          'exception.message', 'read tcp 10.20.0.8:6379: i/o timeout',
          'exception.stacktrace', 'net.(*conn).Read\n\t/usr/local/go/src/net/net.go:190\nshop-mall/internal/cache.(*RedisCache).Get\n\t/app/internal/cache/redis.go:57\nshop-mall/internal/service.(*CatalogService).getProductDetail\n\t/app/internal/service/catalog.go:112')],
     CAST([] AS Array(Map(LowCardinality(String), String)))) AS `Events.Attributes`,
  CAST([] AS Array(String)) AS `Links.TraceId`,
  CAST([] AS Array(String)) AS `Links.SpanId`,
  CAST([] AS Array(String)) AS `Links.TraceState`,
  CAST([] AS Array(Map(LowCardinality(String), String))) AS `Links.Attributes`
FROM tr WHERE tpl IN (0, 6)
UNION ALL
-- ---- 角色5：内部服务 http client span（tpl 2,3,5 → peer.service=user-center） ----
SELECT
  t0 + toIntervalMillisecond(12) AS Timestamp,
  tid AS TraceId,
  substring(lower(hex(MD5(concat(tid, '-r5')))), 1, 16) AS SpanId,
  if(tpl = 5,
     substring(lower(hex(MD5(concat(tid, '-root')))), 1, 16),
     substring(lower(hex(MD5(concat(tid, '-r2')))), 1, 16)) AS ParentSpanId,
  '' AS TraceState,
  if(tpl = 5, 'GET /internal/users/{id}', 'POST /internal/users/validate') AS SpanName,
  'Client' AS SpanKind,
  svc AS ServiceName,
  map('service.name', svc, 'service.instance.id', inst,
      'deployment.environment.name', 'production', 'telemetry.sdk.language', 'go') AS ResourceAttributes,
  'demo/seed-apm-agent' AS ScopeName,
  '1.0.0' AS ScopeVersion,
  map('http.method', if(tpl = 5, 'GET', 'POST'),
      'http.route', if(tpl = 5, '/internal/users/{id}', '/internal/users/validate'),
      'http.status_code', '200',
      'peer.service', 'user-center', 'server.address', 'user-center', 'server.port', '8080') AS SpanAttributes,
  toUInt64((4 + (n * 7) % 20) * 1000000) AS Duration,
  'Unset' AS StatusCode,
  '' AS StatusMessage,
  CAST([] AS Array(DateTime64(9))) AS `Events.Timestamp`,
  CAST([] AS Array(String)) AS `Events.Name`,
  CAST([] AS Array(Map(LowCardinality(String), String))) AS `Events.Attributes`,
  CAST([] AS Array(String)) AS `Links.TraceId`,
  CAST([] AS Array(String)) AS `Links.SpanId`,
  CAST([] AS Array(String)) AS `Links.TraceState`,
  CAST([] AS Array(Map(LowCardinality(String), String))) AS `Links.Attributes`
FROM tr WHERE tpl IN (2, 3, 5)
UNION ALL
-- ---- 角色6：外部支付 http client span（tpl 2 正常 / tpl 3 502 Error + exception） ----
SELECT
  t0 + toIntervalMillisecond(25) AS Timestamp,
  tid AS TraceId,
  substring(lower(hex(MD5(concat(tid, '-r6')))), 1, 16) AS SpanId,
  substring(lower(hex(MD5(concat(tid, '-r2')))), 1, 16) AS ParentSpanId,
  '' AS TraceState,
  'POST /v1/payments' AS SpanName,
  'Client' AS SpanKind,
  svc AS ServiceName,
  map('service.name', svc, 'service.instance.id', inst,
      'deployment.environment.name', 'production', 'telemetry.sdk.language', 'go') AS ResourceAttributes,
  'demo/seed-apm-agent' AS ScopeName,
  '1.0.0' AS ScopeVersion,
  map('http.method', 'POST', 'http.route', '/v1/payments',
      'http.status_code', if(tpl = 3, '502', '200'),
      'server.address', 'pay.example.com', 'server.port', '443') AS SpanAttributes,
  if(tpl = 3, toUInt64((500 + (n * 17) % 300) * 1000000),
              toUInt64((80 + (n * 13) % 150) * 1000000)) AS Duration,
  if(tpl = 3, 'Error', 'Unset') AS StatusCode,
  if(tpl = 3, 'payment gateway returned HTTP 502', '') AS StatusMessage,
  if(tpl = 3, [t0 + toIntervalMillisecond(toInt64(525 + (n * 17) % 300))],
             CAST([] AS Array(DateTime64(9)))) AS `Events.Timestamp`,
  if(tpl = 3, ['exception'], CAST([] AS Array(String))) AS `Events.Name`,
  if(tpl = 3,
     [map('exception.type', 'PaymentGatewayError',
          'exception.message', 'payment gateway returned HTTP 502 Bad Gateway',
          'exception.stacktrace', 'net/http.(*Client).Do\n\t/usr/local/go/src/net/http/client.go:590\nshop-mall/internal/pay.(*GatewayClient).Charge\n\t/app/internal/pay/gateway.go:74\nshop-mall/internal/service.(*OrderService).CreateOrder\n\t/app/internal/service/order.go:96')],
     CAST([] AS Array(Map(LowCardinality(String), String)))) AS `Events.Attributes`,
  CAST([] AS Array(String)) AS `Links.TraceId`,
  CAST([] AS Array(String)) AS `Links.SpanId`,
  CAST([] AS Array(String)) AS `Links.TraceState`,
  CAST([] AS Array(Map(LowCardinality(String), String))) AS `Links.Attributes`
FROM tr WHERE tpl IN (2, 3);
SQL

# ---------- 6) 注入运行时指标（近 1 小时、每分钟 1 点、2 个实例） ----------
# gauge：go.memory.used（go.memory.type=other/stack 双序列）、go.goroutines
# sum：go.memory.allocations（cumulative counter）
# histogram：go.schedule.duration（Sum/Count 折算均值）
echo "[seed-apm-agent-demo] 注入运行时指标（gauge/sum/histogram）..."
ch <<'SQL'
INSERT INTO apm.otel_metrics_gauge
  (ResourceAttributes, ResourceSchemaUrl, ScopeName, ScopeVersion, ScopeAttributes, ScopeDroppedAttrCount,
   ScopeSchemaUrl, ServiceName, MetricName, MetricDescription, MetricUnit, Attributes,
   StartTimeUnix, TimeUnix, Value, Flags,
   Exemplars.FilteredAttributes, Exemplars.TimeUnix, Exemplars.Value, Exemplars.SpanId, Exemplars.TraceId)
SELECT
  map('service.name', svc, 'service.instance.id', inst, 'deployment.environment.name', 'production',
      'telemetry.sdk.language', 'go') AS ResourceAttributes,
  '' AS ResourceSchemaUrl,
  'go.opentelemetry.io/contrib/instrumentation/runtime' AS ScopeName,
  '0.45.0' AS ScopeVersion,
  map() AS ScopeAttributes,
  toUInt32(0) AS ScopeDroppedAttrCount,
  '' AS ScopeSchemaUrl,
  svc AS ServiceName,
  m.1 AS MetricName,
  m.2 AS MetricDescription,
  m.3 AS MetricUnit,
  if(m.4 = '', map(), map('go.memory.type', m.4)) AS Attributes,
  now64(9) - toIntervalSecond(7200) AS StartTimeUnix,
  now64(9) - toIntervalSecond(i * 60 + 15) AS TimeUnix,
  toFloat64(multiIf(
    m.1 = 'go.memory.used' AND m.4 = 'other', 42000000 + (i * 37 % 18) * 1500000 + (si - 1) * 8000000,
    m.1 = 'go.memory.used', 2400000 + (i * 11 % 9) * 300000 + (si - 1) * 500000,
    130 + (i * 7 % 95) + (si - 1) * 70)) AS Value,
  toUInt32(0) AS Flags,
  CAST([] AS Array(Map(LowCardinality(String), String))) AS `Exemplars.FilteredAttributes`,
  CAST([] AS Array(DateTime64(9))) AS `Exemplars.TimeUnix`,
  CAST([] AS Array(Float64)) AS `Exemplars.Value`,
  CAST([] AS Array(String)) AS `Exemplars.SpanId`,
  CAST([] AS Array(String)) AS `Exemplars.TraceId`
FROM (
  SELECT i, si, ['shop-mall', 'user-center'][si] AS svc,
         ['shop-mall-pod-1', 'user-center-pod-1'][si] AS inst
  FROM (SELECT arrayJoin(range(0, 60)) AS i) t1
  CROSS JOIN (SELECT arrayJoin([1, 2]) AS si) t2
) base
CROSS JOIN (
  SELECT arrayJoin([
    ('go.memory.used', 'Memory used by the Go runtime.', 'By', 'other'),
    ('go.memory.used', 'Memory used by the Go runtime.', 'By', 'stack'),
    ('go.goroutines', 'Number of goroutines that currently exist.', '{thread}', '')
  ]) AS m
) series;

INSERT INTO apm.otel_metrics_sum
  (ResourceAttributes, ResourceSchemaUrl, ScopeName, ScopeVersion, ScopeAttributes, ScopeDroppedAttrCount,
   ScopeSchemaUrl, ServiceName, MetricName, MetricDescription, MetricUnit, Attributes,
   StartTimeUnix, TimeUnix, Value, Flags,
   Exemplars.FilteredAttributes, Exemplars.TimeUnix, Exemplars.Value, Exemplars.SpanId, Exemplars.TraceId,
   AggregationTemporality, IsMonotonic)
SELECT
  map('service.name', svc, 'service.instance.id', inst, 'deployment.environment.name', 'production',
      'telemetry.sdk.language', 'go') AS ResourceAttributes,
  '' AS ResourceSchemaUrl,
  'go.opentelemetry.io/contrib/instrumentation/runtime' AS ScopeName,
  '0.45.0' AS ScopeVersion,
  map() AS ScopeAttributes,
  toUInt32(0) AS ScopeDroppedAttrCount,
  '' AS ScopeSchemaUrl,
  svc AS ServiceName,
  'go.memory.allocations' AS MetricName,
  'Count of allocations to the heap by the application.' AS MetricDescription,
  '{allocation}' AS MetricUnit,
  map() AS Attributes,
  now64(9) - toIntervalSecond(7200) AS StartTimeUnix,
  now64(9) - toIntervalSecond(i * 60 + 15) AS TimeUnix,
  toFloat64(8500000 + (7200 - i * 60) * (900 + si * 140)) AS Value,
  toUInt32(0) AS Flags,
  CAST([] AS Array(Map(LowCardinality(String), String))) AS `Exemplars.FilteredAttributes`,
  CAST([] AS Array(DateTime64(9))) AS `Exemplars.TimeUnix`,
  CAST([] AS Array(Float64)) AS `Exemplars.Value`,
  CAST([] AS Array(String)) AS `Exemplars.SpanId`,
  CAST([] AS Array(String)) AS `Exemplars.TraceId`,
  toInt32(2) AS AggregationTemporality,
  toBool(1) AS IsMonotonic
FROM (
  SELECT i, si, ['shop-mall', 'user-center'][si] AS svc,
         ['shop-mall-pod-1', 'user-center-pod-1'][si] AS inst
  FROM (SELECT arrayJoin(range(0, 60)) AS i) t1
  CROSS JOIN (SELECT arrayJoin([1, 2]) AS si) t2
) base;

INSERT INTO apm.otel_metrics_histogram
  (ResourceAttributes, ResourceSchemaUrl, ScopeName, ScopeVersion, ScopeAttributes, ScopeDroppedAttrCount,
   ScopeSchemaUrl, ServiceName, MetricName, MetricDescription, MetricUnit, Attributes,
   StartTimeUnix, TimeUnix, Count, Sum, BucketCounts, ExplicitBounds,
   Exemplars.FilteredAttributes, Exemplars.TimeUnix, Exemplars.Value, Exemplars.SpanId, Exemplars.TraceId,
   Flags, Min, Max, AggregationTemporality)
SELECT
  map('service.name', svc, 'service.instance.id', inst, 'deployment.environment.name', 'production',
      'telemetry.sdk.language', 'go') AS ResourceAttributes,
  '' AS ResourceSchemaUrl,
  'go.opentelemetry.io/contrib/instrumentation/runtime' AS ScopeName,
  '0.45.0' AS ScopeVersion,
  map() AS ScopeAttributes,
  toUInt32(0) AS ScopeDroppedAttrCount,
  '' AS ScopeSchemaUrl,
  svc AS ServiceName,
  'go.schedule.duration' AS MetricName,
  'The time goroutines spend waiting for the scheduler.' AS MetricDescription,
  's' AS MetricUnit,
  map() AS Attributes,
  now64(9) - toIntervalSecond(7200) AS StartTimeUnix,
  now64(9) - toIntervalSecond(i * 60 + 15) AS TimeUnix,
  cnt AS Count,
  cnt * (0.00002 + (i % 10) * 0.000001) AS Sum,
  [toUInt64(cnt * 0.50), toUInt64(cnt * 0.20), toUInt64(cnt * 0.12), toUInt64(cnt * 0.08),
   toUInt64(cnt * 0.05), toUInt64(cnt * 0.03), toUInt64(cnt * 0.01), toUInt64(cnt * 0.008),
   toUInt64(cnt * 0.002)] AS BucketCounts,
  [0, 0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.001, 0.01] AS ExplicitBounds,
  CAST([] AS Array(Map(LowCardinality(String), String))) AS `Exemplars.FilteredAttributes`,
  CAST([] AS Array(DateTime64(9))) AS `Exemplars.TimeUnix`,
  CAST([] AS Array(Float64)) AS `Exemplars.Value`,
  CAST([] AS Array(String)) AS `Exemplars.SpanId`,
  CAST([] AS Array(String)) AS `Exemplars.TraceId`,
  toUInt32(0) AS Flags,
  0.000001 AS Min,
  0.005 AS Max,
  toInt32(2) AS AggregationTemporality
FROM (
  SELECT i, si, ['shop-mall', 'user-center'][si] AS svc,
         ['shop-mall-pod-1', 'user-center-pod-1'][si] AS inst,
         toUInt64(4000 + (i * 13 % 2500) + si * 500) AS cnt
  FROM (SELECT arrayJoin(range(0, 60)) AS i) t1
  CROSS JOIN (SELECT arrayJoin([1, 2]) AS si) t2
) base;
SQL

# ---------- 7) PG：apm_services / apm_agents 演示登记（observation_mode=agent） ----------
echo "[seed-apm-agent-demo] 注入 PG Agent 登记数据..."
PG_USER="$(docker exec "$PG_CONTAINER" printenv POSTGRES_USER)"
PG_DB="$(docker exec "$PG_CONTAINER" printenv POSTGRES_DB)"

docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;

-- 服务映射（shop-mall / user-center → 演示应用，CLAIMED）
INSERT INTO apm_services (service_name, environment, application_id, claim_status, first_seen_at, last_seen_at)
SELECT a.code, 'production', a.id, 'CLAIMED', now() - interval '2 hours', now()
FROM applications a
WHERE a.code IN ('shop-mall', 'user-center') AND a.deleted_at IS NULL
ON CONFLICT (service_name, environment) DO UPDATE
  SET application_id = EXCLUDED.application_id,
      claim_status = 'CLAIMED',
      last_seen_at = now(),
      updated_at = now();

-- 幂等：先删除旧演示 Agent（实例 ID 固定）
DELETE FROM apm_agents
WHERE service_id IN (SELECT id FROM apm_services WHERE service_name IN ('shop-mall', 'user-center'))
  AND instance_id IN ('shop-mall-pod-1', 'user-center-pod-1');

-- 演示 Agent：心跳为当前时间、存态 CONNECTED_BASELINE（非 REVOKED → 在线）
INSERT INTO apm_agents
  (service_id, instance_id, language, agent_version, sdk_version, status,
   cert_fingerprint, cert_not_after, last_heartbeat_at, node_info, registered_at)
SELECT s.id, s.service_name || '-pod-1', 'go', '0.4.2', 'otel-go-1.28.0', 'CONNECTED_BASELINE',
       repeat(md5('jz-demo-agent-cert-' || s.service_name), 2),
       now() + interval '72 hours', now(),
       jsonb_build_object('hostname', s.service_name || '-pod-1', 'pid', 1,
                          'os', 'linux', 'arch', 'arm64', 'ip', '10.20.0.' || (10 + row_number() OVER ())),
       now() - interval '2 hours'
FROM apm_services s
WHERE s.service_name IN ('shop-mall', 'user-center');

COMMIT;
SQL

# ---------- 8) 汇总 ----------
echo "[seed-apm-agent-demo] ClickHouse 行数："
ch <<'SQL'
SELECT 'otel_traces', count() FROM apm.otel_traces
UNION ALL SELECT 'otel_traces_trace_id_ts', count() FROM apm.otel_traces_trace_id_ts
UNION ALL SELECT 'apm_service_minutes', count() FROM apm.apm_service_minutes
UNION ALL SELECT 'apm_endpoint_minutes', count() FROM apm.apm_endpoint_minutes
UNION ALL SELECT 'apm_sql_minutes', count() FROM apm.apm_sql_minutes
UNION ALL SELECT 'apm_exception_fingerprints', count() FROM apm.apm_exception_fingerprints
UNION ALL SELECT 'otel_metrics_gauge', count() FROM apm.otel_metrics_gauge
UNION ALL SELECT 'otel_metrics_sum', count() FROM apm.otel_metrics_sum
UNION ALL SELECT 'otel_metrics_histogram', count() FROM apm.otel_metrics_histogram
FORMAT TabSeparatedWithNames;
SQL

docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tA <<'SQL'
SELECT 'apm_agents: ' || count(*) || ' (' || string_agg(instance_id || '/' || status, ', ') || ')'
FROM apm_agents
WHERE instance_id IN ('shop-mall-pod-1', 'user-center-pod-1');
SQL

echo "[seed-apm-agent-demo] done. 重建 api（APM_CLICKHOUSE_DSN）后打开「业务性能」各 Agent 模式页面查看。"
