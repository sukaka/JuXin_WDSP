#!/usr/bin/env bash
# 九章 §55 性能矩阵缺口项（大规模维度）本机测量驱动。
# 口径：任务书 docs/tasks/STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md 五十五「性能要求」
# 缺口三项：API 数量 10 万级 / 参数模型百万级（下发构建耗时、产物大小、构建期内存）/
# 图谱查询性能（api_call_edges 30 万边 + 10 万节点查询 P95）。
#
# 环境：一次性隔离容器 p0s3-pg（127.0.0.1:55432，postgres:16-alpine）上的独立临时库
# jiuzhang_perf（用完即删），专用一次性角色 perf（不入库任何既有凭据）；
# 全程不触碰 jiuzhang_waf / jiuzhang_waf_test，不改 server/gateway/web 源码。
#
# 测量方法：test/performance/w23-largescale/bench（Go，逐字复刻 server 侧仓储 SQL，
# 见 main.go 文件头）：
#   阶段A BuildGuardConfig API 段五查询 ×5 次 + provider 组装 + json.Marshal（GuardConfig
#         同名字段）→ 各查询 P50/P95、合计、产物字节数（json/gzip）、构建期堆内存增量；
#   阶段B 图谱六查询（ListGraphFiltered/ListTopologyFiltered 节点、listEdges 无过滤/
#         近24h/min_count、边总数 count）×21 次全行扫描 → P50/P95/max + EXPLAIN ANALYZE。
#
# 用法（仓库根目录）：
#   bash test/performance/w23-largescale.sh            # 全流程（迁移→造数→测量→删库）
#   SKIP_SEED=1 bash test/performance/w23-largescale.sh   # 已造数仅测量
#   KEEP_DB=1  bash test/performance/w23-largescale.sh    # 保留 jiuzhang_perf 供复测
# 原始数据（EXPLAIN、JSON 汇总、下发产物 gzip）保留在 /tmp/w23-largescale-<TS>/。
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TS=$(date +%s)
WORK="/tmp/w23-largescale-$TS"
mkdir -p "$WORK"

PG_CONTAINER="${PG_CONTAINER:-p0s3-pg}"
PERF_DB=jiuzhang_perf
PW_FILE=/tmp/.jiuzhang_perf_pw

PSQL() { docker exec -i "$PG_CONTAINER" psql -U jiuzhang -d "$PERF_DB" "$@"; }
PSQL_ADMIN() { docker exec -i "$PG_CONTAINER" psql -U jiuzhang -d postgres "$@"; }

echo "== w23-largescale $(date '+%Y-%m-%d %H:%M:%S') workdir=$WORK =="

# ---------- 临时库与专用角色（幂等） ----------
if ! PSQL_ADMIN -tAc "SELECT 1 FROM pg_database WHERE datname='$PERF_DB'" | grep -q 1; then
  PERF_PW=$(openssl rand -hex 16)
  printf '%s' "$PERF_PW" > "$PW_FILE"; chmod 600 "$PW_FILE"
  PSQL_ADMIN -c "CREATE ROLE perf LOGIN PASSWORD '$PERF_PW'" 2>/dev/null || true
  PSQL_ADMIN -c "CREATE DATABASE $PERF_DB OWNER perf"
  echo "[setup] created db=$PERF_DB role=perf"
else
  [ -f "$PW_FILE" ] || { echo "ABORT: 库已存在但 $PW_FILE 缺失，请手工处理"; exit 1; }
fi

# ---------- 全量迁移（用生产迁移命令，不改生产代码） ----------
if [ -z "${SKIP_MIGRATE:-}" ]; then
  N_MIG=$(PSQL -tAc "SELECT count(*) FROM schema_migrations" 2>/dev/null || echo 0)
  if [ "${N_MIG:-0}" -lt 150 ]; then
    (cd "$REPO_ROOT/server" && POSTGRES_HOST=127.0.0.1 POSTGRES_PORT=55432 \
      POSTGRES_DB=$PERF_DB POSTGRES_USER=perf POSTGRES_PASSWORD="$(cat "$PW_FILE")" \
      VALKEY_PASSWORD=unused MIGRATIONS_DIR=migrations go run ./cmd/api migrate up) \
      > "$WORK/migrate.log" 2>&1 || { echo "ABORT: migrate 失败，见 $WORK/migrate.log"; exit 1; }
    echo "[setup] migrated ($(tail -1 "$WORK/migrate.log"))"
  fi
fi

# ---------- 造数（可跳过复测） ----------
if [ -z "${SKIP_SEED:-}" ]; then
  PSQL -f - < "$SCRIPT_DIR/w23-largescale-seed.sql" > "$WORK/seed.log" 2>&1 \
    || { echo "ABORT: 造数失败，见 $WORK/seed.log"; exit 1; }
  echo "[seed] done"
fi
PSQL -tAc "SELECT 'endpoints='||count(*) FROM api_endpoints"
PSQL -tAc "SELECT 'params='||count(*) FROM api_parameter_models"
PSQL -tAc "SELECT 'edges='||count(*) FROM api_call_edges"

# ---------- 测量 ----------
export PERF_DSN="postgres://perf:$(cat "$PW_FILE")@127.0.0.1:55432/$PERF_DB?sslmode=disable"
(cd "$SCRIPT_DIR/w23-largescale/bench" && \
  GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off go mod tidy > /dev/null 2>&1; \
  GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off go run . -runs 5 -graph-runs 21 -raw "$WORK") \
  | tee "$WORK/bench-stdout.txt" || { echo "ABORT: bench 失败"; exit 1; }

# ---------- 清理（KEEP_DB=1 时保留） ----------
if [ -z "${KEEP_DB:-}" ]; then
  PSQL_ADMIN -c "DROP DATABASE $PERF_DB"
  PSQL_ADMIN -c "DROP ROLE perf" 2>/dev/null || true
  rm -f "$PW_FILE"
  echo "[cleanup] dropped db=$PERF_DB role=perf"
else
  echo "[cleanup] KEEP_DB=1 保留 $PERF_DB（凭据在 $PW_FILE）"
fi
echo "== done, raw: $WORK =="
