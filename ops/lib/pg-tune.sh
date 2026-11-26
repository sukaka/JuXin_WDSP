#!/bin/bash
# pg-tune.sh —— 九章 WDSP PostgreSQL 16 内存自适应调优渲染器（4G/8G/16G/32G/64G 同机混部安全档）。
#
# 用法：
#   bash ops/lib/pg-tune.sh --format conf [--profile auto|4g|8g|16g|32g|64g] [--pg-lib <dir>] [--mem-mb <MB>]
#   bash ops/lib/pg-tune.sh --format env  [--profile auto|4g|8g|16g|32g|64g] [--mem-mb <MB>]
#
# 设计口径：
#   - 面向同机混部（Caddy 网关 + 管理 API + Valkey + PostgreSQL），shared_buffers 约占 18~20%，
#     留足 OS Page Cache 与网关运行内存，杜绝 8G 云主机 OOM 与 64G 物理机默认 128MB 闲置浪费；
#   - auto 模式取「宿主机物理内存」与「容器 cgroup 限额」的较小值，并按 Linux /proc/meminfo 扣除保留区
#     后的实测阈值（6.5G/13.5G/28G/56G）准确归档；
#   - 兼容 Linux bash 4+/5+ 与 macOS /bin/bash 3.2。
set -euo pipefail

FORMAT="conf"
PROFILE="${PG_MEMORY_PROFILE:-auto}"
PG_LIB_DIR=""
MEM_MB_OVERRIDE=""
MEM_MB_SET="false"

usage() {
  cat >&2 <<'EOF'
Usage: pg-tune.sh [--format conf|env] [--profile auto|4g|8g|16g|32g|64g] [--pg-lib <dir>] [--mem-mb <MB>]
EOF
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --format)
      [[ $# -ge 2 ]] || usage
      FORMAT="$2"
      shift 2
      ;;
    --profile)
      [[ $# -ge 2 ]] || usage
      PROFILE="$2"
      shift 2
      ;;
    --pg-lib)
      [[ $# -ge 2 ]] || usage
      PG_LIB_DIR="$2"
      shift 2
      ;;
    --mem-mb)
      [[ $# -ge 2 ]] || usage
      MEM_MB_SET="true"
      MEM_MB_OVERRIDE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      printf '[pg-tune] 未知参数: %s\n' "$1" >&2
      usage
      ;;
  esac
done

case "${FORMAT}" in
  conf|env) ;;
  *)
    printf '[pg-tune] 不支持的 --format: %s（仅支持 conf / env）\n' "${FORMAT}" >&2
    exit 2
    ;;
esac

if [[ "${MEM_MB_SET}" == "true" ]]; then
  if [[ ! "${MEM_MB_OVERRIDE}" =~ ^[1-9][0-9]*$ ]]; then
    printf '[pg-tune] 无效的 --mem-mb: %s\n' "${MEM_MB_OVERRIDE}" >&2
    exit 2
  fi
fi

PROFILE_LOWER="$(printf '%s' "${PROFILE}" | tr '[:upper:]' '[:lower:]')"
case "${PROFILE_LOWER}" in
  4g|8g|16g|32g|64g|auto|"") ;;
  *)
    printf '[pg-tune] 不支持的 --profile: %s（支持 auto|4g|8g|16g|32g|64g）\n' "${PROFILE}" >&2
    exit 2
    ;;
esac

detect_mem_mb() {
  if [[ -n "${MEM_MB_OVERRIDE}" ]]; then
    if [[ ! "${MEM_MB_OVERRIDE}" =~ ^[0-9]+$ ]] || [[ "${MEM_MB_OVERRIDE}" -le 0 ]]; then
      printf '[pg-tune] 无效的 --mem-mb: %s\n' "${MEM_MB_OVERRIDE}" >&2
      exit 2
    fi
    printf '%s\n' "${MEM_MB_OVERRIDE}"
    return
  fi

  local host_mb=0
  if [[ -r /proc/meminfo ]]; then
    local kb
    kb="$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || true)"
    if [[ "${kb:-}" =~ ^[0-9]+$ ]] && [[ "${kb}" -gt 0 ]]; then
      host_mb=$((kb / 1024))
    fi
  elif command -v sysctl >/dev/null 2>&1; then
    local bytes
    bytes="$(sysctl -n hw.memsize 2>/dev/null || true)"
    if [[ "${bytes:-}" =~ ^[0-9]+$ ]] && [[ "${bytes}" -gt 0 ]]; then
      host_mb=$((bytes / 1048576))
    fi
  fi

  local cgroup_mb=0
  local cg_raw=""
  if [[ -r /sys/fs/cgroup/memory.max ]]; then
    cg_raw="$(cat /sys/fs/cgroup/memory.max 2>/dev/null || true)"
  elif [[ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]]; then
    cg_raw="$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || true)"
  fi
  # cgroup v1 未限额时常为极大正数（如 9223372036854771712），排除 >= 1PiB 值
  if [[ "${cg_raw}" =~ ^[0-9]+$ ]] && [[ "${#cg_raw}" -le 15 ]]; then
    cgroup_mb=$((cg_raw / 1048576))
  fi

  if [[ "${host_mb}" -gt 0 && "${cgroup_mb}" -gt 0 ]]; then
    if [[ "${cgroup_mb}" -lt "${host_mb}" ]]; then
      printf '%s\n' "${cgroup_mb}"
    else
      printf '%s\n' "${host_mb}"
    fi
  elif [[ "${cgroup_mb}" -gt 0 ]]; then
    printf '%s\n' "${cgroup_mb}"
  elif [[ "${host_mb}" -gt 0 ]]; then
    printf '%s\n' "${host_mb}"
  else
    # 探测失败保守回退 8G 云主机档
    printf '8192\n'
  fi
}

resolve_profile() {
  local raw
  raw="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "${raw}" in
    4g|8g|16g|32g|64g)
      printf '%s\n' "${raw}"
      return
      ;;
    auto|"")
      local mb
      mb="$(detect_mem_mb)"
      if [[ "${mb}" -ge 56000 ]]; then
        printf '64g\n'
      elif [[ "${mb}" -ge 28000 ]]; then
        printf '32g\n'
      elif [[ "${mb}" -ge 13500 ]]; then
        printf '16g\n'
      elif [[ "${mb}" -ge 6500 ]]; then
        printf '8g\n'
      else
        printf '4g\n'
      fi
      ;;
    *)
      printf '[pg-tune] 不支持的 --profile: %s（支持 auto|4g|8g|16g|32g|64g）\n' "$1" >&2
      exit 2
      ;;
  esac
}

RESOLVED_PROFILE="$(resolve_profile "${PROFILE}")"

case "${RESOLVED_PROFILE}" in
  4g)
    MAX_CONNECTIONS=120
    SHARED_BUFFERS="768MB"
    EFFECTIVE_CACHE_SIZE="2GB"
    WORK_MEM="4MB"
    MAINTENANCE_WORK_MEM="128MB"
    WAL_BUFFERS="8MB"
    MIN_WAL_SIZE="256MB"
    MAX_WAL_SIZE="1GB"
    MAX_WORKER_PROCESSES=4
    MAX_PARALLEL_WORKERS=2
    AUTOVACUUM_MAX_WORKERS=2
    AUTOVACUUM_VACUUM_SCALE="0.05"
    AUTOVACUUM_ANALYZE_SCALE="0.05"
    AUTOVACUUM_INSERT_SCALE="0.05"
    AUTOVACUUM_COST_LIMIT=400
    SHM_SIZE="256mb"
    DB_MAX_CONNS=24
    DB_BG_MAX_CONNS=12
    ;;
  8g)
    MAX_CONNECTIONS=150
    SHARED_BUFFERS="1536MB"
    EFFECTIVE_CACHE_SIZE="4GB"
    WORK_MEM="8MB"
    MAINTENANCE_WORK_MEM="256MB"
    WAL_BUFFERS="16MB"
    MIN_WAL_SIZE="512MB"
    MAX_WAL_SIZE="2GB"
    MAX_WORKER_PROCESSES=4
    MAX_PARALLEL_WORKERS=2
    AUTOVACUUM_MAX_WORKERS=3
    AUTOVACUUM_VACUUM_SCALE="0.02"
    AUTOVACUUM_ANALYZE_SCALE="0.02"
    AUTOVACUUM_INSERT_SCALE="0.05"
    AUTOVACUUM_COST_LIMIT=600
    SHM_SIZE="512mb"
    DB_MAX_CONNS=32
    DB_BG_MAX_CONNS=16
    ;;
  16g)
    MAX_CONNECTIONS=200
    SHARED_BUFFERS="3GB"
    EFFECTIVE_CACHE_SIZE="9GB"
    WORK_MEM="16MB"
    MAINTENANCE_WORK_MEM="512MB"
    WAL_BUFFERS="16MB"
    MIN_WAL_SIZE="1GB"
    MAX_WAL_SIZE="4GB"
    MAX_WORKER_PROCESSES=8
    MAX_PARALLEL_WORKERS=4
    AUTOVACUUM_MAX_WORKERS=4
    AUTOVACUUM_VACUUM_SCALE="0.02"
    AUTOVACUUM_ANALYZE_SCALE="0.02"
    AUTOVACUUM_INSERT_SCALE="0.05"
    AUTOVACUUM_COST_LIMIT=800
    SHM_SIZE="1gb"
    DB_MAX_CONNS=40
    DB_BG_MAX_CONNS=20
    ;;
  32g)
    MAX_CONNECTIONS=250
    SHARED_BUFFERS="6GB"
    EFFECTIVE_CACHE_SIZE="20GB"
    WORK_MEM="32MB"
    MAINTENANCE_WORK_MEM="1GB"
    WAL_BUFFERS="32MB"
    MIN_WAL_SIZE="2GB"
    MAX_WAL_SIZE="8GB"
    MAX_WORKER_PROCESSES=8
    MAX_PARALLEL_WORKERS=4
    AUTOVACUUM_MAX_WORKERS=4
    AUTOVACUUM_VACUUM_SCALE="0.01"
    AUTOVACUUM_ANALYZE_SCALE="0.01"
    AUTOVACUUM_INSERT_SCALE="0.02"
    AUTOVACUUM_COST_LIMIT=1200
    SHM_SIZE="2gb"
    DB_MAX_CONNS=48
    DB_BG_MAX_CONNS=24
    ;;
  64g)
    MAX_CONNECTIONS=300
    SHARED_BUFFERS="12GB"
    EFFECTIVE_CACHE_SIZE="44GB"
    WORK_MEM="64MB"
    MAINTENANCE_WORK_MEM="2GB"
    WAL_BUFFERS="64MB"
    MIN_WAL_SIZE="4GB"
    MAX_WAL_SIZE="16GB"
    MAX_WORKER_PROCESSES=16
    MAX_PARALLEL_WORKERS=8
    AUTOVACUUM_MAX_WORKERS=6
    AUTOVACUUM_VACUUM_SCALE="0.01"
    AUTOVACUUM_ANALYZE_SCALE="0.01"
    AUTOVACUUM_INSERT_SCALE="0.02"
    AUTOVACUUM_COST_LIMIT=1600
    SHM_SIZE="4gb"
    DB_MAX_CONNS=64
    DB_BG_MAX_CONNS=32
    ;;
esac

ENABLE_PG_STAT_STATEMENTS="false"
if [[ -n "${PG_LIB_DIR}" && -f "${PG_LIB_DIR}/pg_stat_statements.so" ]]; then
  ENABLE_PG_STAT_STATEMENTS="true"
fi

if [[ "${FORMAT}" == "env" ]]; then
  cat <<EOF
# 九章 WDSP PostgreSQL 内存自适应调优环境变量（profile=${RESOLVED_PROFILE}，同机混部安全档）
PG_MEMORY_PROFILE=${RESOLVED_PROFILE}
POSTGRES_SHM_SIZE=${SHM_SIZE}
POSTGRES_MAX_CONNECTIONS=${MAX_CONNECTIONS}
POSTGRES_SHARED_BUFFERS=${SHARED_BUFFERS}
POSTGRES_EFFECTIVE_CACHE_SIZE=${EFFECTIVE_CACHE_SIZE}
POSTGRES_WORK_MEM=${WORK_MEM}
POSTGRES_MAINTENANCE_WORK_MEM=${MAINTENANCE_WORK_MEM}
POSTGRES_WAL_BUFFERS=${WAL_BUFFERS}
POSTGRES_MIN_WAL_SIZE=${MIN_WAL_SIZE}
POSTGRES_MAX_WAL_SIZE=${MAX_WAL_SIZE}
POSTGRES_MAX_WORKER_PROCESSES=${MAX_WORKER_PROCESSES}
POSTGRES_MAX_PARALLEL_WORKERS=${MAX_PARALLEL_WORKERS}
POSTGRES_AUTOVACUUM_MAX_WORKERS=${AUTOVACUUM_MAX_WORKERS}
POSTGRES_AUTOVACUUM_VACUUM_SCALE_FACTOR=${AUTOVACUUM_VACUUM_SCALE}
POSTGRES_AUTOVACUUM_ANALYZE_SCALE_FACTOR=${AUTOVACUUM_ANALYZE_SCALE}
POSTGRES_AUTOVACUUM_INSERT_SCALE_FACTOR=${AUTOVACUUM_INSERT_SCALE}
POSTGRES_AUTOVACUUM_COST_LIMIT=${AUTOVACUUM_COST_LIMIT}
POSTGRES_LOG_MIN_DURATION_MS=500
DB_MAX_CONNS=${DB_MAX_CONNS}
DB_BG_MAX_CONNS=${DB_BG_MAX_CONNS}
EOF
  exit 0
fi

cat <<EOF
# ---- 九章 WDSP PostgreSQL 16 自适应调优配置（pg-tune.sh 生成）----
# 档位：${RESOLVED_PROFILE}（同机混部安全档：PostgreSQL + Caddy 网关 + 管理 API + Valkey）
# 可通过 PG_MEMORY_PROFILE=4g|8g|16g|32g|64g 覆盖并重跑 install.sh 刷新

max_connections = ${MAX_CONNECTIONS}
shared_buffers = '${SHARED_BUFFERS}'
effective_cache_size = '${EFFECTIVE_CACHE_SIZE}'
work_mem = '${WORK_MEM}'
maintenance_work_mem = '${MAINTENANCE_WORK_MEM}'

wal_buffers = '${WAL_BUFFERS}'
min_wal_size = '${MIN_WAL_SIZE}'
max_wal_size = '${MAX_WAL_SIZE}'
checkpoint_completion_target = 0.9

random_page_cost = 1.1
effective_io_concurrency = 200
max_worker_processes = ${MAX_WORKER_PROCESSES}
max_parallel_workers = ${MAX_PARALLEL_WORKERS}
max_parallel_workers_per_gather = 2
jit = off

autovacuum = on
autovacuum_max_workers = ${AUTOVACUUM_MAX_WORKERS}
autovacuum_vacuum_scale_factor = ${AUTOVACUUM_VACUUM_SCALE}
autovacuum_analyze_scale_factor = ${AUTOVACUUM_ANALYZE_SCALE}
autovacuum_vacuum_insert_scale_factor = ${AUTOVACUUM_INSERT_SCALE}
autovacuum_vacuum_cost_limit = ${AUTOVACUUM_COST_LIMIT}

log_min_duration_statement = 500
EOF

if [[ "${ENABLE_PG_STAT_STATEMENTS}" == "true" ]]; then
  cat <<'EOF'
shared_preload_libraries = 'pg_stat_statements'
pg_stat_statements.max = 5000
pg_stat_statements.track = top
EOF
fi
