#!/usr/bin/env bash
# WDSP 被测机（SUT）实时性能与资源采集脚本（兼容 Docker Compose 与裸机 systemd 两种部署形态）
# 采集项：
#   1. Caddy Unix Admin /jiuzhang/runtime（连接数/CPS/RPS/in-flight/2xx~5xx/吞吐字节/软件旁路状态/FD/CPU/内存）
#   2. 宿主机 load1、CPU iowait%、系统盘与 2TB 数据盘使用率
#   3. 重点万兆网卡 rx/tx Mbps 与丢包增量 (/sys/class/net/<iface>/statistics/)
#   4. 事件日志文件体积、collector checkpoint 偏移与实时积压字节数
#   5. 容器模式或宿主进程的 Postgres / API / Valkey RSS 内存
set -euo pipefail

OUT_DIR="./metrics-$(date +%Y%m%dT%H%M%S)"
INTERVAL=5
DURATION=0          # 0 表示持续运行直到收到 Ctrl-C / SIGTERM
MODE="auto"         # auto | baremetal | docker
ADMIN_SOCK=""
GW_CONTAINER=""
API_CONTAINER=""
PG_CONTAINER=""
VALKEY_CONTAINER=""
EVENT_LOG=""
DATA_MOUNT="/data"
NIC=""
SAVE_JSONL=0

usage() {
  cat <<'EOF'
用法: collect-metrics.sh [选项]

选项:
  --out-dir DIR          输出目录（默认: ./metrics-<timestamp>）
  --interval SEC         采样间隔秒数（默认: 5；72h 长稳推荐 30 或 60）
  --duration SEC         总采集时长秒数（默认: 0，持续运行至 SIGINT/SIGTERM）
  --mode MODE            auto | baremetal | docker（默认: auto）
  --admin-sock PATH      Caddy Admin Unix Socket 路径（裸机默认 /opt/jiuzhang/data/run/caddy/admin.sock 或 /var/run/caddy/admin.sock；Docker 容器内默认 /var/run/caddy/admin.sock）
  --gw-container NAME    Docker 网关容器名（Docker 模式自动探测）
  --api-container NAME   Docker API 容器名（自动探测）
  --pg-container NAME    Docker Postgres 容器名（自动探测）
  --valkey-container N   Docker Valkey 容器名（自动探测）
  --event-log PATH       api-runtime-events.log 宿主机路径（裸机默认自动探测；Docker 若挂卷可传宿主机路径）
  --data-mount PATH      2TB 数据盘挂载点，用于监控磁盘水位（默认: /data）
  --nic IFACE            重点监控的万兆网卡名（如 ens1f0，可逗号分隔多个如 ens1f0,ens1f1）
  --save-jsonl           同时将原始 /jiuzhang/runtime 快照追加保存到 runtime-snapshots.jsonl
  -h, --help             显示帮助

示例:
  # KY5288G1 裸机网关 72h 长稳采集（每 30 秒采样一次）
  sudo bash collect-metrics.sh --mode baremetal --out-dir /data/stress/soak-72h \
    --interval 30 --nic ens1f0 --data-mount /data

  # 阿里云 4C8G Docker 全栈 5 分钟阶梯压测采集（每 5 秒采样一次）
  bash collect-metrics.sh --mode docker --out-dir ./run-ecs/metrics \
    --interval 5 --duration 360 --nic eth0
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --admin-sock) ADMIN_SOCK="$2"; shift 2 ;;
    --gw-container) GW_CONTAINER="$2"; shift 2 ;;
    --api-container) API_CONTAINER="$2"; shift 2 ;;
    --pg-container) PG_CONTAINER="$2"; shift 2 ;;
    --valkey-container) VALKEY_CONTAINER="$2"; shift 2 ;;
    --event-log) EVENT_LOG="$2"; shift 2 ;;
    --data-mount) DATA_MOUNT="$2"; shift 2 ;;
    --nic) NIC="$2"; shift 2 ;;
    --save-jsonl) SAVE_JSONL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
done

mkdir -p "$OUT_DIR"
CSV_FILE="${OUT_DIR}/runtime-metrics.csv"
JSONL_FILE="${OUT_DIR}/runtime-snapshots.jsonl"

# 自动探测部署形态
if [[ "$MODE" == "auto" ]]; then
  if systemctl is-active --quiet jiuzhang-gateway 2>/dev/null; then
    MODE="baremetal"
  elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qiE 'gateway'; then
    MODE="docker"
  else
    MODE="baremetal"
  fi
fi

# 自动探测容器名
if command -v docker >/dev/null 2>&1; then
  if [[ -z "$GW_CONTAINER" && "$MODE" == "docker" ]]; then
    GW_CONTAINER="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -iE 'gateway' | head -n 1 || true)"
  fi
  if [[ -z "$API_CONTAINER" ]]; then
    API_CONTAINER="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -iE '(^|[-_])(api|server)($|[-_])' | head -n 1 || true)"
  fi
  if [[ -z "$PG_CONTAINER" ]]; then
    PG_CONTAINER="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -iE 'postgres|pg' | head -n 1 || true)"
  fi
  if [[ -z "$VALKEY_CONTAINER" ]]; then
    VALKEY_CONTAINER="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -iE 'valkey|redis' | head -n 1 || true)"
  fi
fi

# 自动探测 admin.sock 与事件日志
if [[ -z "$ADMIN_SOCK" ]]; then
  if [[ "$MODE" == "docker" ]]; then
    ADMIN_SOCK="/var/run/caddy/admin.sock"
  else
    for cand in \
      /opt/jiuzhang-wdsp/data/run/caddy/admin.sock \
      /data/wdsp/data/run/caddy/admin.sock \
      /opt/jiuzhang/data/run/caddy/admin.sock \
      /var/run/caddy/admin.sock \
      /opt/jiuzhang-gateway/run/admin.sock; do
      if [[ -S "$cand" ]]; then
        ADMIN_SOCK="$cand"
        break
      fi
    done
    ADMIN_SOCK="${ADMIN_SOCK:-/opt/jiuzhang-wdsp/data/run/caddy/admin.sock}"
  fi
fi

if [[ -z "$EVENT_LOG" && "$MODE" == "baremetal" ]]; then
  for cand in \
    /opt/jiuzhang-wdsp/data/logs/caddy/api-runtime-events.log \
    /data/wdsp/data/logs/caddy/api-runtime-events.log \
    /var/log/caddy/api-runtime-events.log \
    /opt/jiuzhang/data/logs/caddy/api-runtime-events.log; do
    if [[ -f "$cand" ]]; then
      EVENT_LOG="$cand"
      break
    fi
  done
fi

echo "[collect] mode=${MODE} interval=${INTERVAL}s duration=${DURATION}s out=${CSV_FILE}"
echo "[collect] admin_sock=${ADMIN_SOCK} gw_container=${GW_CONTAINER:-none} api=${API_CONTAINER:-none} pg=${PG_CONTAINER:-none} valkey=${VALKEY_CONTAINER:-none} nic=${NIC:-auto} event_log=${EVENT_LOG:-auto}"

exec python3 -u - \
  "$CSV_FILE" "$JSONL_FILE" "$INTERVAL" "$DURATION" "$MODE" "$ADMIN_SOCK" \
  "$GW_CONTAINER" "$API_CONTAINER" "$PG_CONTAINER" "$VALKEY_CONTAINER" \
  "$EVENT_LOG" "$DATA_MOUNT" "$NIC" "$SAVE_JSONL" <<'PYEOF'
import csv
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

(
    csv_path,
    jsonl_path,
    interval_s,
    duration_s,
    mode,
    admin_sock,
    gw_ctr,
    api_ctr,
    pg_ctr,
    valkey_ctr,
    event_log,
    data_mount,
    nic_csv,
    save_jsonl_flag,
) = sys.argv[1:15]

interval = max(1, int(interval_s))
duration = int(duration_s)
save_jsonl = save_jsonl_flag == "1"
nics = [x.strip() for x in nic_csv.split(",") if x.strip()]

stop_requested = False

def handle_signal(_signum, _frame):
    global stop_requested
    stop_requested = True

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

def fetch_runtime_json():
    try:
        if mode == "docker" and gw_ctr:
            cmd = [
                "docker", "exec", gw_ctr,
                "curl", "-fsS", "--max-time", "3",
                "--unix-socket", admin_sock,
                "http://localhost/jiuzhang/runtime",
            ]
        else:
            cmd = [
                "curl", "-fsS", "--max-time", "3",
                "--unix-socket", admin_sock,
                "http://localhost/jiuzhang/runtime",
            ]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        return json.loads(out)
    except Exception:
        return None

def read_proc_cpu_stat():
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            parts = f.readline().split()
        if parts and parts[0] == "cpu":
            vals = [int(x) for x in parts[1:]]
            total = sum(vals)
            iowait = vals[4] if len(vals) > 4 else 0
            return total, iowait
    except Exception:
        pass
    return 0, 0

def read_nic_stats(ifaces):
    rx_b = tx_b = rx_d = tx_d = 0
    for nic in ifaces:
        base = f"/sys/class/net/{nic}/statistics"
        if not os.path.isdir(base):
            continue
        def ri(name):
            try:
                with open(f"{base}/{name}", "r", encoding="utf-8") as f:
                    return int(f.read().strip())
            except Exception:
                return 0
        rx_b += ri("rx_bytes")
        tx_b += ri("tx_bytes")
        rx_d += ri("rx_dropped") + ri("rx_missed_errors") + ri("rx_fifo_errors")
        tx_d += ri("tx_dropped") + ri("tx_fifo_errors")
    return rx_b, tx_b, rx_d, tx_d

def disk_used_pct(path):
    if not path or not os.path.exists(path):
        return ""
    try:
        st = os.statvfs(path)
        if st.f_blocks == 0:
            return ""
        used = (st.f_blocks - st.f_bavail) / st.f_blocks * 100.0
        return f"{used:.2f}"
    except Exception:
        return ""

def parse_mem_mib(raw):
    m = re.match(r"^\s*([0-9.]+)\s*([KMGTP]i?B|B)", raw or "", re.IGNORECASE)
    if not m:
        return ""
    val = float(m.group(1))
    unit = m.group(2).lower()
    factors = {
        "b": 1 / (1024 * 1024),
        "kb": 1000 / (1024 * 1024),
        "kib": 1 / 1024,
        "mb": 1000 * 1000 / (1024 * 1024),
        "mib": 1.0,
        "gb": 1000**3 / (1024 * 1024),
        "gib": 1024.0,
        "tb": 1000**4 / (1024 * 1024),
        "tib": 1024.0 * 1024.0,
    }
    return f"{val * factors.get(unit, 1.0):.2f}"

def docker_rss_map(names):
    targets = [n for n in names if n]
    if not targets:
        return {}
    try:
        out = subprocess.check_output(
            ["docker", "stats", "--no-stream", "--format", "{{.Name}}|{{.MemUsage}}"] + targets,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=4,
        )
        res = {}
        for line in out.splitlines():
            if "|" not in line:
                continue
            name, mem = line.split("|", 1)
            used_part = mem.split("/")[0].strip()
            res[name.strip()] = parse_mem_mib(used_part)
        return res
    except Exception:
        return {}

def event_log_stats():
    log_bytes = ""
    ckpt_offset = ""
    lag_bytes = ""
    try:
        if event_log and os.path.isfile(event_log):
            sz = os.path.getsize(event_log)
            log_bytes = str(sz)
            ckpt_path = event_log + ".checkpoint"
            if os.path.isfile(ckpt_path):
                with open(ckpt_path, "r", encoding="utf-8", errors="ignore") as f:
                    raw = f.read().strip()
                off = None
                try:
                    obj = json.loads(raw)
                    for k in ("offset", "Offset", "byte_offset"):
                        if k in obj:
                            off = int(obj[k])
                            break
                except Exception:
                    if raw.isdigit():
                        off = int(raw)
                if off is not None:
                    ckpt_offset = str(off)
                    lag_bytes = str(max(0, sz - off))
        elif mode == "docker" and api_ctr:
            # 尝试在 api 容器内快速 stat
            cmd = [
                "docker", "exec", api_ctr, "sh", "-c",
                'p="${WAF_API_EVENTS_LOG:-/var/log/caddy-audit/api-runtime-events.log}"; '
                'if [ -f "$p" ]; then stat -c %s "$p" 2>/dev/null || wc -c < "$p"; else echo ""; fi; '
                'if [ -f "${p}.checkpoint" ]; then cat "${p}.checkpoint"; fi',
            ]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=3).splitlines()
            if out and out[0].strip().isdigit():
                sz = int(out[0].strip())
                log_bytes = str(sz)
                if len(out) > 1:
                    raw = "\n".join(out[1:]).strip()
                    off = None
                    try:
                        obj = json.loads(raw)
                        for k in ("offset", "Offset", "byte_offset"):
                            if k in obj:
                                off = int(obj[k])
                                break
                    except Exception:
                        if raw.isdigit():
                            off = int(raw)
                    if off is not None:
                        ckpt_offset = str(off)
                        lag_bytes = str(max(0, sz - off))
    except Exception:
        pass
    return log_bytes, ckpt_offset, lag_bytes

FIELDNAMES = [
    "ts_utc",
    "unix_s",
    "gw_cpu_pct",
    "gw_mem_pct",
    "gw_mem_used_mib",
    "gw_fd_open",
    "gw_conn_active",
    "gw_conn_cps",
    "gw_rps",
    "gw_inflight",
    "gw_s2xx_rps",
    "gw_s4xx_rps",
    "gw_s5xx_rps",
    "gw_bytes_in_bps",
    "gw_bytes_out_bps",
    "bypass_active",
    "bypass_transitions",
    "bypassed_total",
    "host_load1",
    "host_iowait_pct",
    "disk_root_used_pct",
    "disk_data_used_pct",
    "nic_rx_mbps",
    "nic_tx_mbps",
    "nic_rx_drop_delta",
    "nic_tx_drop_delta",
    "event_log_bytes",
    "checkpoint_offset",
    "event_lag_bytes",
    "pg_rss_mib",
    "api_rss_mib",
    "valkey_rss_mib",
]

start_t = time.monotonic()
prev_cpu = read_proc_cpu_stat()
prev_nic = read_nic_stats(nics)
prev_t = start_t

with open(csv_path, "w", newline="", encoding="utf-8") as cf:
    writer = csv.DictWriter(cf, fieldnames=FIELDNAMES)
    writer.writeheader()
    cf.flush()

    jf = open(jsonl_path, "a", encoding="utf-8") if save_jsonl else None
    try:
        while not stop_requested:
            now_mono = time.monotonic()
            if duration > 0 and (now_mono - start_t) >= duration:
                break

            ts_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            unix_s = int(time.time())

            rt = fetch_runtime_json() or {}
            if jf is not None and rt:
                jf.write(json.dumps(rt, ensure_ascii=False) + "\n")
                jf.flush()

            res = rt.get("resources") or {}
            con = rt.get("connections") or {}
            http_s = rt.get("http") or {}
            byp = rt.get("software_bypass") or {}

            mem_used_b = res.get("memory_used_bytes")
            mem_used_mib = f"{mem_used_b / (1024 * 1024):.2f}" if isinstance(mem_used_b, (int, float)) else ""

            # Host CPU iowait & load1
            cur_cpu = read_proc_cpu_stat()
            d_total = cur_cpu[0] - prev_cpu[0]
            d_iowait = cur_cpu[1] - prev_cpu[1]
            iowait_pct = f"{(d_iowait / d_total * 100.0):.2f}" if d_total > 0 else ""
            prev_cpu = cur_cpu

            load1 = ""
            try:
                load1 = f"{os.getloadavg()[0]:.2f}"
            except Exception:
                pass

            # NIC throughput & drops
            cur_nic = read_nic_stats(nics)
            dt = max(0.001, now_mono - prev_t)
            if nics and prev_t != now_mono:
                rx_mbps = f"{max(0, cur_nic[0] - prev_nic[0]) * 8.0 / dt / 1e6:.2f}"
                tx_mbps = f"{max(0, cur_nic[1] - prev_nic[1]) * 8.0 / dt / 1e6:.2f}"
                rx_dd = str(max(0, cur_nic[2] - prev_nic[2]))
                tx_dd = str(max(0, cur_nic[3] - prev_nic[3]))
            else:
                rx_mbps = tx_mbps = rx_dd = tx_dd = ""
            prev_nic = cur_nic
            prev_t = now_mono

            rss_map = docker_rss_map([api_ctr, pg_ctr, valkey_ctr])
            log_b, ckpt_off, lag_b = event_log_stats()

            def fmt_num(v):
                if v is None:
                    return ""
                if isinstance(v, float):
                    return f"{v:.2f}"
                return str(v)

            row = {
                "ts_utc": ts_utc,
                "unix_s": str(unix_s),
                "gw_cpu_pct": fmt_num(res.get("cpu_percent")),
                "gw_mem_pct": fmt_num(res.get("memory_percent")),
                "gw_mem_used_mib": mem_used_mib,
                "gw_fd_open": fmt_num(res.get("fd_open")),
                "gw_conn_active": fmt_num(con.get("active")),
                "gw_conn_cps": fmt_num(con.get("accepted_per_second")),
                "gw_rps": fmt_num(http_s.get("requests_per_second")),
                "gw_inflight": fmt_num(http_s.get("requests_in_flight")),
                "gw_s2xx_rps": fmt_num(http_s.get("status_2xx_per_second")),
                "gw_s4xx_rps": fmt_num(http_s.get("status_4xx_per_second")),
                "gw_s5xx_rps": fmt_num(http_s.get("status_5xx_per_second")),
                "gw_bytes_in_bps": fmt_num(con.get("bytes_in_per_second")),
                "gw_bytes_out_bps": fmt_num(con.get("bytes_out_per_second")),
                "bypass_active": "1" if byp.get("active") else ("0" if byp else ""),
                "bypass_transitions": fmt_num(byp.get("transitions_total")),
                "bypassed_total": fmt_num(byp.get("bypassed_requests_total")),
                "host_load1": load1,
                "host_iowait_pct": iowait_pct,
                "disk_root_used_pct": disk_used_pct("/"),
                "disk_data_used_pct": disk_used_pct(data_mount),
                "nic_rx_mbps": rx_mbps,
                "nic_tx_mbps": tx_mbps,
                "nic_rx_drop_delta": rx_dd,
                "nic_tx_drop_delta": tx_dd,
                "event_log_bytes": log_b,
                "checkpoint_offset": ckpt_off,
                "event_lag_bytes": lag_b,
                "pg_rss_mib": rss_map.get(pg_ctr, ""),
                "api_rss_mib": rss_map.get(api_ctr, ""),
                "valkey_rss_mib": rss_map.get(valkey_ctr, ""),
            }
            writer.writerow(row)
            cf.flush()

            # Sleep until next tick (interruptible)
            target_sleep = interval - (time.monotonic() - now_mono)
            end_sleep = time.monotonic() + max(0.0, target_sleep)
            while not stop_requested and time.monotonic() < end_sleep:
                time.sleep(min(0.5, max(0.0, end_sleep - time.monotonic())))
    finally:
        if jf is not None:
            jf.close()

print(f"[collect] 采集结束，CSV 已保存: {csv_path}")
PYEOF
