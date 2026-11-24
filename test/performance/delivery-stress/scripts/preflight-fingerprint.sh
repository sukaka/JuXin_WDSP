#!/usr/bin/env bash
# 被测机（SUT）前置硬件/系统/网络/磁盘/WDSP 版本指纹采集脚本
# 适用于 KY5288G1（openEuler 24.03 SP3，2xKH-40000 + 240G SATA + 2T 数据盘 + 4x10G）与阿里云 ECS（4C8G）。
# 默认只读采集；仅在显式指定 --fio-dir 时执行 10 秒安全临时盘测速并立即清理临时文件。
set -euo pipefail

OUT_DIR="${OUT_DIR:-./bench-fingerprint-$(date +%Y%m%dT%H%M%S)}"
IFACES=""
FIO_DIRS=()
DEPLOY_MODE="auto" # auto | docker | baremetal

usage() {
  cat <<'EOF'
用法: preflight-fingerprint.sh [选项]

选项:
  --out-dir DIR         输出目录（默认: ./bench-fingerprint-<timestamp>）
  --ifaces LIST         逗号分隔的重点网卡名（如 ens1f0,ens1f1；不填则自动发现所有非 lo/docker 物理口）
  --fio-dir DIR         可选，可重复指定：在指定目录下做 10s 4K随机写/顺序写测速（测后自动删除临时文件）
  --mode MODE           WDSP 部署形态: auto | docker | baremetal（默认: auto）
  -h, --help            显示帮助

示例:
  # KY5288G1 双万兆口 + 双盘判型采集
  sudo bash preflight-fingerprint.sh --out-dir /data/stress/fp-ky5288 \
    --ifaces ens1f0,ens1f1 --fio-dir /tmp --fio-dir /data

  # 阿里云 4C8G ECS 采集
  sudo bash preflight-fingerprint.sh --out-dir ./fp-ecs --ifaces eth0 --fio-dir /tmp
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --ifaces) IFACES="$2"; shift 2 ;;
    --fio-dir) FIO_DIRS+=("$2"); shift 2 ;;
    --mode) DEPLOY_MODE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
done

mkdir -p "$OUT_DIR"
TXT_OUT="${OUT_DIR}/fingerprint.txt"
JSON_OUT="${OUT_DIR}/fingerprint.json"

log_section() {
  printf '\n==================== %s ====================\n' "$1" >> "$TXT_OUT"
}

: > "$TXT_OUT"
echo "WDSP Stress Test SUT Preflight Fingerprint" >> "$TXT_OUT"
echo "Collected At (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$TXT_OUT"
echo "Hostname: $(hostname)" >> "$TXT_OUT"

log_section "OS & KERNEL"
uname -a >> "$TXT_OUT"
if [[ -r /etc/os-release ]]; then
  cat /etc/os-release >> "$TXT_OUT"
fi

log_section "CPU & NUMA"
if command -v lscpu >/dev/null 2>&1; then
  lscpu >> "$TXT_OUT"
fi
if command -v numactl >/dev/null 2>&1; then
  echo "--- numactl --hardware ---" >> "$TXT_OUT"
  numactl --hardware >> "$TXT_OUT" 2>&1 || true
fi
HAS_AVX2="no"
HAS_AES="no"
if [[ -r /proc/cpuinfo ]]; then
  grep -qm1 -w avx2 /proc/cpuinfo && HAS_AVX2="yes" || true
  grep -qm1 -w aes /proc/cpuinfo && HAS_AES="yes" || true
fi
echo "CPU Flags Check: avx2=${HAS_AVX2} aes=${HAS_AES}" >> "$TXT_OUT"

log_section "MEMORY"
free -h >> "$TXT_OUT" 2>&1 || true
if command -v dmidecode >/dev/null 2>&1 && [[ "$(id -u)" -eq 0 ]]; then
  echo "--- DIMM Summary ---" >> "$TXT_OUT"
  dmidecode -t memory 2>/dev/null | grep -E "^\s*(Size|Speed|Configured Memory Speed|Type|Locator):" | grep -v "No Module Installed" >> "$TXT_OUT" || true
fi

log_section "DISKS & FILESYSTEMS"
lsblk -d -o NAME,MODEL,SIZE,ROTA,TRAN,TYPE 2>/dev/null >> "$TXT_OUT" || true
echo "--- df -hT ---" >> "$TXT_OUT"
df -hT >> "$TXT_OUT" 2>&1 || true

log_section "NETWORK INTERFACES"
ip -br addr >> "$TXT_OUT" 2>&1 || true

if [[ -z "$IFACES" ]]; then
  IFACES="$(ls /sys/class/net 2>/dev/null | grep -Ev '^(lo|docker|br-|veth|virbr|cali|flannel|cni)' | paste -sd, - || true)"
fi

IFS=',' read -r -a IFACE_ARR <<< "$IFACES"
for nic in "${IFACE_ARR[@]}"; do
  [[ -n "$nic" && -d "/sys/class/net/${nic}" ]] || continue
  echo "--- NIC: ${nic} ---" >> "$TXT_OUT"
  echo "speed=$(cat "/sys/class/net/${nic}/speed" 2>/dev/null || echo unknown)Mb/s numa_node=$(cat "/sys/class/net/${nic}/device/numa_node" 2>/dev/null || echo unknown) operstate=$(cat "/sys/class/net/${nic}/operstate" 2>/dev/null || echo unknown)" >> "$TXT_OUT"
  if command -v ethtool >/dev/null 2>&1; then
    ethtool -i "$nic" >> "$TXT_OUT" 2>&1 || true
    ethtool -l "$nic" >> "$TXT_OUT" 2>&1 || true
    ethtool -g "$nic" >> "$TXT_OUT" 2>&1 || true
    ethtool -k "$nic" 2>/dev/null | grep -E "large-receive-offload|tcp-segmentation-offload|generic-receive-offload|generic-segmentation-offload" >> "$TXT_OUT" || true
  fi
done

log_section "SYSCTL KEY PARAMETERS"
for key in \
  net.core.somaxconn \
  net.core.netdev_max_backlog \
  net.core.rmem_max \
  net.core.wmem_max \
  net.ipv4.tcp_rmem \
  net.ipv4.tcp_wmem \
  net.ipv4.tcp_max_syn_backlog \
  net.ipv4.tcp_tw_reuse \
  net.ipv4.ip_local_port_range \
  net.ipv4.tcp_congestion_control \
  net.netfilter.nf_conntrack_max \
  fs.file-max \
  fs.nr_open; do
  val="$(sysctl -n "$key" 2>/dev/null || echo "N/A")"
  printf "%-36s = %s\n" "$key" "$val" >> "$TXT_OUT"
done
echo "CPU governor (cpu0): $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo N/A)" >> "$TXT_OUT"

log_section "WDSP DEPLOYMENT SNAPSHOT (NO SECRETS)"
DETECTED_MODE="$DEPLOY_MODE"
if [[ "$DETECTED_MODE" == "auto" ]]; then
  if systemctl is-active --quiet jiuzhang-gateway 2>/dev/null; then
    DETECTED_MODE="baremetal"
  elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qiE 'jiuzhang|wdsp|gateway'; then
    DETECTED_MODE="docker"
  else
    DETECTED_MODE="unknown"
  fi
fi
echo "Detected WDSP Mode: ${DETECTED_MODE}" >> "$TXT_OUT"

if command -v systemctl >/dev/null 2>&1; then
  systemctl status jiuzhang-gateway --no-pager -n 0 >> "$TXT_OUT" 2>&1 || true
fi
if command -v docker >/dev/null 2>&1; then
  echo "--- Running Containers (Safe Fields Only) ---" >> "$TXT_OUT"
  docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null >> "$TXT_OUT" || true
  echo "--- Image Digests ---" >> "$TXT_OUT"
  docker images --digests --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.Digest}}' 2>/dev/null | grep -iE 'jiuzhang|wdsp|postgres|valkey' >> "$TXT_OUT" || true
fi

if [[ ${#FIO_DIRS[@]} -gt 0 ]]; then
  log_section "OPTIONAL FIO STORAGE BENCHMARK (10s SAFE TEMP FILE)"
  if command -v fio >/dev/null 2>&1; then
    for fdir in "${FIO_DIRS[@]}"; do
      if [[ ! -d "$fdir" ]]; then
        echo "跳过不存在目录: $fdir" >> "$TXT_OUT"
        continue
      fi
      tmpfile="${fdir}/.wdsp-fio-probe-$$.tmp"
      echo "--- fio @ ${fdir} ---" >> "$TXT_OUT"
      fio --name=randwrite4k --filename="$tmpfile" --size=256M --rw=randwrite --bs=4k --direct=1 --ioengine=sync --numjobs=2 --time_based --runtime=5 --group_reporting >> "$TXT_OUT" 2>&1 || true
      fio --name=seqwrite1m --filename="$tmpfile" --size=256M --rw=write --bs=1M --direct=1 --ioengine=sync --numjobs=1 --time_based --runtime=5 --group_reporting >> "$TXT_OUT" 2>&1 || true
      rm -f "$tmpfile"
    done
  else
    echo "fio 未安装，跳过磁盘 IOPS 测速（建议安装 fio 核实 2TB 数据盘是 SSD 还是 HDD）。" >> "$TXT_OUT"
  fi
fi

# 生成结构化 JSON 供 summarize-run.py 消费
python3 - "$TXT_OUT" "$JSON_OUT" "$DETECTED_MODE" "$HAS_AVX2" "$HAS_AES" "$IFACES" <<'PYEOF'
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone

txt_path, json_path, mode, has_avx2, has_aes, ifaces_csv = sys.argv[1:7]

def cmd_out(args):
    try:
        return subprocess.check_output(args, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return ""

os_pretty = ""
if os.path.exists("/etc/os-release"):
    with open("/etc/os-release", "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.startswith("PRETTY_NAME="):
                os_pretty = line.split("=", 1)[1].strip().strip('"')
                break

cpu_model = ""
cpu_cores = os.cpu_count() or 0
if os.path.exists("/proc/cpuinfo"):
    with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.lower().startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break

mem_total_kb = 0
if os.path.exists("/proc/meminfo"):
    with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.startswith("MemTotal:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    mem_total_kb = int(parts[1])
                break

disks = []
lsblk_raw = cmd_out(["lsblk", "-J", "-d", "-o", "NAME,MODEL,SIZE,ROTA,TRAN,TYPE"])
if lsblk_raw:
    try:
        parsed = json.loads(lsblk_raw)
        for d in parsed.get("blockdevices", []):
            rota = str(d.get("rota", "")).lower() in ("1", "true")
            disks.append({
                "name": d.get("name"),
                "model": (d.get("model") or "").strip(),
                "size": d.get("size"),
                "media": "HDD" if rota else "SSD_OR_NVME",
                "transport": d.get("tran"),
            })
    except Exception:
        pass

nics = []
for nic in [x.strip() for x in ifaces_csv.split(",") if x.strip()]:
    base = f"/sys/class/net/{nic}"
    if not os.path.isdir(base):
        continue
    def read_s(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            return ""
    nics.append({
        "name": nic,
        "speed_mbps": read_s(f"{base}/speed"),
        "operstate": read_s(f"{base}/operstate"),
        "numa_node": read_s(f"{base}/device/numa_node"),
    })

recommendations = []
if has_avx2 == "no" and platform.machine() == "x86_64":
    recommendations.append("CPU 无 AVX2（如兆芯 KH-40000）：建议必测 HTTP vs HTTPS 与 CRS PL1 对照，优先采用裸机 systemd 网关节省网络栈 CPU。")
if mode == "docker" and any(n.get("speed_mbps") == "10000" for n in nics):
    recommendations.append("检测到万兆网卡但当前为 Docker 形态：正式冲刺万兆极限建议切换为裸机 systemd 网关并应用 tune-gateway-baremetal.sh。")
if any(d.get("media") == "HDD" for d in disks) and any(d.get("media") == "SSD_OR_NVME" for d in disks):
    recommendations.append("检测到混合磁盘（SSD + HDD）：建议冷热分层——PostgreSQL 数据目录放 SSD，大日志文件放 2TB 盘。")

doc = {
    "collected_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "hostname": platform.node(),
    "os": os_pretty or platform.platform(),
    "kernel": platform.release(),
    "arch": platform.machine(),
    "cpu": {
        "model": cpu_model,
        "logical_cores": cpu_cores,
        "avx2": has_avx2 == "yes",
        "aes": has_aes == "yes",
    },
    "memory_gib": round(mem_total_kb / (1024 * 1024), 2) if mem_total_kb else 0.0,
    "disks": disks,
    "nics": nics,
    "wdsp_deploy_mode": mode,
    "recommendations": recommendations,
    "raw_text_file": os.path.basename(txt_path),
}
with open(json_path, "w", encoding="utf-8") as f:
    json.dump(doc, f, ensure_ascii=False, indent=2)
PYEOF

echo "[preflight] 指纹采集完成："
echo "  文本报告: $TXT_OUT"
echo "  结构化JSON: $JSON_OUT"
