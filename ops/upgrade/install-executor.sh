#!/usr/bin/env bash
# 一次性安装宿主机升级执行器；可用 --patch 引导 1.0.0 升级到 1.0.1。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE=""
ENV_FILE=""
PATCH_FILE=""
API_URL="http://127.0.0.1:18081"
TIMEOUT=600

usage() {
  cat <<'EOF'
用法:
  sudo ./install-executor.sh -c /绝对路径/docker-compose.yml -e /绝对路径/.env [选项]

选项:
  -c, --compose-file FILE  当前生产环境使用的 compose 文件（必填）
  -e, --env-file FILE      当前生产环境使用的 env 文件（必填）
      --patch FILE         安装后立即应用 1.0.0 → 1.0.1 小补丁（首次引导推荐）
      --api-url URL        健康检查地址（默认 http://127.0.0.1:18081）
      --timeout SEC        健康检查/补丁等待超时（默认 600 秒）
  -h, --help               显示帮助
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--compose-file) COMPOSE_FILE="${2:-}"; shift 2 ;;
    -e|--env-file) ENV_FILE="${2:-}"; shift 2 ;;
    --patch) PATCH_FILE="${2:-}"; shift 2 ;;
    --api-url) API_URL="${2:-}"; shift 2 ;;
    --timeout) TIMEOUT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf '未知参数: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { printf '%s\n' '请使用 sudo 运行此脚本' >&2; exit 1; }
[[ -n "$COMPOSE_FILE" && -n "$ENV_FILE" ]] || { usage >&2; exit 2; }
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || { printf '%s\n' '--timeout 必须是整数' >&2; exit 2; }
# diff/cmp 属 diffutils：被安装的 upgrade-executor.sh 运行期必需，安装期一并核查。
for cmd in docker systemctl jq python3 curl flock install sha256sum realpath timeout diff cmp; do
  command -v "$cmd" >/dev/null 2>&1 && continue
  case "$cmd" in
    diff|cmp) printf '缺少命令: %s（diffutils 包；升级执行器文件比对必需）\n' "$cmd" >&2 ;;
    *) printf '缺少命令: %s\n' "$cmd" >&2 ;;
  esac
  exit 1
done
[[ -f "$COMPOSE_FILE" && -f "$ENV_FILE" ]] || { printf '%s\n' 'compose 或 env 文件不存在' >&2; exit 1; }
[[ -x "$SCRIPT_DIR/upgrade-executor.sh" ]] || { printf '%s\n' 'upgrade-executor.sh 不存在或不可执行' >&2; exit 1; }
COMPOSE_FILE="$(realpath "$COMPOSE_FILE")"
ENV_FILE="$(realpath "$ENV_FILE")"
[[ -z "$PATCH_FILE" || -f "$PATCH_FILE" ]] || { printf '补丁不存在: %s\n' "$PATCH_FILE" >&2; exit 1; }
[[ -z "$PATCH_FILE" ]] || PATCH_FILE="$(realpath "$PATCH_FILE")"

compose() { docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }
api_container="$(compose ps -q api)"
[[ -n "$api_container" ]] || { printf '%s\n' '找不到正在运行的 api 容器' >&2; exit 1; }
runtime_dir="$(docker inspect "$api_container" --format '{{range .Mounts}}{{if eq .Destination "/app/runtime"}}{{.Source}}{{end}}{{end}}')"
[[ -n "$runtime_dir" && -d "$runtime_dir" ]] || { printf '%s\n' 'api 容器未挂载 /app/runtime，无法建立安全共享通道' >&2; exit 1; }

install -d -m 0755 /usr/local/libexec /etc/jiuzhang
install -m 0755 "$SCRIPT_DIR/upgrade-executor.sh" /usr/local/libexec/jiuzhang-upgrade-executor
install -d -m 0770 -o 1000 -g root "$runtime_dir/upgrade-packages" "$runtime_dir/upgrade-executor/jobs"
install -d -m 0750 -o root -g 1000 "$runtime_dir/upgrade-executor/results"
install -d -m 0700 -o root -g root "$runtime_dir/upgrade-executor/work" "$runtime_dir/upgrade-executor/state"

config_tmp="$(mktemp)"; path_tmp="$(mktemp)"; service_tmp="$(mktemp)"
trap 'rm -f "$config_tmp" "$path_tmp" "$service_tmp"' EXIT
printf 'RUNTIME_DIR=%q\nCOMPOSE_FILE=%q\nENV_FILE=%q\nAPI_URL=%q\nTIMEOUT=%q\n' \
  "$runtime_dir" "$COMPOSE_FILE" "$ENV_FILE" "$API_URL" "$TIMEOUT" >"$config_tmp"
install -m 0600 -o root -g root "$config_tmp" /etc/jiuzhang/upgrade-executor.conf
cat >"$path_tmp" <<EOF
[Unit]
Description=JiuZhang WDSP Upgrade Job Watcher
[Path]
PathExistsGlob=$runtime_dir/upgrade-executor/jobs/*.json
Unit=jiuzhang-upgrade-executor.service
[Install]
WantedBy=multi-user.target
EOF
cat >"$service_tmp" <<'EOF'
[Unit]
Description=JiuZhang WDSP Host Upgrade Executor
After=docker.service
Wants=docker.service
[Service]
Type=oneshot
ExecStart=/usr/local/libexec/jiuzhang-upgrade-executor --config /etc/jiuzhang/upgrade-executor.conf
EOF
install -m 0644 "$path_tmp" /etc/systemd/system/jiuzhang-upgrade-executor.path
install -m 0644 "$service_tmp" /etc/systemd/system/jiuzhang-upgrade-executor.service
systemctl daemon-reload
systemctl enable --now jiuzhang-upgrade-executor.path
systemctl start jiuzhang-upgrade-executor.service
printf '宿主机升级执行器安装完成，共享目录: %s\n' "$runtime_dir/upgrade-executor"

if [[ -n "$PATCH_FILE" ]]; then
  package_name="$(basename "$PATCH_FILE")"
  package_target="$runtime_dir/upgrade-packages/$package_name"
  install -m 0640 -o 1000 -g root "$PATCH_FILE" "$package_target"
  package_sha="$(sha256sum "$package_target" | awk '{print $1}')"
  readarray -t versions < <(python3 - "$PATCH_FILE" <<'PY'
import json, sys, tarfile
with tarfile.open(sys.argv[1], "r:gz") as tf:
    names = [n for n in tf.getnames() if n.endswith("/manifest.json") and ".." not in n.split("/")]
    if len(names) != 1:
        raise SystemExit("补丁 manifest 数量异常")
    f = tf.extractfile(names[0])
    manifest = json.load(f)
    print(manifest.get("version_from", ""))
    print(manifest.get("version_to", ""))
PY
  )
  [[ "${versions[0]:-}" == "1.0.0" && "${versions[1]:-}" == "1.0.1" ]] || {
    printf '%s\n' '--patch 仅用于首次引导 1.0.0 → 1.0.1' >&2; exit 1;
  }
  job_id="$(cat /proc/sys/kernel/random/uuid)"
  job_tmp="$(mktemp "$runtime_dir/upgrade-executor/jobs/.job.XXXXXX")"
  jq -n --arg id "$job_id" --arg file "$package_name" --arg sha "$package_sha" \
    '{job_id:$id,package_file:$file,package_sha256:$sha,version_from:"1.0.0",version_to:"1.0.1",requested_at:(now|todate)}' >"$job_tmp"
  chmod 0640 "$job_tmp"; chown 1000:root "$job_tmp"
  mv "$job_tmp" "$runtime_dir/upgrade-executor/jobs/$job_id.json"
  systemctl start jiuzhang-upgrade-executor.service
  elapsed=0; result="$runtime_dir/upgrade-executor/results/$job_id.json"
  while [[ ! -f "$result" && $elapsed -lt $TIMEOUT ]]; do sleep 2; elapsed=$((elapsed + 2)); done
  [[ -f "$result" ]] || { printf '%s\n' '等待首次补丁执行超时，请查看 journalctl -u jiuzhang-upgrade-executor' >&2; exit 1; }
  jq . "$result"
  [[ "$(jq -r '.status' "$result")" == SUCCESS ]] || exit 1
  printf '%s\n' '首次补丁已生效；以后可直接在 Web 升级页面上传并执行小补丁。'
fi
