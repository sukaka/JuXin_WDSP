#!/usr/bin/env bash
# 宿主机升级执行器：只处理 API 写入共享目录的签名范围内运行时小补丁任务。
set -euo pipefail

CONFIG_FILE="/etc/jiuzhang/upgrade-executor.conf"

usage() {
  printf '%s\n' '用法: upgrade-executor.sh [--config FILE]' \
    '由 systemd 调用；配置文件必须由 root 拥有且不可被其他用户写入。'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG_FILE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf '未知参数: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { printf '%s\n' '必须以 root 运行' >&2; exit 1; }
[[ -f "$CONFIG_FILE" ]] || { printf '配置文件不存在: %s\n' "$CONFIG_FILE" >&2; exit 1; }
owner="$(stat -c '%u' "$CONFIG_FILE")"
mode="$(stat -c '%a' "$CONFIG_FILE")"
[[ "$owner" == 0 ]] && (( (0$mode & 022) == 0 )) || {
  printf '%s\n' '配置文件必须由 root 拥有且组/其他用户不可写' >&2; exit 1;
}
# 配置由本项目安装脚本生成，权限已在上方验证。
# shellcheck disable=SC1090
source "$CONFIG_FILE"

: "${RUNTIME_DIR:?缺少 RUNTIME_DIR}"
: "${COMPOSE_FILE:?缺少 COMPOSE_FILE}"
: "${ENV_FILE:?缺少 ENV_FILE}"
: "${API_URL:=http://127.0.0.1:18081}"
: "${TIMEOUT:=600}"

for cmd in docker jq python3 curl flock sha256sum; do
  command -v "$cmd" >/dev/null 2>&1 || { printf '缺少命令: %s\n' "$cmd" >&2; exit 1; }
done
[[ -d "$RUNTIME_DIR" && -f "$COMPOSE_FILE" && -f "$ENV_FILE" ]] || {
  printf '%s\n' '运行目录、compose 文件或 env 文件不存在' >&2; exit 1;
}

JOBS_DIR="$RUNTIME_DIR/upgrade-executor/jobs"
RESULTS_DIR="$RUNTIME_DIR/upgrade-executor/results"
WORK_DIR="$RUNTIME_DIR/upgrade-executor/work"
STATE_DIR="$RUNTIME_DIR/upgrade-executor/state"
PACKAGES_DIR="$RUNTIME_DIR/upgrade-packages"
mkdir -p "$JOBS_DIR" "$RESULTS_DIR" "$WORK_DIR" "$STATE_DIR"

compose() { docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
write_result() {
  local job_id="$1" status="$2" stage="$3" code="$4" message="$5" tmp
  tmp="$(mktemp "$RESULTS_DIR/.result.XXXXXX")"
  jq -n --arg id "$job_id" --arg status "$status" --arg stage "$stage" \
    --arg code "$code" --arg message "$message" --arg finished "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    '{job_id:$id,status:$status,stage:$stage,error_code:$code,message:$message,finished_at:$finished}' >"$tmp"
  chmod 0640 "$tmp"
  chown root:1000 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$RESULTS_DIR/$job_id.json"
}
safe_extract() {
  local archive="$1" destination="$2"
  python3 - "$archive" "$destination" <<'PY'
import os, pathlib, sys, tarfile
archive, destination = sys.argv[1:]
root = pathlib.Path(destination).resolve()
MAX_EXPANDED_BYTES = 8 << 30
with tarfile.open(archive, "r:gz") as tf:
    members = tf.getmembers()
    if not members or len(members) > 20:
        raise SystemExit("升级包文件数量异常")
    expanded = 0
    for m in members:
        p = pathlib.PurePosixPath(m.name)
        if p.is_absolute() or ".." in p.parts or not (m.isdir() or m.isfile()):
            raise SystemExit("升级包包含不安全路径或文件类型")
        if m.size < 0 or expanded > MAX_EXPANDED_BYTES - m.size:
            raise SystemExit("升级包解压大小超出安全上限")
        expanded += m.size
        target = (root / p).resolve()
        if os.path.commonpath((root, target)) != str(root):
            raise SystemExit("升级包路径越界")
    tf.extractall(root, members=members)
PY
}
wait_api() {
  local elapsed=0
  while (( elapsed < TIMEOUT )); do
    if curl -fsS --max-time 5 "$API_URL/api/v1/health" >/dev/null 2>&1; then return 0; fi
    sleep 2; elapsed=$((elapsed + 2))
  done
  return 1
}

declare -a SERVICES=() STABLE_IMAGES=() OLD_IDS=()
CURRENT_JOB="" CURRENT_STAGE="APPLYING" CURRENT_MESSAGE=""

rollback_images() {
  local i
  for i in "${!SERVICES[@]}"; do
    [[ -n "${OLD_IDS[$i]:-}" ]] && docker tag "${OLD_IDS[$i]}" "${STABLE_IMAGES[$i]}" >/dev/null 2>&1 || true
  done
  ((${#SERVICES[@]} == 0)) || compose up -d --no-deps "${SERVICES[@]}" >/dev/null 2>&1 || true
  wait_api || true
}

process_job() {
  local job_file="$1" package_name expected_sha package version_from version_to job_id
  local work package_root manifest archive archive_sha host_arch service target stable old i
  CURRENT_STAGE="APPLYING"
  job_id="$(jq -er '.job_id | strings' "$job_file")" || return 1
  [[ "$job_id" =~ ^[0-9a-fA-F-]{36}$ ]] || return 1
  CURRENT_JOB="$job_id"
  package_name="$(jq -er '.package_file | strings' "$job_file")" || return 1
  [[ "$package_name" == "$(basename "$package_name")" && "$package_name" == *.tar.gz ]] || return 1
  expected_sha="$(jq -er '.package_sha256 | strings | ascii_downcase' "$job_file")" || return 1
  [[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] || return 1
  version_from="$(jq -er '.version_from | strings' "$job_file")" || return 1
  version_to="$(jq -er '.version_to | strings' "$job_file")" || return 1
  package="$PACKAGES_DIR/$package_name"
  [[ -f "$package" ]] || { CURRENT_MESSAGE="找不到升级包"; return 1; }
  [[ "$(sha256_file "$package")" == "$expected_sha" ]] || { CURRENT_MESSAGE="升级包 SHA-256 不匹配"; return 1; }

  work="$WORK_DIR/$job_id"
  rm -rf "$work"
  mkdir -p "$work"
  safe_extract "$package" "$work" || { CURRENT_MESSAGE="升级包安全解压失败"; return 1; }
  mapfile -t roots < <(find "$work" -mindepth 1 -maxdepth 1 -type d)
  [[ ${#roots[@]} -eq 1 ]] || { CURRENT_MESSAGE="升级包目录结构无效"; return 1; }
  package_root="${roots[0]}"
  manifest="$package_root/manifest.json"
  [[ -f "$manifest" && -f "$package_root/SHA256SUMS" ]] || { CURRENT_MESSAGE="升级包清单缺失"; return 1; }
  (cd "$package_root" && sha256sum -c SHA256SUMS >/dev/null) || { CURRENT_MESSAGE="包内校验和失败"; return 1; }
  jq -e --arg from "$version_from" --arg to "$version_to" '
    .format_version == 1 and .product == "wdsp" and .package_type == "runtime-patch" and
    .change_type == "bugfix" and .version_from == $from and .version_to == $to and
    (.components | length >= 1) and
    (all(.components[]; (.service == "api" or .service == "web") and (.image | type == "string")))
  ' "$manifest" >/dev/null || { CURRENT_MESSAGE="升级包 manifest 不符合小补丁协议"; return 1; }
  host_arch="$(uname -m)"; [[ "$host_arch" == x86_64 ]] && host_arch=amd64; [[ "$host_arch" == aarch64 ]] && host_arch=arm64
  [[ "$(jq -r '.architecture' "$manifest")" == "$host_arch" ]] || { CURRENT_MESSAGE="升级包架构与宿主机不一致"; return 1; }
  archive="$(jq -er '.images_archive.path' "$manifest")" || return 1
  [[ "$archive" == "images/runtime-images.tar" ]] || { CURRENT_MESSAGE="镜像归档路径无效"; return 1; }
  archive="$package_root/$archive"
  archive_sha="$(jq -er '.images_archive.sha256 | ascii_downcase' "$manifest")" || return 1
  [[ "$(sha256_file "$archive")" == "$archive_sha" ]] || { CURRENT_MESSAGE="镜像归档校验失败"; return 1; }

  mapfile -t SERVICES < <(jq -r '.components[].service' "$manifest")
  mapfile -t targets < <(jq -r '.components[].image' "$manifest")
  STABLE_IMAGES=(); OLD_IDS=()
  mapfile -t compose_services < <(compose config --services)
  for i in "${!SERVICES[@]}"; do
    service="${SERVICES[$i]}"; target="${targets[$i]}"
    printf '%s\n' "${compose_services[@]}" | grep -Fxq "$service" || { CURRENT_MESSAGE="compose 中没有服务 $service"; return 1; }
    stable="$(compose config --format json | jq -er --arg s "$service" '.services[$s].image')" || return 1
    old="$(docker image inspect "$stable" --format '{{.Id}}' 2>/dev/null)" || { CURRENT_MESSAGE="无法读取当前 $service 镜像"; return 1; }
    STABLE_IMAGES+=("$stable"); OLD_IDS+=("$old")
  done

  docker load -i "$archive" >/dev/null || { CURRENT_MESSAGE="加载镜像失败"; return 1; }
  for i in "${!SERVICES[@]}"; do
    docker image inspect "${targets[$i]}" >/dev/null 2>&1 || { CURRENT_MESSAGE="包内缺少镜像 ${targets[$i]}"; return 1; }
    docker tag "${targets[$i]}" "${STABLE_IMAGES[$i]}" || return 1
  done

  # API 镜像入口会在启动服务前执行 migrate up；这里保持 MIGRATING 状态，
  # 直到新容器成功启动，再进入健康检查阶段。
  CURRENT_STAGE="MIGRATING"
  compose up -d --no-deps "${SERVICES[@]}" || { CURRENT_MESSAGE="启动新版本容器失败"; return 1; }
  CURRENT_STAGE="VERIFYING"
  wait_api || { CURRENT_MESSAGE="升级后管理 API 健康检查超时"; return 1; }
  return 0
}

exec 9>"$RUNTIME_DIR/upgrade-executor/executor.lock"
flock -n 9 || exit 0
shopt -s nullglob
for queued in "$JOBS_DIR"/*.json; do
  processing="${queued%.json}.processing"
  mv "$queued" "$processing" || continue
  CURRENT_JOB="$(basename "$queued" .json)"; CURRENT_MESSAGE="执行器内部错误"
  if process_job "$processing"; then
    write_result "$CURRENT_JOB" SUCCESS VERIFYING "" "升级已生效并通过健康检查"
    mv "$processing" "${processing%.processing}.done"
    rm -rf "$WORK_DIR/$CURRENT_JOB"
  else
    rollback_images
    write_result "$CURRENT_JOB" FAILED "$CURRENT_STAGE" APPLY_FAILED "$CURRENT_MESSAGE；已尝试恢复原容器镜像"
    mv "$processing" "${processing%.processing}.failed"
  fi
done
