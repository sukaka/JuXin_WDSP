#!/usr/bin/env bash
# 宿主机升级执行器：处理 API 写入共享目录的运行时小补丁（package_type=runtime-patch）
# 与功能升级包（package_type=upgrade，多组件，含新组件首次部署）任务。
#
# 注意：本脚本更新后必须在宿主机重新运行 install-executor.sh 完成安装
# （程序位于 /usr/local/libexec/jiuzhang-upgrade-executor），否则 systemd 仍运行旧版。
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

# diff/cmp 属 diffutils：manifest 文件清单比对与 compose 覆盖判异必需；
# openEuler 最小化镜像缺省不带，缺失时必须报准确错误而非下游误导性比对失败。
for cmd in docker jq python3 curl flock sha256sum gzip timeout diff cmp; do
  command -v "$cmd" >/dev/null 2>&1 && continue
  case "$cmd" in
    diff|cmp) printf '缺少命令: %s（diffutils 包；manifest 文件比对与 compose 覆盖判异必需）\n' "$cmd" >&2 ;;
    *) printf '缺少命令: %s\n' "$cmd" >&2 ;;
  esac
  exit 1
done
[[ -d "$RUNTIME_DIR" && -f "$COMPOSE_FILE" && -f "$ENV_FILE" ]] || {
  printf '%s\n' '运行目录、compose 文件或 env 文件不存在' >&2; exit 1;
}

JOBS_DIR="$RUNTIME_DIR/upgrade-executor/jobs"
RESULTS_DIR="$RUNTIME_DIR/upgrade-executor/results"
WORK_DIR="$RUNTIME_DIR/upgrade-executor/work"
STATE_DIR="$RUNTIME_DIR/upgrade-executor/state"
PACKAGES_DIR="$RUNTIME_DIR/upgrade-packages"
# OVERRIDES_DIR 升级包新组件 compose 片段持久化目录（随每次 compose 调用并入）。
OVERRIDES_DIR="$RUNTIME_DIR/upgrade-executor/compose-overrides.d"
mkdir -p "$JOBS_DIR" "$RESULTS_DIR" "$WORK_DIR" "$STATE_DIR" "$OVERRIDES_DIR"

# compose ARGS... —— 基础 compose 文件 + 已并入的新组件片段（按文件名升序）。
compose() {
  local args=(-f "$COMPOSE_FILE") f
  for f in "$OVERRIDES_DIR"/*.yml; do
    [[ -e "$f" ]] || continue
    args+=(-f "$f")
  done
  docker compose "${args[@]}" --env-file "$ENV_FILE" "$@"
}
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

# 返回本轮单容器快照；inspect 失败绝不能等同于“未声明 HEALTHCHECK”。
wait_service() {
  local service="$1" container_id snapshot state health image restarts started extra
  container_id="$(compose ps -q "$service" 2>/dev/null)" || return 1
  [[ "$container_id" =~ ^[a-zA-Z0-9_-]+$ ]] || return 1
  snapshot="$(timeout 8 docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.Image}}|{{.RestartCount}}|{{.State.StartedAt}}' "$container_id" 2>/dev/null)" || return 1
  IFS='|' read -r state health image restarts started extra <<<"$snapshot"
  [[ "$state" == running && ( -z "$health" || "$health" == healthy ) \
    && "$image" == sha256:* && "$restarts" =~ ^[0-9]+$ && -n "$started" && -z "$extra" ]] || return 1
  printf '%s|%s|%s|%s\n' "$container_id" "$image" "$restarts" "$started"
}

probe_service() {
  local service="$1" container_id="$2" socket_dir
  case "$service" in
    api)
      timeout 8 docker exec "$container_id" wget -q -T 5 -O /dev/null http://127.0.0.1:8080/api/v1/health
      ;;
    web)
      timeout 12 docker exec "$container_id" sh -ec 'wget -q -T 5 -O /dev/null http://127.0.0.1:8080/ && wget -q -T 5 -O /dev/null http://127.0.0.1:8080/api/v1/health'
      ;;
    gateway)
      socket_dir="$(timeout 8 docker inspect --format '{{json .Mounts}}' "$container_id" | jq -er '[.[] | select(.Destination == "/var/run/caddy") | .Source] | if length == 1 then .[0] | select(type == "string" and startswith("/")) else empty end')" || return 1
      [[ -n "$socket_dir" ]] || return 1
      curl -fsS --max-time 5 --unix-socket "$socket_dir/admin.sock" http://localhost/config/ >/dev/null
      ;;
    netmgrd)
      timeout 8 docker exec "$container_id" /usr/local/bin/netmgrd --healthcheck
      ;;
    *) return 1 ;;
  esac
}

wait_selected_services() {
  local i service snapshot image expected signature previous="" stable_since=-1 ready
  local deadline=$((SECONDS + TIMEOUT))
  local -a expected_images=() snapshots=()
  if (( ${#SERVICES[@]} == 0 || ${#SERVICES[@]} != ${#STABLE_IMAGES[@]} )); then
    CURRENT_MESSAGE="升级后组件清单与镜像清单不匹配"
    return 1
  fi
  for i in "${!SERVICES[@]}"; do
    if ! expected="$(timeout 8 docker image inspect --format '{{.Id}}' "${STABLE_IMAGES[$i]}" 2>/dev/null)" || [[ "$expected" != sha256:* ]]; then
      CURRENT_MESSAGE="无法读取升级目标镜像: ${SERVICES[$i]}"
      return 1
    fi
    expected_images+=("$expected")
  done
  while (( SECONDS < deadline )); do
    ready=1 signature="" snapshots=()
    for i in "${!SERVICES[@]}"; do
      service="${SERVICES[$i]}"
      if ! snapshot="$(wait_service "$service")"; then
        CURRENT_MESSAGE="升级后组件 $service 未就绪（容器状态或 inspect 不可用）"
        ready=0; break
      fi
      image="${snapshot#*|}"; image="${image%%|*}"
      if [[ "$image" != "${expected_images[$i]}" ]]; then
        CURRENT_MESSAGE="升级后组件 $service 未运行目标镜像"
        ready=0; break
      fi
      if ! probe_service "$service" "${snapshot%%|*}" >/dev/null 2>&1; then
        CURRENT_MESSAGE="升级后组件 $service 实际服务探测失败"
        ready=0; break
      fi
      snapshots+=("$snapshot")
      signature+="$service:$snapshot;"
    done
    if (( ready )) && ! curl -fsS --max-time 5 "$API_URL/api/v1/health" >/dev/null 2>&1; then
      CURRENT_MESSAGE="升级后管理 API 健康检查失败"
      ready=0
    fi
    # 检查 API 期间其他组件也可能退出/重启；回读整个组件集合而非单次顺序放行。
    if (( ready )); then
      for i in "${!SERVICES[@]}"; do
        if ! snapshot="$(wait_service "${SERVICES[$i]}")" || [[ "$snapshot" != "${snapshots[$i]}" ]]; then
          CURRENT_MESSAGE="升级后组件 ${SERVICES[$i]} 在健康检查期间发生变化"
          ready=0; break
        fi
      done
    fi
    if (( ready )); then
      if [[ "$signature" != "$previous" ]] || (( stable_since < 0 )); then
        previous="$signature" stable_since=$SECONDS
      fi
      if (( SECONDS - stable_since >= 10 && SECONDS < deadline )); then
        CURRENT_MESSAGE=""
        return 0
      fi
      CURRENT_MESSAGE="升级后组件尚未连续稳定 10 秒"
    else
      previous="" stable_since=-1
    fi
    sleep 2
  done
  CURRENT_MESSAGE+="（${TIMEOUT} 秒内未就绪）"
  return 1
}

declare -a SERVICES=() STABLE_IMAGES=() OLD_IDS=() NEW_SERVICES=()
CURRENT_JOB="" CURRENT_STAGE="APPLYING" CURRENT_MESSAGE="" INSTALLED_OVERRIDE=""
IMAGE_SWITCH_STARTED=false

rollback_images() {
  local i
  declare -a existed=()
  if [[ "$IMAGE_SWITCH_STARTED" == true ]]; then
    for i in "${!SERVICES[@]}"; do
      if [[ -n "${OLD_IDS[$i]:-}" ]]; then
        docker tag "${OLD_IDS[$i]}" "${STABLE_IMAGES[$i]}" >/dev/null 2>&1 || true
        existed+=("${SERVICES[$i]}")
      fi
    done
  fi
  # 新组件回滚：趁 compose 片段仍在时移除其容器，再摘除片段、删除新加载的镜像标签
  ((${#NEW_SERVICES[@]} == 0)) || compose rm -sf "${NEW_SERVICES[@]}" >/dev/null 2>&1 || true
  if [[ -n "$INSTALLED_OVERRIDE" ]]; then
    rm -f "$INSTALLED_OVERRIDE" || true
    INSTALLED_OVERRIDE=""
  fi
  for i in "${!SERVICES[@]}"; do
    [[ -z "${OLD_IDS[$i]:-}" ]] && docker rmi "${STABLE_IMAGES[$i]}" >/dev/null 2>&1 || true
  done
  if [[ "$IMAGE_SWITCH_STARTED" == true ]]; then
    ((${#existed[@]} == 0)) || compose up -d --no-deps --force-recreate "${existed[@]}" >/dev/null 2>&1 || true
    wait_api || true
  fi
}

process_job() {
  local job_file="$1" package_name expected_sha package version_from version_to job_id
  local work package_root manifest package_type
  CURRENT_STAGE="APPLYING"
  SERVICES=(); STABLE_IMAGES=(); OLD_IDS=(); NEW_SERVICES=(); INSTALLED_OVERRIDE=""; IMAGE_SWITCH_STARTED=false
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
  [[ -f "$manifest" ]] || { CURRENT_MESSAGE="升级包清单缺失"; return 1; }
  package_type="$(jq -er '.package_type | strings' "$manifest")" || { CURRENT_MESSAGE="升级包 manifest 缺少 package_type"; return 1; }
  case "$package_type" in
    runtime-patch) process_runtime_patch "$package_root" "$manifest" "$version_from" "$version_to" ;;
    upgrade) process_upgrade_pack "$package_root" "$manifest" "$version_from" "$version_to" ;;
    *) CURRENT_MESSAGE="不支持的升级包类型: $package_type"; return 1 ;;
  esac
}

# 运行时小补丁（bugfix，组件 api/web/gateway）；gateway 在 retag 前执行同一启动契约门禁。
process_runtime_patch() {
  local package_root="$1" manifest="$2" version_from="$3" version_to="$4"
  local archive archive_sha host_arch service target stable old i
  [[ -f "$package_root/SHA256SUMS" ]] || { CURRENT_MESSAGE="升级包清单缺失"; return 1; }
  (cd "$package_root" && sha256sum -c SHA256SUMS >/dev/null) || { CURRENT_MESSAGE="包内校验和失败"; return 1; }
  jq -e --arg from "$version_from" --arg to "$version_to" '
    .format_version == 1 and .product == "wdsp" and .package_type == "runtime-patch" and
    .change_type == "bugfix" and .version_from == $from and .version_to == $to and
    (.components | length >= 1) and
    (all(.components[]; (.service == "api" or .service == "web" or .service == "gateway") and (.image | type == "string")))
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
  done
  for i in "${!SERVICES[@]}"; do
    [[ "${SERVICES[$i]}" == gateway ]] || continue
    validate_gateway_start_contract "${targets[$i]}" || return 1
  done
  IMAGE_SWITCH_STARTED=true
  for i in "${!SERVICES[@]}"; do
    docker tag "${targets[$i]}" "${STABLE_IMAGES[$i]}" || return 1
  done

  # API 镜像入口会在启动服务前执行 migrate up；这里保持 MIGRATING 状态，
  # 直到新容器成功启动，再进入健康检查阶段。
  CURRENT_STAGE="MIGRATING"
  compose up -d --no-deps "${SERVICES[@]}" || { CURRENT_MESSAGE="启动新版本容器失败"; return 1; }
  CURRENT_STAGE="VERIFYING"
  wait_selected_services || return 1
  return 0
}

validate_gateway_start_contract() {
  local target="$1" image_entrypoint compose_json
  image_entrypoint="$(docker image inspect "$target" --format '{{json .Config.Entrypoint}}' 2>/dev/null)" \
    || { CURRENT_MESSAGE="无法读取 gateway 目标镜像入口"; return 1; }
  case "$image_entrypoint" in
    '["/usr/local/bin/docker-entrypoint.sh"]')
      compose_json="$(compose config --format json 2>/dev/null)" \
        || { CURRENT_MESSAGE="无法解析合并后的 Compose，拒绝启动旧 gateway"; return 1; }
      if ! jq -e '
        .services.gateway as $gateway |
        ($gateway.user == null or $gateway.user == "1000:1000" or $gateway.user == "caddy" or $gateway.user == "caddy:caddy") and
        ($gateway.entrypoint == null or $gateway.entrypoint == [] or $gateway.entrypoint == ["/usr/local/bin/docker-entrypoint.sh"]) and
        ($gateway.cap_add == null or $gateway.cap_add == [] or $gateway.cap_add == ["NET_BIND_SERVICE"]) and
        ($gateway.cap_drop == null or $gateway.cap_drop == [] or $gateway.cap_drop == ["ALL"]) and
        ((($gateway.security_opt // []) | type) == "array") and
        (($gateway.security_opt // []) | index("no-new-privileges:true") != null)
      ' <<<"$compose_json" >/dev/null; then
        CURRENT_MESSAGE="旧 gateway Compose 启动契约不安全（禁止旧 Caddy 常驻 root；要求 user 为空/1000:1000/caddy/caddy:caddy，entrypoint 为空或原入口，cap_add 为空或仅 NET_BIND_SERVICE，cap_drop 为空或 ALL，且启用 no-new-privileges）；禁止 retag/up"
        return 1
      fi
      return 0
      ;;
    '["/usr/local/bin/wdsp-gateway-bind"]') ;;
    *) CURRENT_MESSAGE="拒绝未知 gateway 镜像 Config.Entrypoint: $image_entrypoint"; return 1 ;;
  esac
  compose_json="$(compose config --format json 2>/dev/null)" \
    || { CURRENT_MESSAGE="无法解析合并后的 Compose，拒绝启动新 gateway"; return 1; }
  if ! jq -e '
    .services.gateway as $gateway |
    ($gateway.user == "0:0") and
    ($gateway.entrypoint == ["/usr/local/bin/wdsp-gateway-bind"]) and
    ($gateway.cap_drop == ["ALL"]) and
    ((($gateway.cap_add // []) | sort) == (["NET_BIND_SERVICE", "SETUID", "SETGID", "SETPCAP"] | sort)) and
    (($gateway.security_opt // []) | index("no-new-privileges:true") != null)
  ' <<<"$compose_json" >/dev/null; then
    CURRENT_MESSAGE="新 gateway 启动器与现有 Compose 启动契约不兼容（要求 user=0:0、entrypoint=/usr/local/bin/wdsp-gateway-bind、cap_drop=ALL、cap_add 恰好为 NET_BIND_SERVICE/SETUID/SETGID/SETPCAP、no-new-privileges）；请先使用完整包升级宿主 Compose"
    return 1
  fi
}

# 功能升级包（package_type=upgrade，build-upgrade-pack.sh 产物）：
#   逐组件 images[].tar（gzip）docker load 并 inspect → 启动契约检查 → 统一 retag → compose up -d；
#   manifest.files 逐一校验（存在性/大小/SHA-256）并反查无未声明文件（口径同服务端
#   artifact.go）；组件白名单 api/web/gateway/netmgrd；新组件（netmgrd）经包内
#   compose/upgrade-services.yml 片段并入 compose-overrides.d 后首次创建。
# 失败回滚语义沿用 runtime-patch（retag 回退）；新组件额外摘除片段并删除新镜像标签。
process_upgrade_pack() {
  local package_root="$1" manifest="$2" version_from="$3" version_to="$4"
  local host_arch service target stable old i f rel expected_size expected_sha actual_size actual_sha

  # 可选纵深：构建器总是产出 SHA256SUMS，存在即校验（manifest.files 才是主校验）
  if [[ -f "$package_root/SHA256SUMS" ]]; then
    (cd "$package_root" && sha256sum -c SHA256SUMS >/dev/null) || { CURRENT_MESSAGE="包内校验和失败"; return 1; }
  fi
  jq -e --arg from "$version_from" --arg to "$version_to" '
    .components as $comps | .images as $imgs | .files as $files |
    (.format_version == 1 or .format_version == "1") and
    .product == "wdsp" and .package_type == "upgrade" and
    (.change_type == "feature" or .change_type == "bugfix") and
    .version_from == $from and .version_to == $to and .version == $to and
    (.arch | type == "string") and
    ($comps | type == "array" and length >= 1 and (unique | length) == length and
      (all(.[]; . == "api" or . == "web" or . == "gateway" or . == "netmgrd"))) and
    ($imgs | type == "array" and length == ($comps | length)) and
    (all($imgs[]; (.component == .service) and
      (.service == "api" or .service == "web" or .service == "gateway" or .service == "netmgrd") and
      (.image | type == "string" and test("^[A-Za-z0-9._:/-]+$")) and
      (.tar | type == "string" and test("^images/[A-Za-z0-9._-]+\\.tar\\.gz$")))) and
    (([$imgs[].component] | sort) == ($comps | sort)) and
    ($files | type == "array" and length >= 1) and
    (all($files[];
      (.path | type == "string" and . != "manifest.json" and . != "manifest.sig"
        and test("^[A-Za-z0-9._/-]+$")
        and (startswith("/") | not) and (contains("..") | not)) and
      (.sha256 | type == "string" and test("^[0-9a-fA-F]{64}$")) and
      (.size | type == "number" and . >= 0)))
  ' "$manifest" >/dev/null || { CURRENT_MESSAGE="升级包 manifest 不符合升级包协议"; return 1; }
  host_arch="$(uname -m)"; [[ "$host_arch" == x86_64 ]] && host_arch=amd64; [[ "$host_arch" == aarch64 ]] && host_arch=arm64
  [[ "$(jq -r '.arch' "$manifest")" == "$host_arch" ]] || { CURRENT_MESSAGE="升级包架构与宿主机不一致"; return 1; }

  # manifest.files 逐一校验（路径已经在上方 jq 白名单校验过）
  while IFS=$'\t' read -r rel expected_size expected_sha; do
    f="$package_root/$rel"
    [[ -f "$f" ]] || { CURRENT_MESSAGE="包内文件缺失: $rel"; return 1; }
    actual_size="$(stat -c%s "$f")"
    [[ "$actual_size" == "$expected_size" ]] || { CURRENT_MESSAGE="包内文件大小不符: $rel"; return 1; }
    actual_sha="$(sha256_file "$f")"
    [[ "$actual_sha" == "$(printf '%s' "$expected_sha" | tr 'A-F' 'a-f')" ]] || { CURRENT_MESSAGE="包内文件 SHA-256 不符: $rel"; return 1; }
  done < <(jq -er '.files[] | [.path, (.size | tostring), .sha256] | @tsv' "$manifest")
  # 反查：除 manifest.json/manifest.sig（保留根文件，不进 files 清单）外不得有未声明
  # 文件（与服务端「归档↔清单一一对应」同口径；manifest.sig 为包内签名，服务端上传时验签）
  local listed_tmp actual_tmp
  listed_tmp="$(mktemp "$STATE_DIR/.listed.XXXXXX")"
  actual_tmp="$(mktemp "$STATE_DIR/.actual.XXXXXX")"
  jq -r '.files[].path' "$manifest" | LC_ALL=C sort > "$listed_tmp"
  if ! (cd "$package_root" && find . -type f ! -name manifest.json ! -name manifest.sig -printf '%P\n' | LC_ALL=C sort) > "$actual_tmp"; then
    rm -f "$listed_tmp" "$actual_tmp"
    CURRENT_MESSAGE="包内文件枚举失败"
    return 1
  fi
  if ! diff -q "$listed_tmp" "$actual_tmp" >/dev/null 2>&1; then
    rm -f "$listed_tmp" "$actual_tmp"
    CURRENT_MESSAGE="包内文件与 manifest 声明不一致（存在未声明文件）"
    return 1
  fi
  rm -f "$listed_tmp" "$actual_tmp"

  mapfile -t SERVICES < <(jq -r '.images[].service' "$manifest")
  mapfile -t targets < <(jq -r '.images[].image' "$manifest")
  mapfile -t tars < <(jq -r '.images[].tar' "$manifest")
  # 组件白名单（双重防御；jq 协议校验已约束）
  for service in "${SERVICES[@]}"; do
    case "$service" in
      api|web|gateway|netmgrd) ;;
      *) CURRENT_MESSAGE="拒绝未知组件: $service"; return 1 ;;
    esac
  done

  # 新组件首次部署：宿主 compose（含已并入片段）缺失的服务须由包内片段恰好补齐
  mapfile -t compose_services < <(compose config --services)
  declare -a missing=()
  local found c
  for service in "${SERVICES[@]}"; do
    found=0
    for c in "${compose_services[@]}"; do [[ "$c" == "$service" ]] && { found=1; break; }; done
    ((found == 1)) || missing+=("$service")
  done
  if ((${#missing[@]} > 0)); then
    local fragment="$package_root/compose/upgrade-services.yml"
    [[ -f "$fragment" ]] || { CURRENT_MESSAGE="升级包缺少新组件 compose 片段（缺失服务: ${missing[*]}）"; return 1; }
    local of merged_before merged_after before_services after_services added
    local args=(-f "$COMPOSE_FILE")
    for of in "$OVERRIDES_DIR"/*.yml; do
      [[ -e "$of" ]] || continue
      args+=(-f "$of")
    done
    merged_before="$(docker compose "${args[@]}" --env-file "$ENV_FILE" config --format json 2>/dev/null)" \
      || { CURRENT_MESSAGE="现有 compose 配置解析失败"; return 1; }
    merged_after="$(docker compose "${args[@]}" -f "$fragment" --env-file "$ENV_FILE" config --format json 2>/dev/null)" \
      || { CURRENT_MESSAGE="新组件 compose 片段无法并入解析"; return 1; }
    before_services="$(printf '%s' "$merged_before" | jq -r '.services | keys[]' | LC_ALL=C sort)"
    after_services="$(printf '%s' "$merged_after" | jq -r '.services | keys[]' | LC_ALL=C sort)"
    added="$(comm -13 <(printf '%s\n' "$before_services") <(printf '%s\n' "$after_services"))"
    [[ "$added" == "$(printf '%s\n' "${missing[@]}" | LC_ALL=C sort)" ]] \
      || { CURRENT_MESSAGE="compose 片段新增服务与缺失服务不一致"; return 1; }
    # 片段不得改写既有服务的镜像
    local img_before img_after
    while IFS= read -r c; do
      [[ -n "$c" ]] || continue
      img_before="$(printf '%s' "$merged_before" | jq -er --arg s "$c" '.services[$s].image // ""')"
      img_after="$(printf '%s' "$merged_after" | jq -er --arg s "$c" '.services[$s].image // ""')"
      [[ "$img_before" == "$img_after" ]] || { CURRENT_MESSAGE="compose 片段试图改写既有服务 $c 的镜像"; return 1; }
    done <<< "$before_services"
    # 新服务镜像必须与 manifest 声明一致
    local want
    while IFS= read -r c; do
      [[ -n "$c" ]] || continue
      want="$(jq -er --arg s "$c" '.images[] | select(.service == $s) | .image' "$manifest")" || return 1
      [[ "$(printf '%s' "$merged_after" | jq -er --arg s "$c" '.services[$s].image // ""')" == "$want" ]] \
        || { CURRENT_MESSAGE="新服务 $c 的 compose 镜像与 manifest 声明不一致"; return 1; }
    done <<< "$added"
    # 幂等安装片段：同名文件内容必须一致
    local target_override="$OVERRIDES_DIR/upgrade-${version_to}.yml"
    if [[ -f "$target_override" ]] && ! cmp -s "$fragment" "$target_override"; then
      CURRENT_MESSAGE="compose 片段与已安装的同名片段冲突: upgrade-${version_to}.yml"
      return 1
    fi
    install -m 0600 -o root -g root "$fragment" "$target_override" \
      || { CURRENT_MESSAGE="安装 compose 片段失败"; return 1; }
    INSTALLED_OVERRIDE="$target_override"
    mapfile -t NEW_SERVICES < <(printf '%s\n' "${missing[@]}")
  fi

  STABLE_IMAGES=(); OLD_IDS=()
  for i in "${!SERVICES[@]}"; do
    service="${SERVICES[$i]}"; target="${targets[$i]}"
    stable="$(compose config --format json | jq -er --arg s "$service" '.services[$s].image')" || return 1
    old=""
    if [[ " ${NEW_SERVICES[*]-} " == *" $service "* ]]; then
      # 新组件：compose 片段镜像即目标标签（已校验一致），无旧镜像可回退
      [[ "$stable" == "$target" ]] || { CURRENT_MESSAGE="新服务 $service 镜像口径异常"; return 1; }
    else
      old="$(docker image inspect "$stable" --format '{{.Id}}' 2>/dev/null)" || { CURRENT_MESSAGE="无法读取当前 $service 镜像"; return 1; }
    fi
    STABLE_IMAGES+=("$stable"); OLD_IDS+=("$old")
  done

  for i in "${!targets[@]}"; do
    gzip -dc "$package_root/${tars[$i]}" | docker load >/dev/null \
      || { CURRENT_MESSAGE="加载镜像失败: ${tars[$i]}"; return 1; }
  done
  for i in "${!targets[@]}"; do
    docker image inspect "${targets[$i]}" >/dev/null 2>&1 || { CURRENT_MESSAGE="包内缺少镜像 ${targets[$i]}"; return 1; }
  done
  for i in "${!targets[@]}"; do
    [[ "${SERVICES[$i]}" == gateway ]] || continue
    validate_gateway_start_contract "${targets[$i]}" || return 1
  done

  # gateway 重建会使 network_mode: service:gateway 的 netmgrd 失去原网络命名空间。
  # 即使升级包不更新 netmgrd 镜像，也要把现有服务纳入同次重建、健康检查与回滚。
  if printf '%s\n' "${SERVICES[@]}" | grep -Fxq gateway \
    && ! printf '%s\n' "${SERVICES[@]}" | grep -Fxq netmgrd \
    && printf '%s\n' "${compose_services[@]}" | grep -Fxq netmgrd; then
    stable="$(compose config --format json | jq -er '.services.netmgrd.image | select(type == "string" and length > 0)')" \
      || { CURRENT_MESSAGE="无法读取 netmgrd 的 compose 镜像"; return 1; }
    old="$(docker image inspect "$stable" --format '{{.Id}}' 2>/dev/null)" \
      || { CURRENT_MESSAGE="无法读取当前 netmgrd 镜像"; return 1; }
    SERVICES+=(netmgrd)
    STABLE_IMAGES+=("$stable")
    OLD_IDS+=("$old")
  fi

  IMAGE_SWITCH_STARTED=true
  for i in "${!targets[@]}"; do
    docker tag "${targets[$i]}" "${STABLE_IMAGES[$i]}" || return 1
  done

  # API 镜像入口会在启动服务前执行 migrate up；这里保持 MIGRATING 状态，
  # 直到新容器成功启动，再进入健康检查阶段。强制重建覆盖镜像未变化的 netmgrd。
  CURRENT_STAGE="MIGRATING"
  compose up -d --no-deps --force-recreate "${SERVICES[@]}" || { CURRENT_MESSAGE="启动新版本容器失败"; return 1; }
  CURRENT_STAGE="VERIFYING"
  wait_selected_services || return 1
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
    if [[ "$IMAGE_SWITCH_STARTED" == true ]]; then
      CURRENT_MESSAGE+="；已尝试恢复原容器镜像"
    else
      CURRENT_MESSAGE+="；未切换镜像，现有容器未重建；已清理本轮新组件/临时资源"
    fi
    write_result "$CURRENT_JOB" FAILED "$CURRENT_STAGE" APPLY_FAILED "$CURRENT_MESSAGE"
    mv "$processing" "${processing%.processing}.failed"
  fi
done
