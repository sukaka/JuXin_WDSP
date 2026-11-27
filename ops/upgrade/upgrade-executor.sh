#!/usr/bin/env bash
# 宿主机升级执行器：处理 API 写入共享目录的运行时小补丁（package_type=runtime-patch）
# 与功能升级包（package_type=upgrade，多组件，含新组件首次部署）任务。
#
# 注意：本脚本更新后必须在宿主机重新运行 install-executor.sh 完成安装
# （程序位于 /usr/local/libexec/jiuzhang-upgrade-executor），否则 systemd 仍运行旧版。
set -euo pipefail

CONFIG_FILE="/etc/jiuzhang/upgrade-executor.conf"
TEST_PUBKEY_FILE=""

usage() {
  printf '%s\n' '用法: upgrade-executor.sh [--config FILE]' \
    '由 systemd 调用；配置文件必须由 root 拥有且不可被其他用户写入。'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG_FILE="${2:-}"; shift 2 ;;
    --test-pubkey) TEST_PUBKEY_FILE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf '未知参数: %s\n' "$1" >&2; exit 2 ;;
  esac
done

if [[ -n "$TEST_PUBKEY_FILE" && "$CONFIG_FILE" == "/etc/jiuzhang/upgrade-executor.conf" ]]; then
  printf '%s\n' '生产配置禁止使用 --test-pubkey' >&2
  exit 1
fi

[[ $EUID -eq 0 ]] || { printf '%s\n' '必须以 root 运行' >&2; exit 1; }
[[ -f "$CONFIG_FILE" && ! -L "$CONFIG_FILE" ]] || { printf '配置文件不存在或为符号链接: %s\n' "$CONFIG_FILE" >&2; exit 1; }
owner="$(stat -c '%u' "$CONFIG_FILE")"
mode="$(stat -c '%a' "$CONFIG_FILE")"
[[ "$owner" == 0 ]] && (( (0$mode & 022) == 0 )) || {
  printf '%s\n' '配置文件必须由 root 拥有且组/其他用户不可写' >&2; exit 1;
}
# 防止配置文件覆盖只读 CLI 测试公钥或内置发布公钥
_cli_test_pubkey="$TEST_PUBKEY_FILE"
# 配置由本项目安装脚本生成，权限已在上方验证。
# shellcheck disable=SC1090
source "$CONFIG_FILE"
TEST_PUBKEY_FILE="$_cli_test_pubkey"
unset _cli_test_pubkey

# 内置可信发布公钥（Ed25519，与 ops/offline-package/release-signing.pub 同源；
# 放在 source CONFIG_FILE 之后设为 readonly，禁止配置或环境覆盖生产信任根）。
readonly WDSP_RELEASE_PUBKEY_PEM="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJBzjZs04R6NVLDuKoJsViPuBEGlo70z/zpnKi6ZHq2s=
-----END PUBLIC KEY-----"

if [[ -n "$TEST_PUBKEY_FILE" ]]; then
  [[ "$CONFIG_FILE" != "/etc/jiuzhang/upgrade-executor.conf" ]] || {
    printf '%s\n' '生产配置禁止使用 --test-pubkey' >&2; exit 1;
  }
  [[ -f "$TEST_PUBKEY_FILE" && ! -L "$TEST_PUBKEY_FILE" ]] || {
    printf '测试公钥文件无效: %s\n' "$TEST_PUBKEY_FILE" >&2; exit 1;
  }
fi

: "${RUNTIME_DIR:?缺少 RUNTIME_DIR}"
: "${HOST_STATE_DIR:=/var/lib/jiuzhang/upgrade-executor}"
: "${COMPOSE_FILE:?缺少 COMPOSE_FILE}"
: "${ENV_FILE:?缺少 ENV_FILE}"
: "${API_URL:=http://127.0.0.1:18081}"
: "${TIMEOUT:=600}"

# diff/cmp 属 diffutils：manifest 文件清单比对与 compose 覆盖判异必需；
# openEuler 最小化镜像缺省不带，缺失时必须报准确错误而非下游误导性比对失败。
for cmd in docker jq python3 curl flock sha256sum gzip timeout diff cmp openssl; do
  command -v "$cmd" >/dev/null 2>&1 && continue
  case "$cmd" in
    diff|cmp) printf '缺少命令: %s（diffutils 包；manifest 文件比对与 compose 覆盖判异必需）\n' "$cmd" >&2 ;;
    *) printf '缺少命令: %s\n' "$cmd" >&2 ;;
  esac
  exit 1
done
[[ -d "$RUNTIME_DIR" && ! -L "$RUNTIME_DIR" && -f "$COMPOSE_FILE" && ! -L "$COMPOSE_FILE" && -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || {
  printf '%s\n' '运行目录、compose 文件或 env 文件不存在或为符号链接' >&2; exit 1;
}

# 宿主机 root 专用特权状态目录（工作区/状态/compose 覆盖片段/锁文件），与 uid 1000 可写目录彻底隔离。
python3 - "$HOST_STATE_DIR" <<'PY'
import os, pathlib, stat, sys
p = pathlib.Path(sys.argv[1])
if not p.is_absolute() or ".." in p.parts or len(p.parts) < 3:
    raise SystemExit(f"非法 HOST_STATE_DIR: {p}")
cur = pathlib.Path("/")
for part in p.parts[1:]:
    cur = cur / part
    if cur.is_symlink():
        raise SystemExit(f"HOST_STATE_DIR 组件不得为符号链接: {cur}")
    if cur.exists():
        st = os.lstat(cur)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or (stat.S_IMODE(st.st_mode) & 0o022) != 0:
            raise SystemExit(f"HOST_STATE_DIR 组件属主或权限不安全: {cur}")
    else:
        cur.mkdir(mode=0o700)
        os.chown(cur, 0, 0)
        os.chmod(cur, 0o700)
for sub in ("", "work", "state", "compose-overrides.d"):
    d = p / sub if sub else p
    if d.is_symlink():
        raise SystemExit(f"特权目录不得为符号链接: {d}")
    if not d.exists():
        d.mkdir(mode=0o700)
    st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0:
        raise SystemExit(f"特权目录属主或类型异常: {d}")
    os.chmod(d, 0o700)
lock_file = p / "executor.lock"
if lock_file.is_symlink():
    raise SystemExit(f"锁文件不得为符号链接: {lock_file}")
PY

JOBS_DIR="$RUNTIME_DIR/upgrade-executor/jobs"
RESULTS_DIR="$RUNTIME_DIR/upgrade-executor/results"
PACKAGES_DIR="$RUNTIME_DIR/upgrade-packages"
WORK_DIR="$HOST_STATE_DIR/work"
STATE_DIR="$HOST_STATE_DIR/state"
# OVERRIDES_DIR 升级包新组件 compose 片段持久化目录（位于 root 0700 状态目录，随每次 compose 调用并入）。
OVERRIDES_DIR="$HOST_STATE_DIR/compose-overrides.d"
LOCK_FILE="$HOST_STATE_DIR/executor.lock"
for _shared in "$RUNTIME_DIR/upgrade-executor" "$JOBS_DIR" "$RESULTS_DIR" "$PACKAGES_DIR"; do
  [[ ! -L "$_shared" ]] || { printf '共享通道目录不得为符号链接: %s\n' "$_shared" >&2; exit 1; }
done
unset _shared
mkdir -p "$JOBS_DIR" "$RESULTS_DIR"

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
  [[ ! -L "$RESULTS_DIR/$job_id.json" ]] || return 1
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
    if not members or len(members) > 64:
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
  if [[ "$service" == pcapd ]]; then
    container_id="$(compose --profile request-pcap ps -q "$service" 2>/dev/null)" || return 1
  elif [[ "$service" == hasyncd ]]; then
    container_id="$(compose --profile ha-sync ps -q "$service" 2>/dev/null)" || return 1
  else
    container_id="$(compose ps -q "$service" 2>/dev/null)" || return 1
  fi
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
    mirrorcap)
      timeout 8 docker exec "$container_id" /usr/local/bin/mirrorcap --healthcheck
      ;;
    tproxyd)
      timeout 8 docker exec "$container_id" /usr/local/bin/tproxyd --healthcheck
      ;;
    havipd)
      timeout 8 docker exec "$container_id" /usr/local/bin/havipd --healthcheck
      ;;
    hasyncd)
      timeout 8 docker exec "$container_id" /usr/local/bin/hasyncd --healthcheck
      ;;
    logrotator)
      timeout 8 docker exec "$container_id" kill -0 1
      ;;
    containerops)
      timeout 8 docker exec "$container_id" sh -ec 'test -S "${CONTAINEROPS_SOCKET:-/run/containerops/containerops.sock}"'
      ;;
    pcapd)
      timeout 8 docker exec "$container_id" kill -0 1
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
    if [[ "${SERVICES[$i]}" == pcapd && "${PCAPD_SKIP_START:-false}" == true ]] \
      || [[ "${SERVICES[$i]}" == hasyncd && "${HASYNCD_SKIP_START:-false}" == true ]]; then
      expected_images+=("")
      continue
    fi
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
      if [[ "$service" == pcapd && "${PCAPD_SKIP_START:-false}" == true ]] \
        || [[ "$service" == hasyncd && "${HASYNCD_SKIP_START:-false}" == true ]]; then
        snapshots+=("")
        continue
      fi
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
        if [[ "${SERVICES[$i]}" == pcapd && "${PCAPD_SKIP_START:-false}" == true ]] \
          || [[ "${SERVICES[$i]}" == hasyncd && "${HASYNCD_SKIP_START:-false}" == true ]]; then
          continue
        fi
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

declare -a SERVICES=() STABLE_IMAGES=() OLD_IDS=() NEW_SERVICES=() API_EXTRA_NETWORKS=()
CURRENT_JOB="" CURRENT_STAGE="APPLYING" CURRENT_MESSAGE="" INSTALLED_OVERRIDE=""
IMAGE_SWITCH_STARTED=false
PCAPD_SKIP_START=false
HASYNCD_SKIP_START=false

rollback_images() {
  local i
  declare -a existed=()
  local rollback_pcapd=false rollback_hasyncd=false
  if [[ "$IMAGE_SWITCH_STARTED" == true ]]; then
    for i in "${!SERVICES[@]}"; do
      if [[ -n "${OLD_IDS[$i]:-}" ]]; then
        docker tag "${OLD_IDS[$i]}" "${STABLE_IMAGES[$i]}" >/dev/null 2>&1 || true
        if [[ "${SERVICES[$i]}" == pcapd ]]; then
          [[ "${PCAPD_SKIP_START:-false}" == true ]] || rollback_pcapd=true
        elif [[ "${SERVICES[$i]}" == hasyncd ]]; then
          [[ "${HASYNCD_SKIP_START:-false}" == true ]] || rollback_hasyncd=true
        else
          existed+=("${SERVICES[$i]}")
        fi
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
    if ((${#existed[@]} > 0)); then
      compose up -d --no-deps --force-recreate "${existed[@]}" >/dev/null 2>&1 || true
      if printf '%s\n' "${existed[@]}" | grep -Fxq api; then
        reattach_api_extra_networks rollback >/dev/null 2>&1 || true
      fi
    fi
    if [[ "$rollback_pcapd" == true ]]; then
      compose --profile request-pcap up -d --no-deps --force-recreate pcapd >/dev/null 2>&1 || true
    fi
    if [[ "$rollback_hasyncd" == true ]]; then
      compose --profile ha-sync up -d --no-deps --force-recreate hasyncd >/dev/null 2>&1 || true
    fi
    wait_api || true
  fi
}

exec_valid_docker_network_name() {
  local name="${1:-}"
  [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || return 1
  case "$name" in
    none|host|bridge) return 1 ;;
  esac
  return 0
}

exec_container_network_names() {
  local target="${1:-}" raw
  [[ -n "$target" ]] || return 0
  raw="$(docker inspect --format '{{json .NetworkSettings.Networks}}' "$target" 2>/dev/null || true)"
  [[ -n "$raw" ]] || return 0
  jq -r 'if type == "object" then keys[] else empty end' <<<"$raw" 2>/dev/null || true
}

exec_colocated_apm_clickhouse_container() {
  local info cid
  info="$(docker inspect --format '{{.State.Running}}|{{.Name}}' jiuzhang-apm-clickhouse 2>/dev/null || true)"
  if [[ "$info" == "true|/jiuzhang-apm-clickhouse" || "$info" == "true|jiuzhang-apm-clickhouse" ]]; then
    printf 'jiuzhang-apm-clickhouse\n'
    return 0
  fi
  cid="$(docker ps -q --filter status=running \
    --filter label=com.docker.compose.project=jiuzhang-apm \
    --filter label=com.docker.compose.service=clickhouse 2>/dev/null | head -n 1 || true)"
  if [[ "$cid" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
    info="$(docker inspect --format '{{.State.Running}}|{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}' "$cid" 2>/dev/null || true)"
    if [[ "$info" == "true|jiuzhang-apm|clickhouse" ]]; then
      printf '%s\n' "$cid"
      return 0
    fi
  fi
  return 0
}

capture_api_extra_networks() {
  API_EXTRA_NETWORKS=()
  printf '%s\n' "${SERVICES[@]:-}" | grep -Fxq api || return 0
  local compose_json old_api_id ch_cid net ex skip
  local -a excluded=() candidates=()
  compose_json="$(compose config --format json 2>/dev/null || true)"
  if [[ -n "$compose_json" ]]; then
    while IFS= read -r net; do
      [[ -n "$net" ]] && excluded+=("$net")
    done < <(jq -r '
      (.name // "") as $proj |
      (.networks // {}) as $top |
      ((.services.api.networks // {}) | if type == "array" then . else keys end)[]? |
      . as $k |
      if ($top[$k].name // "") != "" then $top[$k].name
      elif $proj != "" then ($proj + "_" + $k)
      else $k end
    ' <<<"$compose_json" 2>/dev/null || true)
  fi
  old_api_id="$(compose ps -q api 2>/dev/null || true)"
  if [[ -n "$old_api_id" ]]; then
    while IFS= read -r net; do
      [[ -n "$net" ]] && candidates+=("$net")
    done < <(exec_container_network_names "$old_api_id")
  fi
  ch_cid="$(exec_colocated_apm_clickhouse_container)"
  if [[ -n "$ch_cid" ]]; then
    while IFS= read -r net; do
      [[ -n "$net" ]] && candidates+=("$net")
    done < <(exec_container_network_names "$ch_cid")
  fi
  ((${#candidates[@]} > 0)) || return 0
  while IFS= read -r net; do
    [[ -n "$net" ]] || continue
    exec_valid_docker_network_name "$net" || continue
    skip=false
    for ex in ${excluded[@]+"${excluded[@]}"}; do
      if [[ "$net" == "$ex" ]]; then
        skip=true
        break
      fi
    done
    [[ "$skip" == false ]] && API_EXTRA_NETWORKS+=("$net")
  done < <(printf '%s\n' "${candidates[@]}" | LC_ALL=C sort -u)
}

reattach_api_extra_networks() {
  local mode="${1:-strict}"
  declare -p API_EXTRA_NETWORKS >/dev/null 2>&1 || return 0
  ((${#API_EXTRA_NETWORKS[@]} > 0)) || return 0
  local api_id current_nets net after_nets
  api_id="$(compose ps -q api 2>/dev/null || true)"
  if [[ ! "$api_id" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
    CURRENT_MESSAGE="无法定位重建后的 api 容器，无法恢复附加网络"
    return 1
  fi
  current_nets="$(exec_container_network_names "$api_id")"
  for net in "${API_EXTRA_NETWORKS[@]}"; do
    exec_valid_docker_network_name "$net" || continue
    if [[ -n "$current_nets" ]] && printf '%s\n' "$current_nets" | grep -Fxq "$net"; then
      continue
    fi
    if ! docker network inspect "$net" >/dev/null 2>&1; then
      if [[ "$mode" == "rollback" ]]; then
        continue
      fi
      CURRENT_MESSAGE="api 附加网络不存在，无法恢复连接: $net"
      return 1
    fi
    if ! docker network connect "$net" "$api_id" >/dev/null 2>&1; then
      CURRENT_MESSAGE="为 api 容器恢复附加网络失败（如 ClickHouse 网络）: $net"
      return 1
    fi
    after_nets="$(exec_container_network_names "$api_id")"
    if ! printf '%s\n' "$after_nets" | grep -Fxq "$net"; then
      CURRENT_MESSAGE="api 容器附加网络恢复校验失败: $net"
      return 1
    fi
    current_nets="$after_nets"
  done
  return 0
}

process_job() {
  local job_file="$1" package_name expected_sha package version_from version_to job_id
  local work package_root manifest package_type
  CURRENT_STAGE="APPLYING"
  SERVICES=(); STABLE_IMAGES=(); OLD_IDS=(); NEW_SERVICES=(); API_EXTRA_NETWORKS=(); INSTALLED_OVERRIDE=""; IMAGE_SWITCH_STARTED=false; PCAPD_SKIP_START=false; HASYNCD_SKIP_START=false
  [[ -f "$job_file" && ! -L "$job_file" ]] || { CURRENT_MESSAGE="任务文件无效或为符号链接"; return 1; }
  job_id="$(jq -er '.job_id | strings' "$job_file")" || return 1
  [[ "$job_id" =~ ^[0-9a-fA-F-]{36}$ ]] || return 1
  CURRENT_JOB="$job_id"
  package_name="$(jq -er '.package_file | strings' "$job_file")" || return 1
  [[ "$package_name" == "$(basename "$package_name")" && "$package_name" == *.tar.gz ]] || return 1
  expected_sha="$(jq -er '.package_sha256 | strings | ascii_downcase' "$job_file")" || return 1
  [[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] || return 1
  version_from="$(jq -er '.version_from | strings' "$job_file")" || return 1
  version_to="$(jq -er '.version_to | strings' "$job_file")" || return 1
  validate_version_string "$version_from" || { CURRENT_MESSAGE="起始版本号格式非法"; return 1; }
  validate_version_string "$version_to" || { CURRENT_MESSAGE="目标版本号格式非法"; return 1; }
  package="$PACKAGES_DIR/$package_name"
  [[ -f "$package" && ! -L "$package" ]] || { CURRENT_MESSAGE="找不到升级包或升级包为符号链接"; return 1; }
  [[ "$(sha256_file "$package")" == "$expected_sha" ]] || { CURRENT_MESSAGE="升级包 SHA-256 不匹配"; return 1; }

  work="$WORK_DIR/$job_id"
  rm -rf "$work"
  mkdir -p "$work"
  safe_extract "$package" "$work" || { CURRENT_MESSAGE="升级包安全解压失败"; return 1; }
  mapfile -t roots < <(find "$work" -mindepth 1 -maxdepth 1 -type d)
  [[ ${#roots[@]} -eq 1 ]] || { CURRENT_MESSAGE="升级包目录结构无效"; return 1; }
  package_root="${roots[0]}"
  manifest="$package_root/manifest.json"
  [[ -f "$manifest" && ! -L "$manifest" ]] || { CURRENT_MESSAGE="升级包清单缺失"; return 1; }
  verify_package_signature "$package_root" "$manifest" || return 1
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
  local archive archive_sha host_arch service target stable old i recreate_netmgrd=false
  validate_version_string "$version_from" || { CURRENT_MESSAGE="起始版本号格式非法"; return 1; }
  validate_version_string "$version_to" || { CURRENT_MESSAGE="目标版本号格式非法"; return 1; }
  verify_package_signature "$package_root" "$manifest" || return 1
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
  for i in "${!targets[@]}"; do
    docker image inspect "${targets[$i]}" >/dev/null 2>&1 || { CURRENT_MESSAGE="包内缺少镜像 ${targets[$i]}"; return 1; }
  done
  for i in "${!targets[@]}"; do
    [[ "${SERVICES[$i]}" == gateway ]] || continue
    validate_gateway_start_contract "${targets[$i]}" || return 1
  done
  # runtime-patch 涉及 gateway 重建时，共享 gateway 网络命名空间的 netmgrd/havipd 必须同步强制重建。
  if printf '%s\n' "${SERVICES[@]}" | grep -Fxq gateway; then
    local _gw_dep
    for _gw_dep in netmgrd havipd; do
      if ! printf '%s\n' "${SERVICES[@]}" | grep -Fxq "$_gw_dep" \
        && printf '%s\n' "${compose_services[@]}" | grep -Fxq "$_gw_dep"; then
        stable="$(compose config --format json | jq -er --arg s "$_gw_dep" '.services[$s].image | select(type == "string" and length > 0)')" \
          || { CURRENT_MESSAGE="无法读取 $_gw_dep 的 compose 镜像"; return 1; }
        old="$(docker image inspect "$stable" --format '{{.Id}}' 2>/dev/null)" \
          || { CURRENT_MESSAGE="无法读取当前 $_gw_dep 镜像"; return 1; }
        SERVICES+=("$_gw_dep")
        STABLE_IMAGES+=("$stable")
        OLD_IDS+=("$old")
        recreate_netmgrd=true
      fi
    done
  fi
  capture_api_extra_networks
  IMAGE_SWITCH_STARTED=true
  for i in "${!targets[@]}"; do
    docker tag "${targets[$i]}" "${STABLE_IMAGES[$i]}" || return 1
  done

  # API 镜像入口会在启动服务前执行 migrate up；这里保持 MIGRATING 状态，
  # 直到新容器成功启动，再进入健康检查阶段。
  CURRENT_STAGE="MIGRATING"
  if [[ "$recreate_netmgrd" == true ]]; then
    compose up -d --no-deps --force-recreate "${SERVICES[@]}" || { CURRENT_MESSAGE="启动新版本容器失败"; return 1; }
  else
    compose up -d --no-deps "${SERVICES[@]}" || { CURRENT_MESSAGE="启动新版本容器失败"; return 1; }
  fi
  reattach_api_extra_networks strict || return 1
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

validate_version_string() {
  local v="$1"
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9._-]+)?$ && "$v" != *..* ]]
}

# 宿主机执行器独立 Ed25519 验签（fail-closed）：
#   验证包内 manifest.sig（base64 单行 64 字节 Ed25519 签名）覆盖 manifest.json 原始字节；
#   若 manifest.json 声明 files_manifest_sha256，则同步校验其与 files 紧凑 JSON 摘要一致。
#   信任根为内置 WDSP_RELEASE_PUBKEY_PEM；仅显式 CLI --test-pubkey 在非生产配置下可替换测试公钥。
verify_package_signature() {
  local package_root="$1" manifest="$2"
  local sig_file="$package_root/manifest.sig"
  local pub_tmp="" raw_sig="" pub_path="" verify_err=""
  if [[ ! -f "$sig_file" || -L "$sig_file" ]]; then
    CURRENT_MESSAGE="升级包缺少 Ed25519 签名（manifest.sig），宿主机执行器拒绝加载或切换镜像"
    return 1
  fi
  if [[ ! -f "$manifest" || -L "$manifest" ]]; then
    CURRENT_MESSAGE="升级包 manifest.json 无效或为符号链接"
    return 1
  fi
  raw_sig="$(mktemp "${STATE_DIR:-${TMPDIR:-/tmp}}/.sig.XXXXXX")"
  if ! python3 - "$sig_file" "$raw_sig" <<'PY'
import base64, pathlib, sys
sig_path, out_path = sys.argv[1:]
text = pathlib.Path(sig_path).read_text(encoding="ascii").strip()
if not text or "\n" in text or "\r" in text:
    raise SystemExit("manifest.sig 必须为单行 base64")
raw = base64.b64decode(text.encode("ascii"), validate=True)
if len(raw) != 64:
    raise SystemExit("manifest.sig 解码长度非 64 字节 Ed25519 签名")
pathlib.Path(out_path).write_bytes(raw)
PY
  then
    rm -f "$raw_sig"
    CURRENT_MESSAGE="升级包 manifest.sig 格式非法（期望单行 base64 64 字节 Ed25519 签名）"
    return 1
  fi

  if [[ -n "${TEST_PUBKEY_FILE:-}" ]]; then
    pub_path="$TEST_PUBKEY_FILE"
  else
    local default_pubkey="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJBzjZs04R6NVLDuKoJsViPuBEGlo70z/zpnKi6ZHq2s=
-----END PUBLIC KEY-----"
    pub_tmp="$(mktemp "${STATE_DIR:-${TMPDIR:-/tmp}}/.pub.XXXXXX")"
    chmod 0600 "$pub_tmp"
    printf '%s\n' "${WDSP_RELEASE_PUBKEY_PEM:-$default_pubkey}" > "$pub_tmp"
    pub_path="$pub_tmp"
  fi

  if ! openssl pkeyutl -verify -pubin -inkey "$pub_path" -rawin -in "$manifest" -sigfile "$raw_sig" >/dev/null 2>&1; then
    rm -f "$raw_sig" ${pub_tmp:+"$pub_tmp"}
    CURRENT_MESSAGE="升级包 Ed25519 验签失败（manifest.json 与 manifest.sig 不匹配或非官方签发）"
    return 1
  fi
  rm -f "$raw_sig" ${pub_tmp:+"$pub_tmp"}

  # 若 manifest 含 files_manifest_sha256，校验其与 files 紧凑序列化摘要字节一致
  if ! verify_err="$(python3 - "$manifest" <<'PY' 2>&1
import hashlib, json, pathlib, re, sys
m = json.loads(pathlib.Path(sys.argv[1]).read_bytes().decode("utf-8"))
if "files_manifest_sha256" in m and m["files_manifest_sha256"] is not None:
    want = m["files_manifest_sha256"]
    if not isinstance(want, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", want):
        raise SystemExit("manifest.files_manifest_sha256 格式非法")
    files = m.get("files")
    if not isinstance(files, list) or not files:
        raise SystemExit("manifest.files 缺失或为空")
    normalized = [
        {"path": item["path"], "sha256": item["sha256"], "size": item["size"]}
        for item in files
    ]
    compact = json.dumps(normalized, separators=(",", ":"), ensure_ascii=False)
    actual = hashlib.sha256(compact.encode("utf-8")).hexdigest()
    if actual.lower() != want.lower():
        raise SystemExit("manifest.files_manifest_sha256 摘要不匹配")
PY
  )"; then
    CURRENT_MESSAGE="${verify_err:-升级包 files_manifest_sha256 校验失败}"
    return 1
  fi
  return 0
}

resolve_image_delta_helper() {
  local self_dir cand owner mode
  if [[ -n "${IMAGE_DELTA_HELPER:-}" ]]; then
    cand="$IMAGE_DELTA_HELPER"
  else
    self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P)" || return 1
    if [[ -f "$self_dir/jiuzhang-image-delta.py" ]]; then
      cand="$self_dir/jiuzhang-image-delta.py"
    elif [[ -f "$self_dir/image-delta.py" ]]; then
      cand="$self_dir/image-delta.py"
    elif [[ -f /usr/local/libexec/jiuzhang-image-delta.py ]]; then
      cand=/usr/local/libexec/jiuzhang-image-delta.py
    else
      CURRENT_MESSAGE="宿主机缺少镜像层差量重建工具（jiuzhang-image-delta.py），请重新运行 install-executor.sh"
      return 1
    fi
  fi
  [[ -f "$cand" && ! -L "$cand" ]] || { CURRENT_MESSAGE="差量重建工具不存在或为符号链接: $cand"; return 1; }
  if [[ "${CONFIG_FILE:-}" == "/etc/jiuzhang/upgrade-executor.conf" ]]; then
    owner="$(stat -c '%u' "$cand" 2>/dev/null || echo "")"
    mode="$(stat -c '%a' "$cand" 2>/dev/null || echo "")"
    if [[ "$owner" != "0" || ! "$mode" =~ ^[0-7]{3,4}$ ]] || (( (0$mode & 022) != 0 )); then
      CURRENT_MESSAGE="差量重建工具属主或权限不安全: $cand"
      return 1
    fi
  fi
  printf '%s\n' "$cand"
}

# 功能升级包（package_type=upgrade，build-upgrade-pack.sh 产物）：
#   支持全 11 个自研容器组件（api/web/gateway/netmgrd/mirrorcap/tproxyd/havipd/hasyncd/logrotator/containerops/pcapd）
#   以及完整组件镜像（full）与镜像层差量（layer-delta）两种交付形态：
#   逐组件验签、校验文件清单、差量基础层预检/重建并 docker load → 启动契约检查 → 统一 retag → compose up -d；
#   pcapd（request-pcap）与 hasyncd（ha-sync）均按各自 profile 守卫：原主机未运行时仅更新镜像标签，绝不擅自启动。
# 失败回滚语义沿用 runtime-patch（retag 回退）；新组件额外摘除片段并删除新镜像标签。
process_upgrade_pack() {
  local package_root="$1" manifest="$2" version_from="$3" version_to="$4"
  local host_arch service target stable old i f rel expected_size expected_sha actual_size actual_sha
  local delta_helper="" delta_work actual_layers check_err apply_err base_tar recon_tar pcapd_cid pcapd_state hasyncd_cid hasyncd_state
  local -a delivery_modes=() base_layers_list=() regular_up=()
  local pcapd_up=false hasyncd_up=false
  PCAPD_SKIP_START=false
  HASYNCD_SKIP_START=false

  validate_version_string "$version_from" || { CURRENT_MESSAGE="起始版本号格式非法"; return 1; }
  validate_version_string "$version_to" || { CURRENT_MESSAGE="目标版本号格式非法"; return 1; }
  verify_package_signature "$package_root" "$manifest" || return 1

  # 可选纵深：构建器总是产出 SHA256SUMS，存在即校验（manifest.files 才是主校验）
  if [[ -f "$package_root/SHA256SUMS" ]]; then
    (cd "$package_root" && sha256sum -c SHA256SUMS >/dev/null) || { CURRENT_MESSAGE="包内校验和失败"; return 1; }
  fi
  jq -e --arg from "$version_from" --arg to "$version_to" '
    def allowed_comp:
      . == "api" or . == "web" or . == "gateway" or . == "netmgrd" or
      . == "mirrorcap" or . == "tproxyd" or . == "havipd" or . == "hasyncd" or
      . == "logrotator" or . == "containerops" or . == "pcapd";
    .components as $comps | .images as $imgs | .files as $files |
    (.format_version == 1 or .format_version == "1") and
    .product == "wdsp" and .package_type == "upgrade" and
    (.change_type == "feature" or .change_type == "bugfix") and
    .version_from == $from and .version_to == $to and .version == $to and
    (.arch | type == "string") and
    ($comps | type == "array" and length >= 1 and (unique | length) == length and
      (all(.[]; allowed_comp))) and
    ($imgs | type == "array" and length == ($comps | length)) and
    (all($imgs[]; (.component == .service) and
      (.service | allowed_comp) and
      (.image | type == "string" and test("^[A-Za-z0-9._:/-]+$")) and
      (.tar | type == "string" and test("^images/[A-Za-z0-9._-]+\\.tar\\.gz$")) and
      ((.delivery_mode // "full") as $dm |
        ($dm == "full") or
        ($dm == "layer-delta" and
          (.base_layers | type == "array" and length >= 1 and
            all(.[]; type == "string" and test("^sha256:[0-9a-f]{64}$"))))) and
      ((.diff_ids == null) or
        (.diff_ids | type == "array" and
          all(.[]; type == "string" and test("^sha256:[0-9a-f]{64}$")))))) and
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
  mapfile -t delivery_modes < <(jq -r '.images[] | (.delivery_mode // "full")' "$manifest")
  mapfile -t base_layers_list < <(jq -c '.images[] | (.base_layers // [])' "$manifest")
  # 组件白名单（双重防御；jq 协议校验已约束）
  for service in "${SERVICES[@]}"; do
    case "$service" in
      api|web|gateway|netmgrd|mirrorcap|tproxyd|havipd|hasyncd|logrotator|containerops|pcapd) ;;
      *) CURRENT_MESSAGE="拒绝未知组件: $service"; return 1 ;;
    esac
  done

  # 新组件首次部署：宿主 compose（含已并入片段）缺失的服务须由包内片段恰好补齐
  mapfile -t compose_services < <(compose config --services)
  declare -a pcapd_profile_services=()
  if printf '%s\n' "${SERVICES[@]}" | grep -Fxq pcapd; then
    mapfile -t pcapd_profile_services < <(compose --profile request-pcap config --services 2>/dev/null || true)
  fi
  declare -a hasyncd_profile_services=()
  if printf '%s\n' "${SERVICES[@]}" | grep -Fxq hasyncd; then
    mapfile -t hasyncd_profile_services < <(compose --profile ha-sync config --services 2>/dev/null || true)
  fi
  declare -a missing=()
  local found c
  for service in "${SERVICES[@]}"; do
    found=0
    for c in "${compose_services[@]}"; do [[ "$c" == "$service" ]] && { found=1; break; }; done
    if ((found == 0)) && [[ "$service" == pcapd ]]; then
      for c in ${pcapd_profile_services[@]+"${pcapd_profile_services[@]}"}; do [[ "$c" == "pcapd" ]] && { found=1; break; }; done
    fi
    if ((found == 0)) && [[ "$service" == hasyncd ]]; then
      for c in ${hasyncd_profile_services[@]+"${hasyncd_profile_services[@]}"}; do [[ "$c" == "hasyncd" ]] && { found=1; break; }; done
    fi
    ((found == 1)) || missing+=("$service")
  done
  if ((${#missing[@]} > 0)); then
    local fragment="$package_root/compose/upgrade-services.yml"
    [[ -f "$fragment" ]] || { CURRENT_MESSAGE="升级包缺少新组件 compose 片段（缺失服务: ${missing[*]}）"; return 1; }
    local of merged_before merged_after before_services after_services added
    local args=(-f "$COMPOSE_FILE")
    local profile_args=()
    if printf '%s\n' "${missing[@]}" | grep -Fxq hasyncd; then
      profile_args+=(--profile ha-sync)
    fi
    if printf '%s\n' "${missing[@]}" | grep -Fxq pcapd; then
      profile_args+=(--profile request-pcap)
    fi
    for of in "$OVERRIDES_DIR"/*.yml; do
      [[ -e "$of" ]] || continue
      args+=(-f "$of")
    done
    merged_before="$(docker compose "${args[@]}" ${profile_args[@]+"${profile_args[@]}"} --env-file "$ENV_FILE" config --format json 2>/dev/null)" \
      || { CURRENT_MESSAGE="现有 compose 配置解析失败"; return 1; }
    merged_after="$(docker compose "${args[@]}" -f "$fragment" ${profile_args[@]+"${profile_args[@]}"} --env-file "$ENV_FILE" config --format json 2>/dev/null)" \
      || { CURRENT_MESSAGE="新组件 compose 片段无法并入解析"; return 1; }
    before_services="$(printf '%s' "$merged_before" | jq -r '.services | keys[]' | LC_ALL=C sort)"
    after_services="$(printf '%s' "$merged_after" | jq -r '.services | keys[]' | LC_ALL=C sort)"
    added="$(comm -13 <(printf '%s\n' "$before_services") <(printf '%s\n' "$after_services"))"
    [[ "$added" == "$(printf '%s\n' "${missing[@]}" | LC_ALL=C sort)" ]] \
      || { CURRENT_MESSAGE="compose 片段新增服务与缺失服务不一致"; return 1; }
    # 片段不得修改任何既有服务的任何字段（严格全量规范化 JSON 相等）
    if ! jq -ne --argjson before "$merged_before" --argjson after "$merged_after" '
      ($before.services | keys) as $existing |
      all($existing[]; $before.services[.] == $after.services[.])
    ' >/dev/null; then
      CURRENT_MESSAGE="compose 片段试图修改既有服务定义（禁止改写任何字段）"
      return 1
    fi
    # 新服务镜像必须与 manifest 声明一致，且禁止提权/宿主机命名空间/危险挂载/越权能力
    local sec_err="" merged_after_tmp=""
    merged_after_tmp="$(mktemp "$STATE_DIR/.merged-after.XXXXXX")"
    printf '%s' "$merged_after" > "$merged_after_tmp"
    if ! sec_err="$(python3 - "$manifest" "$added" "$merged_after_tmp" <<'PY' 2>&1
import json, pathlib, sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
added = [line.strip() for line in sys.argv[2].splitlines() if line.strip()]
merged_after = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
services = merged_after.get("services") or {}

allowed_caps = {
    "netmgrd": {"NET_RAW", "NET_ADMIN"},
    "havipd": {"NET_ADMIN", "NET_RAW", "NET_BROADCAST"},
    "hasyncd": set(),
    "mirrorcap": {"NET_RAW", "NET_ADMIN", "SETUID", "SETGID", "SETPCAP"},
    "tproxyd": set(),
    "logrotator": set(),
    "pcapd": {"NET_RAW", "SETUID", "SETGID"},
    "gateway": {"NET_BIND_SERVICE", "SETUID", "SETGID", "SETPCAP"},
    "api": set(),
    "web": set(),
}
forbidden_bind_prefixes = (
    "/etc", "/proc", "/sys", "/dev", "/boot", "/root",
    "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/var/run", "/run", "/var", "/opt", "/home",
)
manifest_images = {item["service"]: item["image"] for item in manifest.get("images", [])}

for name in added:
    svc = services.get(name)
    if not isinstance(svc, dict):
        raise SystemExit(f"新增服务定义异常: {name}")
    if svc.get("image") != manifest_images.get(name):
        raise SystemExit(f"新服务 {name} 的 compose 镜像与 manifest 声明不一致")
    if svc.get("privileged") is True:
        raise SystemExit(f"拒绝新增服务 {name} 启用 privileged")
    for ns_field in ("pid", "ipc", "uts", "userns_mode", "cgroup"):
        val = svc.get(ns_field)
        if val:
            raise SystemExit(f"拒绝新增服务 {name} 使用宿主/共享命名空间字段 {ns_field}={val}")
    if svc.get("devices"):
        raise SystemExit(f"拒绝新增服务 {name} 挂载宿主机设备")
    for opt in (svc.get("security_opt") or []):
        opt_l = str(opt).lower()
        if "unconfined" in opt_l or "label:disable" in opt_l:
            raise SystemExit(f"拒绝新增服务 {name} 弱化安全配置: {opt}")
    caps = {str(c).upper().removeprefix("CAP_") for c in (svc.get("cap_add") or [])}
    allowed = allowed_caps.get(name, set())
    disallowed = sorted(caps - allowed)
    if disallowed:
        raise SystemExit(f"拒绝新增服务 {name} 申请越权 capability: {','.join(disallowed)}")
    for vol in (svc.get("volumes") or []):
        src = ""
        vtype = ""
        if isinstance(vol, dict):
            vtype = str(vol.get("type") or "")
            src = str(vol.get("source") or "")
        elif isinstance(vol, str):
            src = vol.split(":", 1)[0]
            if src.startswith("/") or src.startswith("."):
                vtype = "bind"
        if vtype == "bind" or src.startswith("/") or "docker.sock" in src:
            norm = "/" + src.lstrip("/") if src.startswith("/") else src
            norm_stripped = norm.rstrip("/") or "/"
            if norm_stripped == "/" or ".." in pathlib.PurePosixPath(norm).parts or "docker.sock" in norm:
                raise SystemExit(f"拒绝新增服务 {name} 绑定宿主机根路径或敏感路径: {src}")
            if any(norm_stripped == p or norm_stripped.startswith(p + "/") for p in forbidden_bind_prefixes):
                raise SystemExit(f"拒绝新增服务 {name} 绑定宿主机系统路径: {src}")
PY
    )"; then
      rm -f "$merged_after_tmp"
      CURRENT_MESSAGE="${sec_err:-compose 片段安全校验失败}"
      return 1
    fi
    rm -f "$merged_after_tmp"
    # 幂等安装片段：同名文件内容必须一致
    local target_override="$OVERRIDES_DIR/upgrade-${version_to}.yml"
    [[ ! -L "$target_override" ]] || { CURRENT_MESSAGE="compose 片段目标路径为符号链接"; return 1; }
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
    if [[ "$service" == pcapd ]]; then
      stable="$(compose --profile request-pcap config --format json | jq -er '.services.pcapd.image')" || return 1
      pcapd_cid="$(compose --profile request-pcap ps -q pcapd 2>/dev/null || true)"
      pcapd_state=""
      if [[ "$pcapd_cid" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        pcapd_state="$(docker inspect --format '{{.State.Status}}' "$pcapd_cid" 2>/dev/null || true)"
      fi
      [[ "$pcapd_state" == running ]] || PCAPD_SKIP_START=true
    elif [[ "$service" == hasyncd ]]; then
      stable="$(compose --profile ha-sync config --format json | jq -er '.services.hasyncd.image')" || return 1
      hasyncd_cid="$(compose --profile ha-sync ps -q hasyncd 2>/dev/null || true)"
      hasyncd_state=""
      if [[ "$hasyncd_cid" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        hasyncd_state="$(docker inspect --format '{{.State.Status}}' "$hasyncd_cid" 2>/dev/null || true)"
      fi
      [[ "$hasyncd_state" == running ]] || HASYNCD_SKIP_START=true
    else
      stable="$(compose config --format json | jq -er --arg s "$service" '.services[$s].image')" || return 1
    fi
    old=""
    if [[ " ${NEW_SERVICES[*]-} " == *" $service "* ]]; then
      # 新组件：compose 片段镜像即目标标签（已校验一致），无旧镜像可回退
      [[ "$stable" == "$target" ]] || { CURRENT_MESSAGE="新服务 $service 镜像口径异常"; return 1; }
    else
      old="$(docker image inspect "$stable" --format '{{.Id}}' 2>/dev/null)" || { CURRENT_MESSAGE="无法读取当前 $service 镜像"; return 1; }
    fi
    STABLE_IMAGES+=("$stable"); OLD_IDS+=("$old")
  done

  # 层差量预检（fail-closed：在加载或切换任何镜像之前校验宿主机基础层全部存在）
  for i in "${!targets[@]}"; do
    [[ "${delivery_modes[$i]}" == "layer-delta" ]] || continue
    service="${SERVICES[$i]}"
    if [[ " ${NEW_SERVICES[*]-} " == *" $service "* ]]; then
      CURRENT_MESSAGE="新组件 $service 不存在旧镜像，拒绝使用 layer-delta 差量升级包"
      return 1
    fi
    if [[ -z "$delta_helper" ]]; then
      delta_helper="$(resolve_image_delta_helper)" || return 1
    fi
    actual_layers="$(docker image inspect "${STABLE_IMAGES[$i]}" --format '{{json .RootFS.Layers}}' 2>/dev/null)" \
      || { CURRENT_MESSAGE="无法读取宿主机当前 $service 镜像层清单"; return 1; }
    if ! check_err="$(python3 "$delta_helper" check-base \
      --required-base-layers-json "${base_layers_list[$i]}" \
      --actual-layers-json "$actual_layers" 2>&1)"; then
      CURRENT_MESSAGE="宿主机当前 $service 镜像不满足差量升级基础层要求（期望起始版本 ${version_from}）：${check_err}"
      return 1
    fi
  done

  delta_work="${work:-$(dirname "$package_root")}"
  for i in "${!targets[@]}"; do
    service="${SERVICES[$i]}"
    if [[ "${delivery_modes[$i]}" == "layer-delta" ]]; then
      base_tar="$delta_work/base-${service}.tar"
      recon_tar="$delta_work/reconstructed-${service}.tar"
      rm -f "$base_tar" "$recon_tar"
      if ! docker save "${STABLE_IMAGES[$i]}" -o "$base_tar" >/dev/null 2>&1; then
        rm -f "$base_tar" "$recon_tar"
        CURRENT_MESSAGE="导出宿主机基准镜像失败（供层差量重建）: ${service}"
        return 1
      fi
      if ! apply_err="$(python3 "$delta_helper" apply \
        --delta-tar "$package_root/${tars[$i]}" \
        --base-tar "$base_tar" \
        --expected-base-layers-json "${base_layers_list[$i]}" \
        --expected-image "${targets[$i]}" \
        --output "$recon_tar" 2>&1)"; then
        rm -f "$base_tar" "$recon_tar"
        CURRENT_MESSAGE="差量镜像重建失败（${service}）：${apply_err}"
        return 1
      fi
      rm -f "$base_tar"
      if ! docker load -i "$recon_tar" >/dev/null; then
        rm -f "$recon_tar"
        CURRENT_MESSAGE="加载重建镜像失败: ${tars[$i]}"
        return 1
      fi
      rm -f "$recon_tar"
    else
      gzip -dc "$package_root/${tars[$i]}" | docker load >/dev/null \
        || { CURRENT_MESSAGE="加载镜像失败: ${tars[$i]}"; return 1; }
    fi
  done
  for i in "${!targets[@]}"; do
    docker image inspect "${targets[$i]}" >/dev/null 2>&1 || { CURRENT_MESSAGE="包内缺少镜像 ${targets[$i]}"; return 1; }
  done
  for i in "${!targets[@]}"; do
    [[ "${SERVICES[$i]}" == gateway ]] || continue
    validate_gateway_start_contract "${targets[$i]}" || return 1
  done
  capture_api_extra_networks

  # gateway 重建会使 network_mode: service:gateway 的 sidecar（netmgrd/havipd）失去原网络命名空间。
  # 即使升级包不更新其镜像，也要把现有服务纳入同次重建、健康检查与回滚。
  if printf '%s\n' "${SERVICES[@]}" | grep -Fxq gateway; then
    local _gw_dep
    for _gw_dep in netmgrd havipd; do
      if ! printf '%s\n' "${SERVICES[@]}" | grep -Fxq "$_gw_dep" \
        && printf '%s\n' "${compose_services[@]}" | grep -Fxq "$_gw_dep"; then
        stable="$(compose config --format json | jq -er --arg s "$_gw_dep" '.services[$s].image | select(type == "string" and length > 0)')" \
          || { CURRENT_MESSAGE="无法读取 $_gw_dep 的 compose 镜像"; return 1; }
        old="$(docker image inspect "$stable" --format '{{.Id}}' 2>/dev/null)" \
          || { CURRENT_MESSAGE="无法读取当前 $_gw_dep 镜像"; return 1; }
        SERVICES+=("$_gw_dep")
        STABLE_IMAGES+=("$stable")
        OLD_IDS+=("$old")
      fi
    done
  fi

  IMAGE_SWITCH_STARTED=true
  for i in "${!targets[@]}"; do
    docker tag "${targets[$i]}" "${STABLE_IMAGES[$i]}" || return 1
  done

  # API 镜像入口会在启动服务前执行 migrate up；这里保持 MIGRATING 状态，
  # 直到新容器成功启动，再进入健康检查阶段。强制重建覆盖镜像未变化的 netmgrd/havipd。
  CURRENT_STAGE="MIGRATING"
  for service in "${SERVICES[@]}"; do
    if [[ "$service" == pcapd ]]; then
      [[ "$PCAPD_SKIP_START" == true ]] || pcapd_up=true
    elif [[ "$service" == hasyncd ]]; then
      [[ "$HASYNCD_SKIP_START" == true ]] || hasyncd_up=true
    else
      regular_up+=("$service")
    fi
  done
  if ((${#regular_up[@]} > 0)); then
    compose up -d --no-deps --force-recreate "${regular_up[@]}" || { CURRENT_MESSAGE="启动新版本容器失败"; return 1; }
  fi
  if [[ "$pcapd_up" == true ]]; then
    compose --profile request-pcap up -d --no-deps --force-recreate pcapd || { CURRENT_MESSAGE="启动新版本 pcapd 容器失败"; return 1; }
  fi
  if [[ "$hasyncd_up" == true ]]; then
    compose --profile ha-sync up -d --no-deps --force-recreate hasyncd || { CURRENT_MESSAGE="启动新版本 hasyncd 容器失败"; return 1; }
  fi
  reattach_api_extra_networks strict || return 1
  CURRENT_STAGE="VERIFYING"
  wait_selected_services || return 1
  return 0
}

exec 9>"$LOCK_FILE"
flock -n 9 || exit 0
shopt -s nullglob
for queued in "$JOBS_DIR"/*.json; do
  [[ ! -L "$queued" && -f "$queued" ]] || continue
  processing="${queued%.json}.processing"
  [[ ! -L "$processing" ]] || continue
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
    rm -rf "$WORK_DIR/$CURRENT_JOB"
  fi
done
