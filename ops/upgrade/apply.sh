#!/usr/bin/env bash
# apply.sh —— 完整升级：健康预检、已验证备份、全组件切换、健康确认与失败回滚。
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

STATE_FILE="$SCRIPT_DIR/.upgrade-state.env"
FULL_UPGRADE=false
IMAGES_DIR=""
IMAGES_TAR=""
NEW_COMPOSE_FILE=""
SERVER_IMAGE=""
GATEWAY_IMAGE=""
USER=""
TIMEOUT=600
PREVIOUS_COMPOSE_FILE=""
CURRENT_LINK=""
SERVICES=()
TARGET_IMAGES=()
OLD_IMAGES=()
OLD_IDS=()
API_EXTRA_NETWORKS=()
RULES_VOLUME_NAME=""
RULES_PREVIOUS_CURRENT_TARGET=""
SWITCH_STARTED=false

usage() {
  cat <<'EOF'
用法: apply.sh [选项]

  --server-image IMG       目标 API 镜像；完整升级缺省取目标 Compose 的实际镜像
  --gateway-image IMG      目标网关镜像；完整升级缺省取目标 Compose 的实际镜像
  --images-tar FILE        可选的合并镜像 tar
  --images-dir DIR         完整包的 images/ 目录，逐个加载其中的 tar
  --new-compose-file FILE  目标 Compose；gateway 启动契约变化时必填
  --full                   完整升级，要求并更新 api/web/gateway/netmgrd/logrotator/containerops
  --previous-compose-file FILE
                           原 Compose，供自动/手工回滚恢复原 release 入口
  --current-link FILE      可选的 current 符号链接，只在全部健康后由调用方切换
  -u, --user USER          管理员用户名（默认读取 .env 的 INITIAL_ADMIN_USERNAME，缺省 admin）
  --api-url URL            管理 API（默认 http://127.0.0.1:18081）
  -c, --compose-file FILE  当前 Compose（默认 docker-compose.yml）
  -e, --env-file FILE      当前及目标环境变量文件（默认 .env）
  --timeout SEC            各等待阶段超时（默认 600）
  -h, --help               显示帮助

JZ_ADMIN_PASSWORD 可预置管理员口令，缺省时交互读取。备份未验证成功前绝不加载/切换镜像。
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-image) SERVER_IMAGE="${2:-}"; shift 2 ;;
    --gateway-image) GATEWAY_IMAGE="${2:-}"; shift 2 ;;
    --images-tar) IMAGES_TAR="${2:-}"; shift 2 ;;
    --images-dir) IMAGES_DIR="${2:-}"; shift 2 ;;
    --new-compose-file) NEW_COMPOSE_FILE="${2:-}"; shift 2 ;;
    --full) FULL_UPGRADE=true; shift ;;
    --previous-compose-file) PREVIOUS_COMPOSE_FILE="${2:-}"; shift 2 ;;
    --current-link) CURRENT_LINK="${2:-}"; shift 2 ;;
    -u|--user) USER="${2:-}"; shift 2 ;;
    --api-url) JZ_API_BASE="${2:-}"; shift 2 ;;
    -c|--compose-file) JZ_COMPOSE_FILE="${2:-}"; shift 2 ;;
    -e|--env-file) JZ_ENV_FILE="${2:-}"; shift 2 ;;
    --timeout) TIMEOUT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done
[[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]] || { log_err "--timeout 必须为正整数"; exit 2; }
for cmd in docker curl jq base64 timeout cmp mktemp; do require_cmd "$cmd"; done
[[ -f "$JZ_COMPOSE_FILE" && -f "$JZ_ENV_FILE" ]] || die "当前 Compose 或 env 文件不存在"
JZ_COMPOSE_FILE="$(cd "$(dirname "$JZ_COMPOSE_FILE")" && pwd -P)/$(basename "$JZ_COMPOSE_FILE")"
JZ_ENV_FILE="$(cd "$(dirname "$JZ_ENV_FILE")" && pwd -P)/$(basename "$JZ_ENV_FILE")"
[[ -n "$USER" ]] || USER="$(resolve_default_admin_user "$JZ_ENV_FILE")"

render_compose() { docker compose -f "$1" --env-file "$2" config --format json 2>/dev/null; }
compose_service_image() { jq -er --arg service "$2" '.services[$service].image | select(type == "string" and length > 0)' <<<"$1"; }
image_entrypoint() {
  local raw
  raw="$(docker image inspect "$1" --format '{{json .Config.Entrypoint}}' 2>/dev/null)" || return 1
  jq -er 'if type == "array" and length == 1 and (.[0] | type == "string") then .[0] else empty end' <<<"$raw"
}
assert_bind_gateway_compose() {
  jq -e '.services.gateway as $g | $g.user == "0:0" and
    ($g.entrypoint == null or $g.entrypoint == ["/usr/local/bin/wdsp-gateway-bind"]) and
    $g.cap_drop == ["ALL"] and
    (($g.cap_add // []) | sort == (["NET_BIND_SERVICE", "SETUID", "SETGID", "SETPCAP"] | sort)) and
    (($g.security_opt // []) | index("no-new-privileges:true") != null)' <<<"$1" >/dev/null
}
legacy_gateway_compose_is_safe() {
  jq -e '.services.gateway as $g |
    ($g.user == null or $g.user == "1000:1000" or $g.user == "caddy" or $g.user == "caddy:caddy") and
    ($g.entrypoint == null or $g.entrypoint == ["/usr/local/bin/docker-entrypoint.sh"]) and
    ($g.cap_add == null or $g.cap_add == ["NET_BIND_SERVICE"]) and
    ($g.cap_drop == null or $g.cap_drop == ["ALL"])' <<<"$1" >/dev/null
}
array_encode() { jq -cn '$ARGS.positional' --args "$@" | base64 | tr -d '\r\n'; }
schema_version() {
  local pg="$1"
  docker exec "$pg" sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT COALESCE(MAX(version),0) FROM schema_migrations"' 2>/dev/null
}
ensure_owner_1000() {
  [[ "$(id -u)" == "0" ]] || return 0
  chown 1000:1000 "$1"
}
file_mode_octal() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null || true
}
compose_volume_source() {
  local compose_json="$1" service="$2" target="$3"
  jq -r --arg s "$service" --arg t "$target" '
    [.services[$s].volumes[]? | select(.type == "volume" and .target == $t) | .source]
    | if length == 1 then .[0] | select(type == "string" and length > 0) else empty end
  ' <<<"$compose_json" 2>/dev/null || true
}
compose_volume_name() {
  local compose_json="$1" vol_key="$2"
  jq -r --arg k "$vol_key" '
    (.volumes[$k].name // empty) as $explicit |
    (.name // empty) as $proj |
    if ($explicit | length) > 0 then $explicit
    elif ($proj | length) > 0 then ($proj + "_" + $k)
    else $k end
  ' <<<"$compose_json" 2>/dev/null || true
}
container_mount_source() {
  local cid="$1" dest="$2"
  [[ "$cid" =~ ^[a-fA-F0-9]+$ ]] || return 0
  docker inspect --format '{{json .Mounts}}' "$cid" 2>/dev/null \
    | jq -r --arg dst "$dest" '
      [.[]? | select(.Destination == $dst) | .Source]
      | if length == 1 then .[0] | select(type == "string" and startswith("/")) else empty end
    ' 2>/dev/null || true
}
copy_cert_file_to_vol() {
  local src="$1" dst_dir="$2" name="$3"
  local dest="$dst_dir/$name" tmp="" cur_mode=""
  [[ ! -L "$src" && -f "$src" && -s "$src" ]] || return 1
  [[ ! -L "$dest" ]] || die "目标证书卷中存在符号链接: ${name}（未切换容器）"
  if [[ -e "$dest" ]]; then
    [[ -f "$dest" ]] && cmp -s "$src" "$dest" \
      || die "目标证书卷已存在同名但内容不同的文件: ${name}，拒绝覆盖（未切换容器）"
    ensure_owner_1000 "$dest" || die "无法设置证书文件属主: $dest"
    cur_mode="$(file_mode_octal "$dest")"
    if [[ "$name" == *.key ]]; then
      [[ "$cur_mode" == "600" ]] || chmod 0600 "$dest" || die "无法收紧私钥权限: $dest"
    elif [[ "$cur_mode" != "600" && "$cur_mode" != "644" ]]; then
      chmod 0600 "$dest" || die "无法修正证书权限: $dest"
    fi
    return 2
  fi
  tmp="$(mktemp "$dst_dir/.wdsp-cert-migrate.XXXXXX")" || die "无法在证书卷创建临时文件: $dst_dir"
  if ! cat "$src" > "$tmp" || ! ensure_owner_1000 "$tmp" || ! chmod 0600 "$tmp" || ! mv -f "$tmp" "$dest"; then
    rm -f -- "$tmp"
    die "迁移证书文件失败: ${name}（未切换容器）"
  fi
  return 0
}
migrate_gateway_certs_if_needed() {
  local target_gw_vol target_api_vol target_vol_name project_name
  local old_gw_vol old_api_vol old_vol_name=""
  target_gw_vol="$(compose_volume_source "$TARGET_COMPOSE_JSON" gateway /etc/caddy/certs)"
  target_api_vol="$(compose_volume_source "$TARGET_COMPOSE_JSON" api /app/runtime/certificates)"
  [[ -n "$target_gw_vol" && "$target_gw_vol" == "$target_api_vol" ]] || return 0

  target_vol_name="$(compose_volume_name "$TARGET_COMPOSE_JSON" "$target_gw_vol")"
  [[ -n "$target_vol_name" ]] || die "无法解析目标证书卷名（compose 卷键: ${target_gw_vol}）"
  project_name="$(jq -r '.name // empty' <<<"$TARGET_COMPOSE_JSON")"

  old_gw_vol="$(compose_volume_source "$OLD_COMPOSE_JSON" gateway /etc/caddy/certs)"
  old_api_vol="$(compose_volume_source "$OLD_COMPOSE_JSON" api /app/runtime/certificates)"
  if [[ -n "$old_gw_vol" && "$old_gw_vol" == "$old_api_vol" ]]; then
    old_vol_name="$(compose_volume_name "$OLD_COMPOSE_JSON" "$old_gw_vol")"
  fi
  # 已在使用同一共享证书卷时无需跨卷迁移
  [[ -n "$old_vol_name" && "$old_vol_name" == "$target_vol_name" ]] && return 0

  if ! docker volume inspect "$target_vol_name" >/dev/null 2>&1; then
    local create_args=()
    [[ -z "$project_name" ]] || create_args+=(--label "com.docker.compose.project=$project_name")
    create_args+=(--label "com.docker.compose.volume=$target_gw_vol")
    docker volume create "${create_args[@]}" "$target_vol_name" >/dev/null \
      || die "创建目标证书卷失败: ${target_vol_name}（未切换容器）"
  fi
  local dst
  dst="$(docker volume inspect --format '{{.Mountpoint}}' "$target_vol_name" 2>/dev/null || true)"
  [[ -n "$dst" && "$dst" == /* && -d "$dst" && ! -L "$dst" ]] \
    || die "无法解析目标证书卷挂载目录: ${target_vol_name}（未切换容器）"
  ensure_owner_1000 "$dst" || die "无法设置目标证书卷属主为 1000:1000: $dst"
  chmod 0700 "$dst" || die "无法设置目标证书卷权限: $dst"

  local old_api_id old_gw_id src_dirs=() candidate_dir old_rt_vol old_rt_name old_rt_mp old_gw_cert_dir
  old_api_id="$(docker compose -f "$OLD_COMPOSE_FILE" --env-file "$JZ_ENV_FILE" ps -q api 2>/dev/null || true)"
  old_gw_id="$(docker compose -f "$OLD_COMPOSE_FILE" --env-file "$JZ_ENV_FILE" ps -q gateway 2>/dev/null || true)"

  candidate_dir="$(container_mount_source "$old_api_id" /app/runtime/certificates)"
  if [[ -z "$candidate_dir" ]]; then
    old_rt_mp="$(container_mount_source "$old_api_id" /app/runtime)"
    if [[ -z "$old_rt_mp" ]]; then
      old_rt_vol="$(compose_volume_source "$OLD_COMPOSE_JSON" api /app/runtime)"
      if [[ -n "$old_rt_vol" ]]; then
        old_rt_name="$(compose_volume_name "$OLD_COMPOSE_JSON" "$old_rt_vol")"
        old_rt_mp="$(docker volume inspect --format '{{.Mountpoint}}' "$old_rt_name" 2>/dev/null || true)"
      fi
    fi
    [[ -z "$old_rt_mp" ]] || candidate_dir="$old_rt_mp/certificates"
  fi
  [[ -n "$candidate_dir" && "$candidate_dir" != "$dst" && -d "$candidate_dir" && ! -L "$candidate_dir" ]] \
    && src_dirs+=("$candidate_dir")

  old_gw_cert_dir="$(container_mount_source "$old_gw_id" /etc/caddy/certs)"
  if [[ -n "$old_gw_cert_dir" && "$old_gw_cert_dir" != "$dst" && "$old_gw_cert_dir" != "${candidate_dir:-}" && -d "$old_gw_cert_dir" && ! -L "$old_gw_cert_dir" ]]; then
    src_dirs+=("$old_gw_cert_dir")
  fi

  local migrated=0 src_dir entry base rc
  shopt -s nullglob
  for src_dir in "${src_dirs[@]}"; do
    for entry in "$src_dir"/*; do
      base="$(basename "$entry")"
      [[ "$base" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.(pem|key)$ ]] || continue
      [[ ! -L "$entry" && -f "$entry" && -s "$entry" ]] || continue
      rc=0
      copy_cert_file_to_vol "$entry" "$dst" "$base" || rc=$?
      [[ "$rc" -eq 0 ]] && migrated=$((migrated + 1))
    done
  done
  shopt -u nullglob

  # 按当前网关持久化 autosave.json 做 fail-closed 复核：避免新 gateway 启动后缺证书崩溃循环
  local old_cfg_mp old_cfg_vol old_cfg_name autosave verified_refs=0 ref rel
  old_cfg_mp="$(container_mount_source "$old_gw_id" /config)"
  if [[ -z "$old_cfg_mp" ]]; then
    old_cfg_vol="$(compose_volume_source "$OLD_COMPOSE_JSON" gateway /config)"
    if [[ -n "$old_cfg_vol" ]]; then
      old_cfg_name="$(compose_volume_name "$OLD_COMPOSE_JSON" "$old_cfg_vol")"
      old_cfg_mp="$(docker volume inspect --format '{{.Mountpoint}}' "$old_cfg_name" 2>/dev/null || true)"
    fi
  fi
  autosave="${old_cfg_mp:+$old_cfg_mp/caddy/autosave.json}"
  if [[ -n "$autosave" && -f "$autosave" && ! -L "$autosave" && -r "$autosave" ]]; then
    local autosave_refs
    autosave_refs="$(jq -r '
      [.apps.tls.certificates.load_files[]? | .certificate, .key]
      | map(select(type == "string" and startswith("/etc/caddy/certs/")))
      | unique[]
    ' "$autosave" 2>/dev/null)" || die "无法解析当前网关 autosave.json 的证书引用: ${autosave}（未切换容器）"
    while IFS= read -r ref; do
      [[ -n "$ref" ]] || continue
      rel="${ref#/etc/caddy/certs/}"
      [[ -n "$rel" && "$rel" != */* && "$rel" != "." && "$rel" != ".." ]] \
        || die "网关 autosave.json 含非法证书路径引用: ${ref}（未切换容器）"
      [[ -f "$dst/$rel" && ! -L "$dst/$rel" && -s "$dst/$rel" ]] \
        || die "目标证书卷 ${target_vol_name} 缺少当前网关配置引用的证书文件: ${rel}（未切换容器）"
      verified_refs=$((verified_refs + 1))
    done <<< "$autosave_refs"
  fi
  if (( migrated > 0 || verified_refs > 0 )); then
    log_info "已完成跨版本证书卷迁移与核验（卷: ${target_vol_name}，本次迁移 ${migrated} 个文件，autosave 核验 ${verified_refs} 项）"
  fi
}
verify_rules_anchors() {
  local dir="$1" rel
  [[ -d "$dir" && ! -L "$dir" ]] || return 1
  for rel in coraza.conf crs/crs-setup.conf jiuzhang/post-contrib-blocking.conf; do
    [[ -f "$dir/$rel" && ! -L "$dir/$rel" && -s "$dir/$rel" ]] || return 1
  done
  return 0
}
atomic_replace_symlink() {
  local target="$1" link_path="$2" parent tmp_link
  parent="$(dirname "$link_path")"
  tmp_link="$parent/.$(basename "$link_path").tmp.$$.$RANDOM"
  rm -f -- "$tmp_link"
  ln -s "$target" "$tmp_link" || return 1
  if [[ "$(id -u)" == "0" ]]; then
    chown -h 1000:1000 "$tmp_link" 2>/dev/null || true
  fi
  if mv -Tf "$tmp_link" "$link_path" 2>/dev/null; then
    return 0
  fi
  if mv -hf "$tmp_link" "$link_path" 2>/dev/null; then
    return 0
  fi
  if command -v python3 >/dev/null 2>&1 && python3 -c 'import os,sys; os.replace(sys.argv[1], sys.argv[2])' "$tmp_link" "$link_path" 2>/dev/null; then
    return 0
  fi
  rm -f -- "$tmp_link"
  return 1
}
resolve_target_builtin_rulepack_version() {
  local ver="" raw_tag=""
  if [[ -f "$TARGET_INSTALL_ROOT/manifest.json" ]]; then
    ver="$(jq -r '.version // empty' "$TARGET_INSTALL_ROOT/manifest.json" 2>/dev/null || true)"
  fi
  if [[ -z "$ver" && -f "$TARGET_INSTALL_ROOT/PRODUCT.txt" ]]; then
    ver="$(awk -F= '$1=="version"{print $2; exit}' "$TARGET_INSTALL_ROOT/PRODUCT.txt" 2>/dev/null || true)"
  fi
  if [[ -z "$ver" && -n "$SERVER_IMAGE" ]]; then
    raw_tag="${SERVER_IMAGE%%@*}"
    if [[ "$raw_tag" == *:* ]]; then
      ver="${raw_tag##*:}"
    fi
  fi
  ver="${ver#v}"
  ver="$(printf '%s' "$ver" | tr -c '0-9A-Za-z._-' '-' | sed 's/^-*//; s/-*$//')"
  [[ -n "$ver" && "$ver" =~ ^[0-9A-Za-z._-]+$ ]] || ver="0.0.0"
  printf 'builtin-%s\n' "$ver"
}
resolve_seed_rules_dir() {
  local cand
  for cand in "$TARGET_INSTALL_ROOT/gateway/rules" "$TARGET_INSTALL_ROOT/../gateway/rules"; do
    if [[ -d "$cand" && ! -L "$cand" ]] && verify_rules_anchors "$cand"; then
      printf '%s\n' "$cand"
      return 0
    fi
  done
  return 1
}
copy_rules_seed_dir() {
  local src="$1" dst="$2"
  mkdir -p "$dst" || return 1
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$src" "$dst" <<'PY' || return 1
import os, shutil, sys
src, dst = sys.argv[1], sys.argv[2]
for root, dirs, files in os.walk(src, followlinks=False):
    rel = os.path.relpath(root, src)
    target_root = dst if rel == "." else os.path.join(dst, rel)
    os.makedirs(target_root, mode=0o750, exist_ok=True)
    os.chmod(target_root, 0o750)
    # 跳过源目录内的符号链接目录，防止目录逃逸
    dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
    for name in files:
        sp = os.path.join(root, name)
        if os.path.islink(sp) or not os.path.isfile(sp):
            continue
        dp = os.path.join(target_root, name)
        shutil.copyfile(sp, dp)
        os.chmod(dp, 0o640)
PY
  else
    cp -R "$src/." "$dst/" || return 1
    find "$dst" -type l -delete || return 1
    find "$dst" -type d -exec chmod 0750 {} + || return 1
    find "$dst" -type f -exec chmod 0640 {} + || return 1
  fi
  if [[ "$(id -u)" == "0" ]]; then
    chown -R 1000:1000 "$dst" || return 1
  fi
  return 0
}
migrate_gateway_rules_volume() {
  local target_gw_vol target_api_vol target_vol_name project_name
  target_gw_vol="$(compose_volume_source "$TARGET_COMPOSE_JSON" gateway /etc/caddy/rules)"
  target_api_vol="$(compose_volume_source "$TARGET_COMPOSE_JSON" api /app/runtime/rules)"
  [[ -n "$target_gw_vol" && "$target_gw_vol" == "$target_api_vol" ]] || return 0

  target_vol_name="$(compose_volume_name "$TARGET_COMPOSE_JSON" "$target_gw_vol")"
  [[ -n "$target_vol_name" ]] || die "无法解析目标规则卷名（compose 卷键: ${target_gw_vol}）"
  project_name="$(jq -r '.name // empty' <<<"$TARGET_COMPOSE_JSON")"

  if ! docker volume inspect "$target_vol_name" >/dev/null 2>&1; then
    local create_args=()
    [[ -z "$project_name" ]] || create_args+=(--label "com.docker.compose.project=$project_name")
    create_args+=(--label "com.docker.compose.volume=$target_gw_vol")
    docker volume create "${create_args[@]}" "$target_vol_name" >/dev/null \
      || die "创建目标规则卷失败: ${target_vol_name}（未切换容器）"
  fi
  local dst
  dst="$(docker volume inspect --format '{{.Mountpoint}}' "$target_vol_name" 2>/dev/null || true)"
  [[ -n "$dst" && "$dst" == /* && -d "$dst" && ! -L "$dst" ]] \
    || die "无法解析目标规则卷挂载目录: ${target_vol_name}（未切换容器）"
  ensure_owner_1000 "$dst" || die "无法设置目标规则卷属主为 1000:1000: ${dst}"
  chmod 0750 "$dst" || die "无法设置目标规则卷权限: ${dst}"

  [[ ! -L "$dst/releases" ]] || die "目标规则卷 releases 路径为符号链接，拒绝迁移（未切换容器）"
  [[ ! -L "$dst/.staging" ]] || die "目标规则卷 .staging 路径为符号链接，拒绝迁移（未切换容器）"
  mkdir -p "$dst/releases" "$dst/.staging" || die "无法初始化目标规则卷目录: ${dst}（未切换容器）"
  ensure_owner_1000 "$dst/releases" && chmod 0750 "$dst/releases" || die "无法设置规则卷 releases 权限: ${dst}/releases"
  ensure_owner_1000 "$dst/.staging" && chmod 0750 "$dst/.staging" || die "无法设置规则卷 .staging 权限: ${dst}/.staging"

  local seed_dir builtin_ver
  seed_dir="$(resolve_seed_rules_dir)" || die "目标版本缺少有效内置规则种子目录（未切换容器）"
  builtin_ver="$(resolve_target_builtin_rulepack_version)"

  local stage_dir="$dst/.staging/seed-${builtin_ver}-$$.$RANDOM"
  local release_dir="$dst/releases/$builtin_ver"
  [[ ! -L "$release_dir" ]] || die "目标规则卷内置种子路径为符号链接: ${release_dir}（未切换容器）"
  rm -rf -- "$stage_dir"
  if ! copy_rules_seed_dir "$seed_dir" "$stage_dir"; then
    rm -rf -- "$stage_dir"
    die "复制内置规则种子到目标规则卷失败: ${target_vol_name}（未切换容器）"
  fi
  if ! verify_rules_anchors "$stage_dir"; then
    rm -rf -- "$stage_dir"
    die "目标内置规则种子缺少核心锚点文件（coraza.conf/crs-setup.conf/post-contrib-blocking.conf），未切换容器"
  fi
  if [[ -e "$release_dir" ]]; then
    local backup_old="$dst/.staging/old-${builtin_ver}-$$.$RANDOM"
    rm -rf -- "$backup_old"
    if ! mv "$release_dir" "$backup_old"; then
      rm -rf -- "$stage_dir"
      die "替换既有内置规则种子目录失败: ${release_dir}（未切换容器）"
    fi
    if ! mv "$stage_dir" "$release_dir"; then
      mv "$backup_old" "$release_dir" 2>/dev/null || true
      rm -rf -- "$stage_dir"
      die "原子落盘内置规则种子失败: ${release_dir}（未切换容器）"
    fi
    rm -rf -- "$backup_old"
  else
    if ! mv "$stage_dir" "$release_dir"; then
      rm -rf -- "$stage_dir"
      die "原子落盘内置规则种子失败: ${release_dir}（未切换容器）"
    fi
  fi

  # 防降级规则（§9.2）：若卷内已存在客户应用的日期规则包（releases/YYYYMMDD.N），
  # 仅旁路写入新系统 builtin-<ver> 快照，绝不覆盖 current 软链。
  local current_link="$dst/current"
  local cur_target="" preserved_customer=false
  if [[ -e "$current_link" && ! -L "$current_link" ]]; then
    die "目标规则卷 current 路径不是符号链接，拒绝覆盖（未切换容器）"
  fi
  if [[ -L "$current_link" ]]; then
    cur_target="$(readlink "$current_link")"
    if [[ "$cur_target" =~ ^releases/([0-9]{8}\.[0-9]{1,3})$ ]]; then
      verify_rules_anchors "$dst/$cur_target" \
        || die "目标规则卷 current 指向不完整的客户规则包快照: ${cur_target}（未切换容器）"
      preserved_customer=true
      log_info "目标规则卷已激活客户离线规则包（current -> ${cur_target}），已旁路写入内置种子 ${builtin_ver} 并保留客户规则包生效（防降级）"
    elif [[ "$cur_target" =~ ^releases/builtin-[0-9A-Za-z._-]+$ ]]; then
      if [[ "$cur_target" != "releases/$builtin_ver" ]]; then
        RULES_VOLUME_NAME="$target_vol_name"
        RULES_PREVIOUS_CURRENT_TARGET="$cur_target"
      fi
      atomic_replace_symlink "releases/$builtin_ver" "$current_link" \
        || die "原子更新目标规则卷 current 软链失败（未切换容器）"
    else
      die "目标规则卷 current 软链指向非法路径: ${cur_target}（未切换容器）"
    fi
  else
    atomic_replace_symlink "releases/$builtin_ver" "$current_link" \
      || die "创建目标规则卷 current 相对软链失败（未切换容器）"
  fi

  local final_target
  final_target="$(readlink "$current_link" 2>/dev/null || true)"
  [[ "$final_target" == releases/* ]] && verify_rules_anchors "$dst/$final_target" \
    || die "目标规则卷 current 指向的快照锚点校验失败: ${final_target:-<empty>}（未切换容器）"

  # 兼容既有扁平路径（如升级前 autosave.json 中仍引用 /etc/caddy/rules/coraza.conf 等路径），
  # 在卷根建立相对软链指向 current/*，确保 gateway --resume 零中断恢复。
  local compat_item
  for compat_item in coraza.conf crs contrib exclusions jiuzhang; do
    if [[ -e "$dst/$compat_item" && ! -L "$dst/$compat_item" ]]; then
      die "目标规则卷根目录存在非符号链接的同名条目: ${compat_item}（未切换容器）"
    fi
    atomic_replace_symlink "current/$compat_item" "$dst/$compat_item" \
      || die "创建目标规则卷兼容软链失败: ${compat_item}（未切换容器）"
  done
  for compat_item in coraza.conf crs/crs-setup.conf jiuzhang/post-contrib-blocking.conf; do
    [[ -f "$dst/$compat_item" && -s "$dst/$compat_item" ]] \
      || die "目标规则卷兼容入口校验失败: ${compat_item}（未切换容器）"
  done

  # 若既有 gateway autosave.json 显式引用了 releases/<ver>/，在停容器前 fail-closed 复核其完整性
  local old_gw_id old_cfg_mp old_cfg_vol old_cfg_name autosave autosave_rule_vers ref_ver
  old_gw_id="$(docker compose -f "$OLD_COMPOSE_FILE" --env-file "$JZ_ENV_FILE" ps -q gateway 2>/dev/null || true)"
  old_cfg_mp="$(container_mount_source "$old_gw_id" /config)"
  if [[ -z "$old_cfg_mp" ]]; then
    old_cfg_vol="$(compose_volume_source "$OLD_COMPOSE_JSON" gateway /config)"
    if [[ -n "$old_cfg_vol" ]]; then
      old_cfg_name="$(compose_volume_name "$OLD_COMPOSE_JSON" "$old_cfg_vol")"
      old_cfg_mp="$(docker volume inspect --format '{{.Mountpoint}}' "$old_cfg_name" 2>/dev/null || true)"
    fi
  fi
  autosave="${old_cfg_mp:+$old_cfg_mp/caddy/autosave.json}"
  if [[ -n "$autosave" && -f "$autosave" && ! -L "$autosave" && -r "$autosave" ]]; then
    autosave_rule_vers="$(grep -oE '/etc/caddy/rules/releases/[0-9A-Za-z._-]+/' "$autosave" 2>/dev/null \
      | sed -E 's|^/etc/caddy/rules/releases/||; s|/$||' | LC_ALL=C sort -u || true)"
    while IFS= read -r ref_ver; do
      [[ -n "$ref_ver" ]] || continue
      verify_rules_anchors "$dst/releases/$ref_ver" \
        || die "目标规则卷 ${target_vol_name} 缺少当前网关 autosave.json 引用的规则快照: releases/${ref_ver}（未切换容器）"
    done <<< "$autosave_rule_vers"
  fi

  if [[ "$preserved_customer" != true ]]; then
    log_info "已完成规则卷迁移与锚点核验（卷: ${target_vol_name}，current -> ${final_target}）"
  fi
}
reconcile_sidecars_permissions_for_netmgrd() {
  # 目标 Compose 中 netmgrd 使用 cap_drop: [ALL] + group_add: ["1000"]（无 CAP_DAC_OVERRIDE）时，
  # 需确保既有 gateway-admin 卷的 sidecars 与 sidecars/diag 目录为 1000:1000 0770，
  # 且待消费的 diag 请求/停止文件为 0640（不触碰 0600 的 capability.json / ha-vip.json）。
  jq -e '
    .services.netmgrd as $n |
    ($n != null) and
    (($n.cap_drop // []) | index("ALL") != null) and
    (($n.group_add // []) | map(tostring) | index("1000") != null)
  ' <<<"$TARGET_COMPOSE_JSON" >/dev/null 2>&1 || return 0

  local admin_dir="" old_gw_id old_api_id admin_vol admin_vol_name
  old_gw_id="$(docker compose -f "$OLD_COMPOSE_FILE" --env-file "$JZ_ENV_FILE" ps -q gateway 2>/dev/null || true)"
  admin_dir="$(container_mount_source "$old_gw_id" /var/run/caddy)"
  if [[ -z "$admin_dir" ]]; then
    old_api_id="$(docker compose -f "$OLD_COMPOSE_FILE" --env-file "$JZ_ENV_FILE" ps -q api 2>/dev/null || true)"
    admin_dir="$(container_mount_source "$old_api_id" /var/run/caddy)"
  fi
  if [[ -z "$admin_dir" ]]; then
    admin_vol="$(compose_volume_source "$TARGET_COMPOSE_JSON" netmgrd /var/run/caddy)"
    if [[ -n "$admin_vol" ]]; then
      admin_vol_name="$(compose_volume_name "$TARGET_COMPOSE_JSON" "$admin_vol")"
      admin_dir="$(docker volume inspect --format '{{.Mountpoint}}' "$admin_vol_name" 2>/dev/null || true)"
    fi
  fi
  [[ -n "$admin_dir" && "$admin_dir" == /* && -d "$admin_dir" && ! -L "$admin_dir" ]] || return 0

  local admin_mode
  admin_mode="$(file_mode_octal "$admin_dir")"
  if [[ "$admin_mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$admin_mode & 8#050) != 8#050 )); then
    chmod g+rx "$admin_dir" || die "无法开放 gateway-admin 卷组遍历权限: $admin_dir"
  fi
  local sidecars_dir="$admin_dir/sidecars"
  [[ ! -L "$sidecars_dir" ]] || die "sidecars 路径为符号链接，拒绝修改权限: $sidecars_dir"
  if [[ -d "$sidecars_dir" ]]; then
    ensure_owner_1000 "$sidecars_dir" || die "无法修正 sidecars 目录属主: $sidecars_dir"
    chmod 0770 "$sidecars_dir" || die "无法修正 sidecars 目录权限: $sidecars_dir"
    local diag_dir="$sidecars_dir/diag"
    [[ ! -L "$diag_dir" ]] || die "sidecars/diag 路径为符号链接，拒绝修改权限: $diag_dir"
    if [[ -d "$diag_dir" ]]; then
      ensure_owner_1000 "$diag_dir" || die "无法修正 sidecars/diag 目录属主: $diag_dir"
      chmod 0770 "$diag_dir" || die "无法修正 sidecars/diag 目录权限: $diag_dir"
      local item
      shopt -s nullglob
      for item in "$diag_dir"/request-*.json "$diag_dir"/stop-*; do
        [[ ! -L "$item" && -f "$item" ]] || continue
        ensure_owner_1000 "$item" || die "无法修正诊断任务文件属主: $item"
        chmod 0640 "$item" || die "无法修正诊断任务文件权限: $item"
      done
      shopt -u nullglob
    fi
    log_info "已对齐 sidecars 共享目录权限（1000:1000 0770，适配无 CAP_DAC_OVERRIDE 的 netmgrd）"
  fi
}

pre_upgrade_health() {
  if [[ -x "$SCRIPT_DIR/../healthcheck/check.sh" ]]; then
    "$SCRIPT_DIR/../healthcheck/check.sh" -c "$JZ_COMPOSE_FILE" -e "$JZ_ENV_FILE" --api-url "$JZ_API_BASE" \
      || die "升级前健康检查未通过，已中止"
  else
    wait_http_ok "$JZ_API_BASE/api/v1/health" 10 || die "管理 API 不可达，已中止"
  fi
}

login_checkpoint=""
login_attempts=1
if [[ "$FULL_UPGRADE" == true ]]; then
  login_attempts=5
  login_checkpoint="${WDSP_FULL_LOGIN_CHECKPOINT:-}"
fi
resume_login=false
if [[ -n "$login_checkpoint" && -f "$login_checkpoint" ]]; then
  resume_login=true
  log_info "从步骤 2/5 的备份登录继续"
else
  log_info "步骤 1/5：升级前健康检查"
  pre_upgrade_health
  if [[ -n "$login_checkpoint" ]]; then
    tmp_checkpoint="$(mktemp "${login_checkpoint}.XXXXXX")"
    printf '%s\n' "$WDSP_FULL_LOGIN_DIGEST" > "$tmp_checkpoint"
    mv -f -- "$tmp_checkpoint" "$login_checkpoint"
  fi
fi

log_info "步骤 2/5：创建并验证 FULL 加密备份"
trap api_cleanup EXIT
api_login "$USER" "$login_attempts"
if [[ "$resume_login" == true ]]; then pre_upgrade_health; fi
if [[ -n "$login_checkpoint" ]]; then rm -f -- "$login_checkpoint"; fi
resp="$(api_req POST /api/v1/backups '{"backup_type":"FULL"}')"
[[ "$(api_code "$resp")" == "SUCCESS" ]] || die "创建备份失败: $(printf '%s' "$resp" | jq -r '.message // "未知错误"')"
BACKUP_JOB_ID="$(printf '%s' "$resp" | jq -r '.data.job.id // empty')"
[[ "$BACKUP_JOB_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || die "备份任务 ID 无效"
elapsed=0
while :; do
  resp="$(api_req GET "/api/v1/backups/$BACKUP_JOB_ID")"
  status="$(printf '%s' "$resp" | jq -r '.data.job.status // empty')"
  verified="$(printf '%s' "$resp" | jq -r '.data.job.verified // false')"
  [[ "$status" == "SUCCESS" && "$verified" == "true" ]] && break
  [[ "$status" == "FAILED" || "$status" == "CANCELLED" ]] && die "升级前备份未成功，未切换镜像"
  (( elapsed >= TIMEOUT )) && die "等待备份超时，未切换镜像"
  sleep 5; elapsed=$((elapsed + 5))
done
api_cleanup
trap - EXIT
log_info "升级前备份已完成并通过验证"

OLD_COMPOSE_FILE="$JZ_COMPOSE_FILE"
TARGET_COMPOSE_FILE="${NEW_COMPOSE_FILE:-$OLD_COMPOSE_FILE}"
[[ -f "$TARGET_COMPOSE_FILE" ]] || die "目标 Compose 不存在"
TARGET_COMPOSE_FILE="$(cd "$(dirname "$TARGET_COMPOSE_FILE")" && pwd -P)/$(basename "$TARGET_COMPOSE_FILE")"
TARGET_INSTALL_ROOT="$(dirname "$TARGET_COMPOSE_FILE")"
[[ -z "$PREVIOUS_COMPOSE_FILE" ]] || PREVIOUS_COMPOSE_FILE="$(cd "$(dirname "$PREVIOUS_COMPOSE_FILE")" && pwd -P)/$(basename "$PREVIOUS_COMPOSE_FILE")"
OLD_COMPOSE_JSON="$(render_compose "$OLD_COMPOSE_FILE" "$JZ_ENV_FILE")" || die "无法渲染当前 Compose"
TARGET_COMPOSE_JSON="$(render_compose "$TARGET_COMPOSE_FILE" "$JZ_ENV_FILE")" || die "无法渲染目标 Compose"
CUR_SERVER_IMAGE="$(compose_service_image "$TARGET_COMPOSE_JSON" api)" || die "目标 Compose 缺少 api 镜像"
CUR_GATEWAY_IMAGE="$(compose_service_image "$TARGET_COMPOSE_JSON" gateway)" || die "目标 Compose 缺少 gateway 镜像"
[[ -n "$SERVER_IMAGE" ]] || { [[ "$FULL_UPGRADE" == true ]] && SERVER_IMAGE="$CUR_SERVER_IMAGE"; }
[[ -n "$GATEWAY_IMAGE" ]] || { [[ "$FULL_UPGRADE" == true ]] && GATEWAY_IMAGE="$CUR_GATEWAY_IMAGE"; }
[[ -n "$SERVER_IMAGE" && -n "$GATEWAY_IMAGE" ]] || die "必须指定 --server-image 与 --gateway-image"

candidates=(api web gateway netmgrd logrotator containerops)
if [[ "$FULL_UPGRADE" == true ]]; then
  SERVICES=("${candidates[@]}")
  if jq -e '.services.mirrorcap.image | strings' <<<"$TARGET_COMPOSE_JSON" >/dev/null 2>&1; then
    SERVICES+=(mirrorcap)
  fi
  if jq -e '.services.tproxyd.image | strings' <<<"$TARGET_COMPOSE_JSON" >/dev/null 2>&1; then
    SERVICES+=(tproxyd)
  fi
  if jq -e '.services.havipd.image | strings' <<<"$TARGET_COMPOSE_JSON" >/dev/null 2>&1; then
    SERVICES+=(havipd)
  fi
  if jq -e '.services.hasyncd.image | strings' <<<"$OLD_COMPOSE_JSON" >/dev/null 2>&1; then
    SERVICES+=(hasyncd)
  fi
  if jq -e '.services.pcapd.image | strings' <<<"$OLD_COMPOSE_JSON" >/dev/null 2>&1; then
    SERVICES+=(pcapd)
  fi
else
  for service in "${candidates[@]}" mirrorcap tproxyd havipd hasyncd; do
    jq -e --arg s "$service" '.services[$s].image' <<<"$OLD_COMPOSE_JSON" >/dev/null 2>&1 || continue
    jq -e --arg s "$service" '.services[$s].image' <<<"$TARGET_COMPOSE_JSON" >/dev/null 2>&1 || continue
    SERVICES+=("$service")
  done
fi
for service in "${SERVICES[@]}"; do
  target="$(compose_service_image "$TARGET_COMPOSE_JSON" "$service")" || die "目标 Compose 缺少 $service 镜像"
  TARGET_IMAGES+=("$target")
  if old="$(compose_service_image "$OLD_COMPOSE_JSON" "$service" 2>/dev/null)"; then
    old_id="$(docker image inspect "$old" --format '{{.Id}}' 2>/dev/null)" || die "无法读取当前 $service 镜像 ID"
    OLD_IMAGES+=("$old"); OLD_IDS+=("$old_id")
  else
    [[ "$FULL_UPGRADE" == true ]] || die "当前 Compose 缺少 $service"
    OLD_IMAGES+=(""); OLD_IDS+=("")
  fi
done
SCHEMA_BEFORE=""
if [[ "$FULL_UPGRADE" == true ]]; then
  [[ -n "$IMAGES_DIR" && -d "$IMAGES_DIR" ]] || die "完整升级必须指定 --images-dir"
  [[ -n "$PREVIOUS_COMPOSE_FILE" && -f "$PREVIOUS_COMPOSE_FILE" ]] || die "完整升级必须指定有效的原 Compose"
  pg_container="$(docker compose -f "$OLD_COMPOSE_FILE" --env-file "$JZ_ENV_FILE" ps -q postgres)" || die "无法定位升级前 PostgreSQL"
  SCHEMA_BEFORE="$(schema_version "$pg_container")"
  [[ "$SCHEMA_BEFORE" =~ ^[0-9]+$ ]] || die "无法读取升级前数据库迁移版本"
fi

log_info "步骤 3/5：加载镜像并记录回滚点"
if [[ -n "$IMAGES_TAR" ]]; then
  [[ -f "$IMAGES_TAR" ]] || die "镜像 tar 不存在"
  docker load -i "$IMAGES_TAR" >/dev/null || die "加载镜像失败"
fi
if [[ -n "$IMAGES_DIR" ]]; then
  for image_tar in "$IMAGES_DIR"/*.tar; do
    [[ -f "$image_tar" ]] || die "镜像目录缺少 tar 文件"
    docker load -i "$image_tar" >/dev/null || die "加载镜像失败: $(basename "$image_tar")"
  done
fi
for target in "${TARGET_IMAGES[@]}" "$SERVER_IMAGE" "$GATEWAY_IMAGE"; do
  docker image inspect "$target" >/dev/null 2>&1 || die "目标镜像不存在: $target"
done
GATEWAY_ENTRYPOINT="$(image_entrypoint "$GATEWAY_IMAGE")" || die "无法读取目标 gateway 镜像入口"
case "$GATEWAY_ENTRYPOINT" in
  /usr/local/bin/wdsp-gateway-bind)
    assert_bind_gateway_compose "$TARGET_COMPOSE_JSON" || die "新 gateway 启动器要求匹配的 Compose 安全契约，请使用 --new-compose-file；未切换镜像" ;;
  /usr/local/bin/docker-entrypoint.sh)
    legacy_gateway_compose_is_safe "$TARGET_COMPOSE_JSON" || die "legacy gateway 镜像不能使用新启动器 Compose，未切换镜像" ;;
  *) die "拒绝未知 gateway 镜像入口: $GATEWAY_ENTRYPOINT" ;;
esac
[[ "$SERVER_IMAGE" == "$CUR_SERVER_IMAGE" ]] || docker image inspect "$SERVER_IMAGE" >/dev/null
NEW_SERVER_IMAGE_ID="$(docker image inspect "$SERVER_IMAGE" --format '{{.Id}}')" || die "无法读取目标 API 镜像 ID"

migrate_gateway_certs_if_needed
migrate_gateway_rules_volume
reconcile_sidecars_permissions_for_netmgrd

API_EXTRA_NETWORKS=()
if printf '%s\n' "${SERVICES[@]}" | grep -Fxq api; then
  OLD_API_ID="$(docker compose -f "$OLD_COMPOSE_FILE" --env-file "$JZ_ENV_FILE" ps -q api 2>/dev/null || true)"
  while IFS= read -r _net; do
    [[ -n "$_net" ]] && API_EXTRA_NETWORKS+=("$_net")
  done < <(collect_api_extra_networks "$OLD_API_ID" "$TARGET_COMPOSE_JSON" "$OLD_COMPOSE_JSON")
  unset _net
fi

JZ_COMPOSE_FILE="$TARGET_COMPOSE_FILE"
umask 077
cat > "$STATE_FILE" <<EOF
OLD_SERVER_IMAGE=${OLD_IMAGES[0]}
OLD_GATEWAY_IMAGE=$(compose_service_image "$OLD_COMPOSE_JSON" gateway)
OLD_SERVER_IMAGE_ID=${OLD_IDS[0]}
OLD_GATEWAY_IMAGE_ID=$(docker image inspect "$(compose_service_image "$OLD_COMPOSE_JSON" gateway)" --format '{{.Id}}')
NEW_SERVER_IMAGE=$SERVER_IMAGE
NEW_GATEWAY_IMAGE=$GATEWAY_IMAGE
NEW_SERVER_IMAGE_ID=$NEW_SERVER_IMAGE_ID
TARGET_COMPOSE_FILE=$TARGET_COMPOSE_FILE
TARGET_ENV_FILE=$JZ_ENV_FILE
PREVIOUS_COMPOSE_FILE=$PREVIOUS_COMPOSE_FILE
CURRENT_LINK=$CURRENT_LINK
FULL_UPGRADE=$FULL_UPGRADE
SCHEMA_BEFORE=$SCHEMA_BEFORE
UPGRADE_SERVICES=$(printf '%s,' "${SERVICES[@]}" | sed 's/,$//')
TARGET_IMAGES_B64=$(array_encode "${TARGET_IMAGES[@]}")
OLD_IMAGES_B64=$(array_encode "${OLD_IMAGES[@]}")
OLD_IDS_B64=$(array_encode "${OLD_IDS[@]}")
API_EXTRA_NETWORKS_B64=$(array_encode ${API_EXTRA_NETWORKS[@]+"${API_EXTRA_NETWORKS[@]}"})
RULES_VOLUME_NAME=$RULES_VOLUME_NAME
RULES_PREVIOUS_CURRENT_TARGET=$RULES_PREVIOUS_CURRENT_TARGET
BACKUP_JOB_ID=$BACKUP_JOB_ID
UPGRADE_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
EOF
chmod 600 "$STATE_FILE"

rollback_failed_upgrade() {
  local rc=$?
  trap - EXIT
  api_cleanup
  if [[ "$SWITCH_STARTED" == true ]]; then
    log_err "升级失败，自动恢复原镜像及新增迁移"
    if bash "$SCRIPT_DIR/rollback.sh" --yes --timeout "$TIMEOUT" --api-url "$JZ_API_BASE"; then
      log_err "自动回滚完成；current 保持原 release，备份任务 $BACKUP_JOB_ID"
    else
      log_err "自动回滚未完成；请勿继续启动其他版本，使用备份任务 $BACKUP_JOB_ID 诊断恢复"
    fi
  fi
  exit "$rc"
}
trap rollback_failed_upgrade EXIT

SWITCH_STARTED=true
[[ "$SERVER_IMAGE" == "$CUR_SERVER_IMAGE" ]] || docker tag "$SERVER_IMAGE" "$CUR_SERVER_IMAGE"
[[ "$GATEWAY_IMAGE" == "$CUR_GATEWAY_IMAGE" ]] || docker tag "$GATEWAY_IMAGE" "$CUR_GATEWAY_IMAGE"

log_info "步骤 4/5：同次重建 ${SERVICES[*]}（PCAP profile 不启动）"
compose rm -sf "${SERVICES[@]}" >/dev/null 2>&1 || true
compose up -d --no-deps --force-recreate "${SERVICES[@]}" || die "新容器创建失败"
if ((${#API_EXTRA_NETWORKS[@]} > 0)); then
  NEW_API_ID="$(compose ps -q api 2>/dev/null || true)"
  reattach_api_extra_networks "$NEW_API_ID" strict "${API_EXTRA_NETWORKS[@]}" \
    || die "恢复 api 附加网络失败（ClickHouse 等数据面将不可达），开始自动回滚"
fi
wait_selected_services() {
  local deadline=$((SECONDS + TIMEOUT)) service id snapshot state health image restarts started extra ready
  while (( SECONDS < deadline )); do
    ready=true
    for i in "${!SERVICES[@]}"; do
      service="${SERVICES[$i]}"
      id="$(compose ps -q "$service" 2>/dev/null)" || { log_warn "$service 容器不存在"; ready=false; break; }
      [[ "$id" =~ ^[a-fA-F0-9]+$ ]] || { ready=false; break; }
      snapshot="$(timeout 8 docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.Image}}|{{.RestartCount}}|{{.State.StartedAt}}' "$id" 2>/dev/null)" || { ready=false; break; }
      IFS='|' read -r state health image restarts started extra <<<"$snapshot"
      expected="$(docker image inspect "${TARGET_IMAGES[$i]}" --format '{{.Id}}' 2>/dev/null)" || { ready=false; break; }
      if [[ "$state" != running || -n "$extra" || ( -n "$health" && "$health" != healthy ) || "$image" != "$expected" || ! "$restarts" =~ ^[0-9]+$ || -z "$started" ]]; then
        log_warn "$service 尚未运行目标镜像并通过自身健康检查（状态=${state:-unknown} 健康=${health:-未配置} 重启=${restarts:-?} 镜像=${image} 预期=${expected}）"
        ready=false; break
      fi
      case "$service" in
        api) timeout 8 docker exec "$id" wget -q -T 5 -O /dev/null http://127.0.0.1:8080/api/v1/health || { ready=false; break; } ;;
        web) timeout 12 docker exec "$id" sh -ec 'wget -q -T 5 -O /dev/null http://127.0.0.1:8080/ && wget -q -T 5 -O /dev/null http://127.0.0.1:8080/api/v1/health' || { ready=false; break; } ;;
        netmgrd) timeout 8 docker exec "$id" /usr/local/bin/netmgrd --healthcheck || { ready=false; break; } ;;
        mirrorcap) timeout 8 docker exec "$id" /usr/local/bin/mirrorcap --healthcheck || { ready=false; break; } ;;
        tproxyd) timeout 8 docker exec "$id" /usr/local/bin/tproxyd --healthcheck || { ready=false; break; } ;;
        havipd) timeout 8 docker exec "$id" /usr/local/bin/havipd --healthcheck || { ready=false; break; } ;;
        hasyncd) timeout 8 docker exec "$id" /usr/local/bin/hasyncd --healthcheck || { ready=false; break; } ;;
      esac
    done
    if [[ "$ready" == true ]] && curl -fsS --max-time 5 "$JZ_API_BASE/api/v1/health" >/dev/null 2>&1; then
      sleep 10
      for service in "${SERVICES[@]}"; do
        id="$(compose ps -q "$service" 2>/dev/null)" || return 1
        [[ "$(docker inspect --format '{{.State.Status}}' "$id" 2>/dev/null)" == running ]] || return 1
      done
      return 0
    fi
    sleep 2
  done
  return 1
}
wait_selected_services || die "组件镜像、运行状态或 HTTP 健康检查未通过"

log_info "步骤 5/5：完整健康检查及 hostctl 单元更新"
if [[ -x "$SCRIPT_DIR/../healthcheck/check.sh" ]]; then
  "$SCRIPT_DIR/../healthcheck/check.sh" -c "$TARGET_COMPOSE_FILE" -e "$JZ_ENV_FILE" --api-url "$JZ_API_BASE" --strict-clickhouse-network \
    || die "升级后健康检查失败"
fi
bash "$TARGET_INSTALL_ROOT/ops/install/install-hostctl.sh" --install-root "$TARGET_INSTALL_ROOT" --strict \
  || die "升级后 hostctl 单元更新失败（目标 release: ${TARGET_INSTALL_ROOT}），开始自动回滚"
SWITCH_STARTED=false
trap - EXIT
log_info "容器与数据库升级完成；备份任务 ${BACKUP_JOB_ID}。current 由完整升级入口在后续宿主检查通过后切换"
