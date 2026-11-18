#!/usr/bin/env bash
# update-full.sh —— 从原始完整离线归档升级现有 release；不重新初始化配置或数据。
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/signing.sh"

WDSP_RELEASE_PUBKEY_PEM="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJBzjZs04R6NVLDuKoJsViPuBEGlo70z/zpnKi6ZHq2s=
-----END PUBLIC KEY-----"
export WDSP_DEVELOPMENT_MODE=0
ALLOW_UNSIGNED=false
PACKAGE=""
CURRENT_RELEASE=""
CURRENT_LINK=""
API_URL="${JZ_API_BASE:-}"
TIMEOUT=600
USER="${JZ_ADMIN_USER:-jiuzhang_admin}"

usage() {
  cat <<'EOF'
用法: update-full.sh --package FILE --current-release DIR [选项]

  --package FILE           jiuzhang-wdsp-update-full-X.Y.Z-amd64.tar.gz 原始归档
  --current-release DIR    当前正在运行的 release 目录（不是新目录）
  --current-link FILE      current 符号链接；缺省为旧 release 同级的 current
  --api-url URL            管理 API（缺省读取现有 Compose 的 API 发布端口）
  --timeout SEC            各等待阶段超时（默认 600）
  -u, --user USER          管理员用户名（默认 jiuzhang_admin）
  --allow-unsigned         仅允许 development 包的隔离验证；生产环境禁止使用
  -h, --help               显示帮助

需要 root、Linux、Docker Compose 与 systemd。JZ_ADMIN_PASSWORD 可预置管理员口令。
保留 .tar.gz、.tar.gz.sig 和 .tar.gz.sha256 于同一目录。脚本先验签再读取包内容，
复用原 env/runtime/命名卷，失败自动回滚，全部健康后才原子切换 current。
PCAP profile 默认关闭，升级不会启用持续抓包。外部客户端访问须另行真实验收。
EOF
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --package) PACKAGE="${2:-}"; shift 2 ;;
    --current-release) CURRENT_RELEASE="${2:-}"; shift 2 ;;
    --current-link) CURRENT_LINK="${2:-}"; shift 2 ;;
    --api-url) API_URL="${2:-}"; shift 2 ;;
    --timeout) TIMEOUT="${2:-}"; shift 2 ;;
    -u|--user) USER="${2:-}"; shift 2 ;;
    --allow-unsigned) ALLOW_UNSIGNED=true; export WDSP_DEVELOPMENT_MODE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done
[[ "$(id -u)" == 0 ]] || die "完整升级必须以 root 执行"
[[ "$(uname -s)" == Linux ]] || die "完整升级仅支持目标 Linux 主机"
[[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "--timeout 必须为正整数"
for cmd in docker curl jq openssl python3 tar sha256sum realpath systemctl install base64 timeout; do require_cmd "$cmd"; done
[[ -f "$PACKAGE" ]] || die "升级归档不存在"
PACKAGE="$(realpath "$PACKAGE")"
[[ "$(basename "$PACKAGE")" == jiuzhang-wdsp-update-full-*-*.tar.gz ]] || die "请使用名称含 update-full 的完整升级归档，不能用 install/run 或应用镜像包"
[[ -d "$CURRENT_RELEASE" ]] || die "当前 release 目录不存在"
CURRENT_RELEASE="$(realpath "$CURRENT_RELEASE")"
OLD_COMPOSE="$CURRENT_RELEASE/docker-compose.yml"
OLD_ENV="$CURRENT_RELEASE/.env"
[[ -f "$OLD_COMPOSE" && -f "$OLD_ENV" && -d "$CURRENT_RELEASE/runtime" ]] || die "原 release 缺少 Compose、env 或 runtime，停止升级"
OLD_MANIFEST="$CURRENT_RELEASE/manifest.json"
[[ -f "$OLD_MANIFEST" ]] || die "原 release 缺少 manifest.json"
if ! jq -e '.edition == "wdsp" and .delivery_mode == "production"' "$OLD_MANIFEST" >/dev/null; then
  [[ "$ALLOW_UNSIGNED" == true ]] && jq -e '.edition == "wdsp" and .delivery_mode == "development" and .signed == false' "$OLD_MANIFEST" >/dev/null \
    || die "原 release 与所选正式/development 升级模式不匹配"
fi
PARENT="$(dirname "$CURRENT_RELEASE")"
[[ -n "$CURRENT_LINK" ]] || CURRENT_LINK="$PARENT/current"
if [[ -e "$CURRENT_LINK" || -L "$CURRENT_LINK" ]]; then
  [[ -L "$CURRENT_LINK" ]] || die "current 已存在但不是符号链接，拒绝覆盖"
  [[ "$(realpath "$CURRENT_LINK")" == "$CURRENT_RELEASE" ]] || die "current 未指向指定的当前 release，拒绝覆盖"
fi
[[ -d /run/systemd/system ]] || die "systemd 不可用"
docker compose version >/dev/null 2>&1 || die "缺少 Docker Compose 插件"
if [[ -z "$API_URL" ]]; then
  API_URL="$(compose_api_url "$OLD_COMPOSE" "$OLD_ENV")" || die "无法从现有 Compose 读取管理 API 地址，请使用 --api-url 显式指定"
fi

log_info "升级前验证交付签名与 SHA-256"
sig_rc=0
ed25519_verify_sidecar "$PACKAGE" || sig_rc=$?
case "$sig_rc" in
  0) ;;
  2) [[ "$ALLOW_UNSIGNED" == true ]] || die "完整升级包未签名；正式升级禁止 --allow-unsigned"
     log_warn "仅用于隔离验证：已显式放行未签名 development 包" ;;
  *) die "完整升级包验签失败，未读取或执行包内容" ;;
esac
sha256_check_sidecar "$PACKAGE" || die "完整升级包 SHA-256 校验失败"
HOST_ARCH="$(detect_arch)"
PACKAGE_INFO="$(python3 - "$PACKAGE" "$ALLOW_UNSIGNED" <<'PY'
import json, pathlib, sys, tarfile
archive, allow_unsigned = sys.argv[1], sys.argv[2] == "true"
with tarfile.open(archive, "r:gz") as tf:
    members = tf.getmembers()
    roots = set()
    total = 0
    manifest = None
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not (member.isdir() or member.isfile()):
            raise SystemExit("归档含不安全路径、链接或特殊文件")
        if not path.parts:
            raise SystemExit("归档路径为空")
        roots.add(path.parts[0])
        if len(path.parts) == 2 and path.parts[1] == "manifest.json" and member.isfile():
            manifest = tf.extractfile(member).read()
        if member.size < 0 or total > (40 << 30) - member.size:
            raise SystemExit("归档解压大小超过 40 GiB 安全上限")
        total += member.size
    if len(roots) != 1 or manifest is None:
        raise SystemExit("完整包必须有唯一根目录和 manifest.json")
    data = json.loads(manifest)
    if data.get("edition") != "wdsp":
        raise SystemExit("仅接受 WDSP 完整包")
    expected = ("development", False) if allow_unsigned else ("production", True)
    if (data.get("delivery_mode"), data.get("signed")) != expected:
        raise SystemExit("包 delivery_mode/signed 与所选升级模式不匹配；正式包必须签名，--allow-unsigned 仅接受 development 包")
    version = data.get("version", "")
    if not isinstance(version, str) or not version or any(c not in "0123456789." for c in version):
        raise SystemExit("包内版本号非法")
    print(json.dumps({"root": next(iter(roots)), "version": version, "arch": data.get("arch"), "size": total}))
PY
)" || die "完整包安全检查失败"
VERSION="$(jq -er .version <<<"$PACKAGE_INFO")"
ARCH="$(jq -er .arch <<<"$PACKAGE_INFO")"
[[ "$ARCH" == "$HOST_ARCH" ]] || die "包架构 $ARCH 与主机 $HOST_ARCH 不一致"
NEW_RELEASE="$PARENT/jiuzhang-wdsp-offline-$VERSION-$ARCH"
[[ ! -e "$NEW_RELEASE" ]] || die "目标 release 已存在，拒绝覆盖：$NEW_RELEASE"
OLD_VERSION="$(jq -er .version "$OLD_MANIFEST")"
[[ "$VERSION" != "$OLD_VERSION" ]] || die "目标版本与原版本相同，无需升级"
FREE_KIB="$(df -Pk "$PARENT" | awk 'NR==2 {print $4}')"
REQUIRED_KIB=$(( $(jq -er .size <<<"$PACKAGE_INFO") / 1024 + 2097152 ))
[[ "$FREE_KIB" -gt "$REQUIRED_KIB" ]] || die "目标磁盘空间不足；解压完整镜像前需保留包大小及至少 2 GiB 余量"

log_info "安全解压 WDSP $VERSION；原 current 与运行目录保持不变"
python3 - "$PACKAGE" "$PARENT" <<'PY'
import pathlib, sys, tarfile
archive, destination = sys.argv[1:]
root = pathlib.Path(destination).resolve()
with tarfile.open(archive, "r:gz") as tf:
    for member in tf.getmembers():
        target = (root / pathlib.PurePosixPath(member.name)).resolve()
        if root != target and root not in target.parents:
            raise SystemExit("归档路径越界")
    tf.extractall(root)
PY
[[ -d "$NEW_RELEASE" && -f "$NEW_RELEASE/manifest.json" ]] || die "目标 release 解压结果异常"
manifest_files_verify "$NEW_RELEASE/manifest.json" "$NEW_RELEASE" || die "目标包文件级完整性校验失败"
[[ ! -e "$NEW_RELEASE/runtime" ]] || die "目标包包含 runtime，拒绝覆盖运行数据"
cp -p "$OLD_ENV" "$NEW_RELEASE/.env"
chmod 600 "$NEW_RELEASE/.env"
if grep -Eq '^GATEWAY_PUBLISH_SMOKE_ADDR=(127\.0\.0\.1|localhost)(:[0-9]+)?$' "$NEW_RELEASE/.env"; then
  sed -i 's/^GATEWAY_PUBLISH_SMOKE_ADDR=.*$/GATEWAY_PUBLISH_SMOKE_ADDR=host.docker.internal/' "$NEW_RELEASE/.env"
  log_info "已在新 release 副本中修正旧离线包的回环探针地址；原 env 未修改"
fi
ln -s "$CURRENT_RELEASE/runtime" "$NEW_RELEASE/runtime"
TARGET_COMPOSE="$NEW_RELEASE/docker-compose.yml"
TARGET_ENV="$NEW_RELEASE/.env"
TARGET_STATE="$NEW_RELEASE/ops/upgrade/.upgrade-state.env"

rollback_full_upgrade() {
  local rc=$?
  trap - EXIT
  if [[ -f "$TARGET_STATE" ]]; then
    log_err "完整升级未完成，恢复原 release 与 current"
    bash "$NEW_RELEASE/ops/upgrade/rollback.sh" --yes --timeout "$TIMEOUT" --api-url "$API_URL" \
      || log_err "自动恢复未完成；保留两个 release 与备份用于诊断，不要删除旧镜像"
  fi
  exit "$rc"
}
trap rollback_full_upgrade EXIT

bash "$NEW_RELEASE/ops/upgrade/apply.sh" \
  --full --images-dir "$NEW_RELEASE/images" \
  --compose-file "$OLD_COMPOSE" --env-file "$TARGET_ENV" \
  --new-compose-file "$TARGET_COMPOSE" --previous-compose-file "$OLD_COMPOSE" \
  --current-link "$CURRENT_LINK" --api-url "$API_URL" --timeout "$TIMEOUT" --user "$USER"

bash "$NEW_RELEASE/ops/upgrade/install-executor.sh" \
  --compose-file "$TARGET_COMPOSE" --env-file "$TARGET_ENV" --api-url "$API_URL"
systemctl is-enabled --quiet jiuzhang-upgrade-executor.path || die "升级执行器未启用"
systemctl is-active --quiet jiuzhang-upgrade-executor.path || die "升级执行器未运行"

CURRENT_TMP="$PARENT/.current.upgrade.$$"
ln -s "$NEW_RELEASE" "$CURRENT_TMP"
mv -Tf "$CURRENT_TMP" "$CURRENT_LINK"
trap - EXIT
log_info "完整升级完成：current 已切换到 $NEW_RELEASE；旧 release、镜像与 FULL 备份均保留"
log_warn "目标 Linux 的外部客户端访问、真实 firewalld 放行及业务请求验收仍需在目标网络执行；未执行项不得记为 PASS"
