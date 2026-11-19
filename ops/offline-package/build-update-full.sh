#!/usr/bin/env bash
# build-update-full.sh —— 从干净提交构建完整 WDSP amd64 升级介质。
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/ops/lib/common.sh"
source "$REPO_ROOT/ops/lib/signing.sh"
TRUSTED_PUBLIC_KEY="$SCRIPT_DIR/release-signing.pub"
VERSION=""
OUTPUT_DIR=""
DEVELOPMENT=false
SIGNING_KEY=""

usage() {
  cat <<'EOF'
用法: build-update-full.sh --version X.Y.Z [选项]
  -v, --version X.Y.Z    目标版本，必填；工作区必须干净且 VERSION.md 已发布该版本
  -o, --output DIR       新的输出目录（缺省 dist/update-full-X.Y.Z-amd64）
      --signing-key FILE 已受信任的发布私钥；也可使用 WDSP_SIGNING_KEY
      --development      仅完整产物验证，生成明确标记的未签名 development 包
      --dry-run          仅检查构建计划，不构建镜像或写输出
  -h, --help             显示帮助
EOF
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--version) VERSION="${2:-}"; shift 2 ;;
    -o|--output) OUTPUT_DIR="${2:-}"; shift 2 ;;
    --signing-key) SIGNING_KEY="${2:-}"; shift 2 ;;
    --development) DEVELOPMENT=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "未知参数: $1" ;;
  esac
done
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "必须提供 X.Y.Z 版本号"
[[ -n "${DRY_RUN:-}" ]] || DRY_RUN=false
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$REPO_ROOT/dist/update-full-$VERSION-amd64"
if [[ "$DEVELOPMENT" == true && ( -n "$SIGNING_KEY" || -n "${WDSP_SIGNING_KEY:-}" ) ]]; then
  die "--development 禁止与生产私钥同用"
fi
if [[ -n "$SIGNING_KEY" ]]; then
  [[ -f "$SIGNING_KEY" ]] || die "签名私钥不存在"
  export WDSP_SIGNING_KEY="$SIGNING_KEY"
fi
if [[ "$DEVELOPMENT" != true ]]; then
  [[ -n "${WDSP_SIGNING_KEY:-}" ]] || die "正式升级介质必须配置受信任的 WDSP_SIGNING_KEY"
  require_cmd openssl
  expected="$(ed25519_pubkey_fingerprint "$TRUSTED_PUBLIC_KEY")"
  derived="$(mktemp "${TMPDIR:-/tmp}/wdsp-update-pub.XXXXXX")"
  openssl pkey -in "$WDSP_SIGNING_KEY" -pubout -out "$derived" >/dev/null 2>&1 || die "发布私钥不可解析"
  actual="$(ed25519_pubkey_fingerprint "$derived")"
  rm -f "$derived"
  [[ -n "$expected" && "$actual" == "$expected" ]] || die "私钥与交付信任根不匹配，拒绝打包"
fi
for cmd in docker go file jq python3 openssl tar; do require_cmd "$cmd"; done
[[ -z "$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ]] || die "正式快照必须从干净工作区构建，请先提交全部发布文件"
PUBLISHED="$(awk -F'`' '/当前已发布版本/ { print $2; exit }' "$REPO_ROOT/VERSION.md")"
[[ "$PUBLISHED" == "$VERSION" ]] || die "VERSION.md 当前发布版本与 --version 不一致"
[[ "$(git -C "$REPO_ROOT" rev-parse 'wdsp-v'"$VERSION"'^{commit}')" == "$(git -C "$REPO_ROOT" rev-parse HEAD)" ]] || die "当前 HEAD 与版本标签不一致"
docker info >/dev/null 2>&1 || die "Docker daemon 不可用"
docker buildx version >/dev/null 2>&1 || die "Docker buildx 不可用"
FREE_KIB="$(df -Pk "$(dirname "$OUTPUT_DIR")" | awk 'NR==2 {print $4}')"
[[ "$FREE_KIB" -ge $((20 * 1024 * 1024)) ]] || die "构建目录至少需要 20 GiB 可用空间"
[[ ! -e "$OUTPUT_DIR" ]] || die "输出目录已存在，拒绝覆盖"

build_image() {
  printf '+ docker buildx build --platform linux/amd64 --load -f %q -t %q:%s %q\n' "$2" "$1" "$VERSION" "$3"
  [[ "$DRY_RUN" == true ]] || docker buildx build --platform linux/amd64 --load -f "$2" -t "$1:$VERSION" "$3"
}
cd "$REPO_ROOT"
build_image jiuzhang-server server/Dockerfile .
build_image jiuzhang-web web/Dockerfile web
build_image jiuzhang-gateway gateway/Dockerfile gateway
build_image jiuzhang-netmgrd gateway/images/netmgrd/Dockerfile gateway
build_image jiuzhang-logrotator gateway/images/logrotator/Dockerfile gateway/images/logrotator
build_image jiuzhang-containerops deployment/containerops/Dockerfile .
build_image jiuzhang-pcapd gateway/images/pcapd/Dockerfile gateway
if [[ "$DRY_RUN" == true ]]; then
  log_info "干运行完成；未生成镜像或交付文件"
  exit 0
fi
mkdir -p "$OUTPUT_DIR"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wdsp-update-full.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
AGENT="$WORK/wdsp-agent"
(
  cd "$REPO_ROOT/wdsp-agent"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
    go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$AGENT" ./cmd/agent
)
file "$AGENT" | grep -q 'ELF 64-bit.*x86-64' || die "Agent 不是 linux/amd64 ELF"
export WDSP_AGENT_BINARY="$AGENT"
BUILD_ARGS=(--version "$VERSION" --product wdsp --arch amd64 --runtime-only --output "$OUTPUT_DIR")
[[ "$DEVELOPMENT" != true ]] || BUILD_ARGS+=(--development)
bash "$SCRIPT_DIR/build.sh" "${BUILD_ARGS[@]}"

ARCHIVE="$OUTPUT_DIR/jiuzhang-wdsp-update-full-$VERSION-amd64.tar.gz"
ORIGINAL="$OUTPUT_DIR/jiuzhang-wdsp-offline-$VERSION-amd64.tar.gz"
[[ -f "$ARCHIVE" && -f "$ORIGINAL" ]] || die "缺少完整升级交付归档"
[[ "$(sha256_of "$ARCHIVE" | awk '{print $1}')" == "$(sha256_of "$ORIGINAL" | awk '{print $1}')" ]] || die "交付别名与原始包内容不同"
sha256_check_sidecar "$ARCHIVE" || die "完整升级别名摘要无效"
if [[ "$DEVELOPMENT" == true ]]; then
  [[ ! -e "${ARCHIVE}.sig" ]] || die "development 包不应带生产签名"
else
  ed25519_verify_file "$TRUSTED_PUBLIC_KEY" "$ARCHIVE" "${ARCHIVE}.sig" || die "完整升级别名验签失败"
fi
LAUNCHER="$OUTPUT_DIR/jiuzhang-wdsp-update-full-$VERSION-amd64.sh"
[[ -x "$LAUNCHER" ]] || die "缺少独立升级启动脚本"
bash -n "$LAUNCHER" && bash "$LAUNCHER" --help >/dev/null || die "独立升级启动脚本不可用"
sha256_check_sidecar "$LAUNCHER" || die "独立升级启动脚本摘要无效"
if [[ "$DEVELOPMENT" == true ]]; then
  [[ ! -e "${LAUNCHER}.sig" ]] || die "development 启动脚本不应带生产签名"
else
  ed25519_verify_file "$TRUSTED_PUBLIC_KEY" "$LAUNCHER" "${LAUNCHER}.sig" || die "独立升级启动脚本验签失败"
fi
VERIFY="$WORK/verify"
mkdir -p "$VERIFY"
COPYFILE_DISABLE=1 tar -xzf "$ARCHIVE" -C "$VERIFY"
ROOT_DIR="$VERIFY/jiuzhang-wdsp-offline-$VERSION-amd64"
[[ -f "$ROOT_DIR/manifest.json" && -f "$ROOT_DIR/ops/upgrade/update-full.sh" ]] || die "归档缺少升级入口或 manifest"
manifest_files_verify "$ROOT_DIR/manifest.json" "$ROOT_DIR" || die "从交付归档解出的文件清单校验失败"
EXPECTED_MODE=production; EXPECTED_SIGNED=true
[[ "$DEVELOPMENT" != true ]] || { EXPECTED_MODE=development; EXPECTED_SIGNED=false; }
jq -e --arg version "$VERSION" --arg commit "$(git rev-parse HEAD)" --arg mode "$EXPECTED_MODE" \
  --argjson signed "$EXPECTED_SIGNED" '
  .edition == "wdsp" and .version == $version and .arch == "amd64" and
  .delivery_mode == $mode and .signed == $signed and .traceability.build_commit == $commit and
  .traceability.signature.key_id == "wdsp-release-ed25519-0db8c1fc0fe556fd" and
  (.images | length) == 11 and all(.images[]; (.image | contains(":latest") | not)) and
  ([.images[].image] | unique | length) == 11' "$ROOT_DIR/manifest.json" >/dev/null \
  || die "manifest 的版本、提交、签名状态或 11 个镜像清单不合格"
COMPOSE_JSON="$(POSTGRES_PASSWORD=verify-only VALKEY_PASSWORD=verify-only JIUZHANG_MASTER_KEY=verify-only \
  docker compose -f "$ROOT_DIR/docker-compose.yml" --env-file /dev/null config --format json)" \
  || die "交付 Compose 无法渲染"
jq -e '(.services | has("pcapd") | not) and
  .services.gateway.user == "0:0" and
  .services.gateway.entrypoint == ["/usr/local/bin/wdsp-gateway-bind"] and
  .services.gateway.cap_drop == ["ALL"] and
  (.services.gateway.cap_add | sort == (["NET_BIND_SERVICE", "SETUID", "SETGID", "SETPCAP"] | sort)) and
  (.services.containerops.tmpfs == ["/tmp:size=8m,mode=1777"]) and
  (.services.netmgrd.network_mode == "service:gateway") and
  any(.services.api.volumes[]?; .source == "gateway-certs" and .target == "/app/runtime/certificates") and
  any(.services.gateway.volumes[]?; .source == "gateway-certs" and .target == "/etc/caddy/certs" and .read_only == true)' <<<"$COMPOSE_JSON" >/dev/null \
  || die "交付 Compose 的低端口、证书下发、sidecar 或默认关闭 PCAP 契约不合格"
SCAN="$OUTPUT_DIR/jiuzhang-wdsp-offline-$VERSION-amd64.scan.json"
jq -e --arg digest "$(sha256_of "$ARCHIVE" | awk '{print $1}')" '.result == "PASS" and .input.sha256 == $digest' "$SCAN" >/dev/null \
  || die "最终内容扫描未绑定本次交付归档"
SIZE="$(stat -f%z "$ARCHIVE" 2>/dev/null || stat -c%s "$ARCHIVE")"
log_info "完整升级介质已校验: $ARCHIVE（$SIZE 字节）"
if [[ "$DEVELOPMENT" == true ]]; then
  log_warn "development 未签名产物只用于本地验证，不能用于正式升级"
else
  log_info "生产签名、别名摘要、11 镜像、交付 Compose、清单及扫描均通过；目标 Linux 升级/回滚与外部访问仍须单独验收"
fi
