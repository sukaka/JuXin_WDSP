#!/usr/bin/env bash
# build-upgrade-pack.sh —— Bug 修复与功能更新统一打包入口（仅 Web 上传）。
#
# 适用场景：新功能开发完成、第二位版本号递增（如 1.2.0 → 1.3.0），包含该版本
# 涉及的变更组件镜像。Bug 修复也使用本脚本；全新安装/跨
# 主版本/基础设施变更请用 ops/offline-package/build.sh（规则见 docs/UPGRADE_PACKAGE_POLICY.md）。
#
# 组件 → 镜像 → Dockerfile（构建上下文）→ compose 服务 映射：
#   api      → jiuzhang-server:<to>   → server/Dockerfile                 （上下文=仓库根） → api
#   web      → jiuzhang-web:<to>      → web/Dockerfile                    （上下文=web/）    → web
#   gateway  → jiuzhang-gateway:<to>  → gateway/Dockerfile                （上下文=gateway/）→ gateway
#   netmgrd  → jiuzhang-netmgrd:<to>  → gateway/images/netmgrd/Dockerfile （上下文=gateway/）→ netmgrd
# 组件白名单与宿主机执行器 upgrade-executor.sh 保持一致；新增组件须两侧同步。
#
# --components auto 自动识别模式（默认；与显式清单互斥）：
#   基准引用：wdsp-v<--from> tag（git rev-parse --verify；tag 缺失报错并提示先
#   git fetch --tags——本脚本只读仓库，绝不自行 fetch 或任何 git 写操作）。
#   变更清单：git diff --name-only wdsp-v<from>..HEAD + 工作区未提交改动（含未跟踪，
#   存在时打印警告，正式包建议先提交再构建）。路径 → 组件映射：
#     server/（含 migrations/openapi）                       → api
#     web/                                                   → web
#     gateway/netmgrd/、gateway/cmd/netmgrd/、
#       gateway/images/netmgrd/                              → netmgrd
#     gateway/go.mod、gateway/go.sum                         → gateway + netmgrd（同一构建上下文）
#     gateway/ 其余                                          → gateway
#     gateway/dynamic_security/                              → api + gateway（go.mod 另含 netmgrd）
#     deployment/、执行器和安装器                            → 拒绝，应用镜像包无法更新宿主环境
#     ops/ 其余、docs/、test/、tools/、scripts/ 等            → 非应用运行时变更，提示跳过
#     未命中任何映射的路径                                    → 报错并列出，需补充映射
#   判定证据逐组件打印（命中路径数 + 前 5 条示例）后继续构建（非交互）；
#   默认直接自动构建；--plan 可以在不构建镜像的情况下预览。
#
# 产物同时满足两套口径（单一 manifest.json，字段不冲突）：
#   1. 服务端 server/internal/upgrades/artifact.go：单一根目录、恰一个 manifest.json、
#      files 与归档文件精确一一对应（files 不得含 manifest.json/manifest.sig 自身）、
#      files_manifest_sha256 = sha256(Go json.Marshal 紧凑序列化的 files 数组)、
#      version/arch 与升级目标版本及服务器 runtime.GOARCH 一致、
#      包内 manifest.sig = 对 manifest.json 归档内原始字节的 Ed25519 签名
#      （base64 单行；单文件格式，不再产出独立 .sig 旁车）。
#   2. 宿主机执行器 upgrade-executor.sh（package_type=upgrade）：components 白名单、
#      images[] 逐组件 docker load → retag → compose up -d，含新组件（netmgrd）首次
#      部署（经包内 compose/upgrade-services.yml 片段并入宿主 compose）。
# 包内路径强制白名单 ^[A-Za-z0-9._/-]+$（排除 <>& 与非 ASCII），保证 python3 紧凑
# 序列化与 Go json.Marshal（HTML 转义）字节一致；该一致性由
# ops/upgrade/tests/upgrade-pack-harness.sh 用 Go 同口径程序回归验证。
#
# 签名：设置 WDSP_SIGNING_KEY（Ed25519 私钥路径，绝不入库）时先生成 manifest.json
# （含 files 清单）→ 对其字节签名写入包内 manifest.sig（不进 files 清单、不参与
# files_manifest_sha256）→ 再打出同时含两个文件的归档，最后从归档抽回两文件按服务端
# 口径自检；未设置时必须显式 --unsigned（仅限本地开发自测，服务端会上传验签失败
# 登记 REJECTED）。
#
# 退出码: 0=成功 1=失败 2=用法错误
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=../lib/common.sh
source "$REPO_ROOT/ops/lib/common.sh"
# shellcheck source=../lib/signing.sh
source "$REPO_ROOT/ops/lib/signing.sh"

usage() {
  cat <<'EOF'
用法: build-upgrade-pack.sh --to X.Y.Z [选项]

选项:
      --from X.Y.Z        起始版本（缺省读取根目录 VERSION.md「当前已发布版本」）
      --to X.Y.Z          目标版本（必填，必须高于 --from）
      --arch ARCH         目标架构 amd64|arm64（缺省取宿主机架构；x86_64/aarch64 自动归一）
      --components LIST   默认 auto 自动识别；可显式传空格或逗号分隔的组件清单；
                          白名单: api web gateway netmgrd；
                          或 "auto"：以 wdsp-v<--from> tag 为基准自动识别变更组件
                          （与显式清单互斥；tag 缺失时报错并提示先 git fetch --tags；
                          路径→组件映射见脚本头注释）
      --plan              只检查变更并打印计划，不构建、不签名、不写发布基线
      --skip-build        跳过 docker build：默认改用本机已有镜像 docker save；
                          与 --images-dir 同用时完全不依赖 docker
      --images-dir DIR    直接使用 DIR 下预导出的 <组件>-<arch>.tar.gz（隐含 --skip-build，
                          供无 docker 环境/测试夹具使用；正式构建请勿使用）
      --unsigned          允许不签名（仅本地开发自测；正式包必须配置 WDSP_SIGNING_KEY）
      --output-dir DIR    输出目录（默认 <仓库>/dist）
  -h, --help              显示帮助

环境变量:
  WDSP_SIGNING_KEY        已受部署系统信任的发布 Ed25519 私钥路径（不能临时生成替代，
                          绝不入库）。设置后对包内 manifest.json 字节签名生成包内
                          manifest.sig（base64 单行），并用对应公钥从归档抽回自检。

产物（<输出目录>/）:
  jiuzhang-wdsp-upgrade-<to>-<arch>.tar.gz           升级包（单一根目录，含 manifest.json；
                                                    签名时另含 manifest.sig，签名内嵌包内）
  jiuzhang-wdsp-upgrade-<to>-<arch>.tar.gz.sha256    旁车 SHA-256

退出码: 0=成功 1=失败 2=用法错误
EOF
}

FROM_VERSION=""
TO_VERSION=""
ARCH=""
COMPONENTS_RAW="auto"
PLAN_ONLY=false
SKIP_BUILD=false
IMAGES_DIR=""
UNSIGNED=false
OUTPUT_DIR="$REPO_ROOT/dist"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan) PLAN_ONLY=true; shift ;;
    --from) FROM_VERSION="${2:-}"; shift 2 ;;
    --to) TO_VERSION="${2:-}"; shift 2 ;;
    --arch) ARCH="${2:-}"; shift 2 ;;
    --components) COMPONENTS_RAW="${2:-}"; shift 2 ;;
    --skip-build) SKIP_BUILD=true; shift ;;
    --images-dir) IMAGES_DIR="${2:-}"; SKIP_BUILD=true; shift 2 ;;
    --unsigned) UNSIGNED=true; shift ;;
    --output-dir) OUTPUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf '未知参数: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

# ---------- 参数解析与校验 ----------

if [[ -z "$FROM_VERSION" ]]; then
  FROM_VERSION="$(grep -E '当前已发布版本：`[0-9]+\.[0-9]+\.[0-9]+`' "$REPO_ROOT/VERSION.md" \
    | head -1 | sed -E 's/.*`([0-9]+\.[0-9]+\.[0-9]+)`.*/\1/')"
  [[ -n "$FROM_VERSION" ]] || { printf '%s\n' '无法从 VERSION.md 解析当前已发布版本，请显式传 --from' >&2; exit 2; }
fi
version_pattern='^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$'
[[ "$FROM_VERSION" =~ $version_pattern ]] || { printf '%s\n' '--from 不是有效版本号' >&2; exit 2; }
[[ "$TO_VERSION" =~ $version_pattern ]] || { printf '%s\n' '--to 不是有效版本号（必填）' >&2; exit 2; }

IFS=. read -r from_major from_minor from_patch <<<"$FROM_VERSION"
IFS=. read -r to_major to_minor to_patch <<<"$TO_VERSION"
if (( to_major < from_major || (to_major == from_major && to_minor < from_minor) \
   || (to_major == from_major && to_minor == from_minor && to_patch <= from_patch) )); then
  printf '目标版本必须高于起始版本: %s -> %s\n' "$FROM_VERSION" "$TO_VERSION" >&2
  exit 2
fi
[[ "$to_major" == "$from_major" ]] || { printf '%s\n' '跨主版本不支持应用升级包，请使用完整安装流程' >&2; exit 2; }
CHANGE_TYPE=bugfix
if (( to_minor > from_minor )); then
  (( to_patch == 0 )) || { printf '%s\n' '功能版本递增时第三位必须归零' >&2; exit 2; }
  CHANGE_TYPE=feature
fi

if [[ -z "$ARCH" ]]; then
  ARCH="$(detect_arch)"
fi
case "$ARCH" in
  amd64|x86_64|x86) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) printf '%s\n' '--arch 仅支持 amd64 或 arm64' >&2; exit 2 ;;
esac

# 组件清单：拆分（空格/逗号）→ auto 识别或白名单校验 → 去重（重复视为用法错误）→ 排序（确定性输出）
COMPONENTS=()
AUTO_COMPONENTS=false
_raw_items="${COMPONENTS_RAW//,/ }"
# 故意的分词：清单允许空格/逗号分隔
# shellcheck disable=SC2086
for _c in $_raw_items; do
  if [[ "$_c" == "auto" ]]; then
    AUTO_COMPONENTS=true
    continue
  fi
  case "$_c" in
    api|web|gateway|netmgrd) ;;
    *) printf '未知组件: %s（白名单: api web gateway netmgrd，或 auto 自动识别）\n' "$_c" >&2; exit 2 ;;
  esac
  COMPONENTS+=("$_c")
done
if [[ "$AUTO_COMPONENTS" == "true" ]]; then
  ((${#COMPONENTS[@]} == 0)) \
    || { printf '%s\n' '--components auto 与显式组件清单互斥，请二选一' >&2; exit 2; }
else
  ((${#COMPONENTS[@]} >= 1)) || { printf '%s\n' '--components 不能为空' >&2; exit 2; }
  log_warn "显式组件模式不检查 Git 变更完整性或宿主机兼容性；日常发布请省略 --components 使用自动识别"
  _total=${#COMPONENTS[@]}
  COMPONENTS_SORTED=()
  while IFS= read -r _c; do COMPONENTS_SORTED+=("$_c"); done < <(printf '%s\n' "${COMPONENTS[@]}" | LC_ALL=C sort -u)
  _unique=${#COMPONENTS_SORTED[@]}
  [[ "$_total" == "$_unique" ]] || { printf '%s\n' '--components 含重复组件' >&2; exit 2; }
  COMPONENTS=("${COMPONENTS_SORTED[@]}")
fi

reject_legacy_gateway_pack() {
  [[ "$FROM_VERSION" == "1.3.0" ]] || return 0
  local component
  for component in "${COMPONENTS[@]}"; do
    if [[ "$component" == gateway ]]; then
      die "1.3.0 的 Compose 不满足新 gateway 启动契约，镜像包无法更新宿主 Compose；拒绝生成从 1.3.0 起含 gateway 的镜像包，请先使用完整包升级"
    fi
  done
}
if [[ "$AUTO_COMPONENTS" != true ]]; then
  reject_legacy_gateway_pack
fi

component_image() { # 组件 → 镜像名:目标版本
  case "$1" in
    api) printf 'jiuzhang-server:%s\n' "$TO_VERSION" ;;
    web) printf 'jiuzhang-web:%s\n' "$TO_VERSION" ;;
    gateway) printf 'jiuzhang-gateway:%s\n' "$TO_VERSION" ;;
    netmgrd) printf 'jiuzhang-netmgrd:%s\n' "$TO_VERSION" ;;
  esac
}
component_dockerfile() {
  case "$1" in
    api) printf 'server/Dockerfile\n' ;;
    web) printf 'web/Dockerfile\n' ;;
    gateway) printf 'gateway/Dockerfile\n' ;;
    netmgrd) printf 'gateway/images/netmgrd/Dockerfile\n' ;;
  esac
}
component_context() {
  case "$1" in
    api) printf '.\n' ;;
    web) printf 'web\n' ;;
    gateway|netmgrd) printf 'gateway\n' ;;
  esac
}

# ---------- 依赖与签名密钥 ----------

for cmd in python3; do
  require_cmd "$cmd"
done
if [[ "$PLAN_ONLY" != true && ( "$SKIP_BUILD" != "true" || -z "$IMAGES_DIR" ) ]]; then
  require_cmd docker
fi

SIGNING_KEY="${WDSP_SIGNING_KEY:-}"
PKG_SIGNED=false
if [[ "$PLAN_ONLY" == true ]]; then
  : # 只读计划不要求密钥或 Docker。
elif [[ -n "$SIGNING_KEY" ]]; then
  require_cmd openssl
  [[ -f "$SIGNING_KEY" ]] || die "WDSP_SIGNING_KEY 指向的私钥不存在: $SIGNING_KEY"
  openssl pkey -in "$SIGNING_KEY" -noout >/dev/null 2>&1 \
    || die "WDSP_SIGNING_KEY 私钥无法解析（须为 Ed25519 私钥，openssl genpkey -algorithm ED25519 生成）: $SIGNING_KEY"
  TRUSTED_PUB="$REPO_ROOT/ops/offline-package/release-signing.pub"
  [[ -f "$TRUSTED_PUB" ]] || die "缺少固定发布公钥: $TRUSTED_PUB"
  expected_pub="$(openssl pkey -pubin -in "$TRUSTED_PUB" -outform DER 2>/dev/null | base64)" || die "发布公钥无效"
  actual_pub="$(openssl pkey -in "$SIGNING_KEY" -pubout -outform DER 2>/dev/null | base64)" || die "无法导出签名公钥"
  [[ "$actual_pub" == "$expected_pub" ]] || die "WDSP_SIGNING_KEY 与固定发布公钥不匹配；不能使用临时生成的私钥制作正式升级包"
  PKG_SIGNED=true
elif [[ "$UNSIGNED" == "true" ]]; then
  log_warn "未配置 WDSP_SIGNING_KEY，本次构建不签名（--unsigned），仅允许本地开发自测。"
  log_warn "服务端上传未签名包将验签失败并登记 REJECTED；正式升级包必须签名。"
else
  die "正式升级包必须签名：请设置 WDSP_SIGNING_KEY；本地开发自测请显式使用 --unsigned"
fi

# target_schema_version：server/migrations 最大迁移号（口径同 server MaxMigrationVersion）。
TARGET_SCHEMA="$(ls "$REPO_ROOT/server/migrations" \
  | grep -E '^[0-9]{6}_[a-z0-9_]+\.up\.sql$' | cut -c1-6 | sort -n | tail -1 | sed 's/^0*//')"
[[ -n "$TARGET_SCHEMA" ]] || die "无法从 server/migrations 解析最大迁移号"

# ---------- --components auto：基于 git 变更的组件自动识别（只读仓库，不写不 fetch） ----------

if [[ "$AUTO_COMPONENTS" == "true" ]]; then
  require_cmd git
  BASE_TAG="wdsp-v$FROM_VERSION"
  git -C "$REPO_ROOT" rev-parse --verify -q "${BASE_TAG}^{commit}" >/dev/null 2>&1 \
    || die "auto 模式需要基准 tag ${BASE_TAG}（对应 --from ${FROM_VERSION}），但仓库中不存在；请先 git fetch --tags（本脚本只读仓库，不会自行 fetch），或显式使用 --components 清单"

  git -C "$REPO_ROOT" merge-base --is-ancestor "$BASE_TAG" HEAD \
    || die "基准 tag $BASE_TAG 不是当前 HEAD 的祖先，拒绝从无关发布历史打包"
  # 禁用 rename 折叠，让源路径删除和目标新增都命中组件；NUL 分隔保留特殊文件名。
  changed_json="$(python3 - "$REPO_ROOT" "$BASE_TAG" <<'PY'
import json, subprocess, sys
root, base = sys.argv[1:]
def git(*args):
    return subprocess.check_output(['git', '-C', root, *args])
def paths(*args):
    return {p.decode('utf-8', 'surrogateescape') for p in git(*args).split(b'\0') if p}
dirty = paths('diff', '--no-renames', '--name-only', '-z', 'HEAD')
dirty |= paths('ls-files', '--others', '--exclude-standard', '-z')
changed = paths('diff', '--no-renames', '--name-only', '-z', base, 'HEAD') | dirty
if git('ls-files', '--unmerged', '-z'):
    sys.exit('存在未解决的合并冲突，拒绝打包')
if dirty:
    print('auto 检测到 %d 条未提交改动（含未跟踪），已计入判定；正式包建议先提交再构建' % len(dirty), file=sys.stderr)
print(json.dumps(sorted(changed)))
PY
)" || die "读取 Git 变更失败"
  changed_all=()
  while IFS= read -r -d '' _p; do
    [[ -n "$_p" ]] && changed_all+=("$_p")
  done < <(python3 -c 'import json,sys; sys.stdout.buffer.write(b"".join(p.encode("utf-8", "surrogateescape")+b"\0" for p in json.loads(sys.argv[1])))' "$changed_json")
  ((${#changed_all[@]} > 0)) \
    || die "auto 未检测到相对 ${BASE_TAG} 的已提交变更且工作区干净；请确认 --from 取值，或显式使用 --components"

  # 路径 → 组件映射（映射表见脚本头注释；顺序敏感，netmgrd 与 go.mod/go.sum 先于 gateway/ 兜底）
  auto_api=() auto_web=() auto_gateway=() auto_netmgrd=() auto_ignored=() auto_unmatched=() auto_host=()
  for _p in "${changed_all[@]}"; do
    case "$_p" in
      server/*) auto_api+=("$_p") ;;
      web/*) auto_web+=("$_p") ;;
      gateway/dynamic_security/go.mod) auto_api+=("$_p"); auto_gateway+=("$_p"); auto_netmgrd+=("$_p") ;;
      gateway/dynamic_security/*) auto_api+=("$_p"); auto_gateway+=("$_p") ;;
      gateway/modules/jiuzhang_guard/go.mod|gateway/.dockerignore) auto_gateway+=("$_p"); auto_netmgrd+=("$_p") ;;
      .dockerignore) auto_api+=("$_p") ;;
      gateway/netmgrd/*|gateway/cmd/netmgrd/*|gateway/images/netmgrd/*) auto_netmgrd+=("$_p") ;;
      gateway/go.mod|gateway/go.sum) auto_gateway+=("$_p"); auto_netmgrd+=("$_p") ;;
      gateway/*) auto_gateway+=("$_p") ;;
      deployment/*|docker-compose*.yml|ops/upgrade/upgrade-executor.sh|ops/upgrade/install-executor.sh) auto_host+=("$_p") ;;
      ops/*|docs/*|test/*|tools/*|scripts/*|licenses/*|diagram/*|output/*|dist/*|.github/*|.agent/*|*.md|.gitignore) auto_ignored+=("$_p") ;;
      *) auto_unmatched+=("$_p") ;;
    esac
  done
  if ((${#auto_host[@]} > 0)); then
    printf '以下宿主机/编排变更不能通过镜像替换自动落地:\n' >&2
    printf '  %s\n' "${auto_host[@]}" >&2
    die "拒绝生成不完整升级包。须先确认部署基线已具备这些宿主机能力；不能用显式组件清单冒充已交付"
  fi
  if ((${#auto_ignored[@]} > 0)); then
    log_warn "auto ${#auto_ignored[@]} 条非应用运行时变更（文档、测试、构建工具等）不产生镜像组件，已跳过"
  fi
  if ((${#auto_unmatched[@]} > 0)); then
    printf 'auto 未命中组件映射的路径:\n' >&2
    printf '  %s\n' "${auto_unmatched[@]}" >&2
    die "auto 存在未命中组件映射的路径（见上）；请补充脚本映射表后再打包"
  fi

  # 判定证据：逐组件一行（命中路径数 + 前 5 条示例），随后继续构建（非交互）
  AUTO_DETECTED=()
  auto_take() { # COMPONENT PATH... —— PATH 非空则登记组件并打印证据行
    local comp="$1"; shift
    (($# > 0)) || return 0
    AUTO_DETECTED+=("$comp")
    local examples="" _x _n=0 _more=""
    for _x in "$@"; do
      examples+=" $_x"
      _n=$((_n + 1))
      ((_n >= 5)) && break
    done
    (($# > 5)) && _more=" …"
    log_info "auto 证据: ${comp} ← 命中 $# 条路径；示例:${examples}${_more}"
  }
  ((${#auto_api[@]} > 0))     && auto_take api "${auto_api[@]}"
  ((${#auto_gateway[@]} > 0)) && auto_take gateway "${auto_gateway[@]}"
  ((${#auto_netmgrd[@]} > 0)) && auto_take netmgrd "${auto_netmgrd[@]}"
  ((${#auto_web[@]} > 0))     && auto_take web "${auto_web[@]}"
  ((${#AUTO_DETECTED[@]} > 0)) \
    || die "auto 未识别出需要构建的镜像组件（变更均为 ops/deployment/docs/测试等非镜像路径）；如需发版请显式使用 --components"
  COMPONENTS=("${AUTO_DETECTED[@]}")
  log_info "auto 识别组件: ${COMPONENTS[*]}（基准 ${BASE_TAG}..HEAD + 工作区改动）"
fi

reject_legacy_gateway_pack
log_info "打包计划: ${FROM_VERSION} -> ${TO_VERSION}（${CHANGE_TYPE}），架构 ${ARCH}，组件 ${COMPONENTS[*]}"
if [[ "$PLAN_ONLY" == true ]]; then
  exit 0
fi
for cmd in jq tar openssl gzip; do require_cmd "$cmd"; done
package_name="jiuzhang-wdsp-upgrade-${TO_VERSION}-${ARCH}"
[[ ! -e "$OUTPUT_DIR/$package_name.tar.gz" && ! -e "$OUTPUT_DIR/$package_name.tar.gz.sha256" ]] \
  || die "输出文件已存在，拒绝覆盖；请更换 --output-dir 或目标版本"

# ---------- 构建/收集镜像 ----------

if [[ "$SKIP_BUILD" != "true" ]]; then
  for comp in "${COMPONENTS[@]}"; do
    image="$(component_image "$comp")"
    dockerfile="$REPO_ROOT/$(component_dockerfile "$comp")"
    context="$REPO_ROOT/$(component_context "$comp")"
    [[ -f "$dockerfile" ]] || die "Dockerfile 不存在: $dockerfile"
    log_info "构建镜像 ${image}（linux/${ARCH}，$(component_dockerfile "$comp")）..."
    docker build --platform "linux/$ARCH" -f "$dockerfile" -t "$image" "$context" \
      || die "镜像构建失败: $comp"
  done
fi
if [[ -z "$IMAGES_DIR" ]]; then
  for comp in "${COMPONENTS[@]}"; do
    image="$(component_image "$comp")"
    docker image inspect "$image" >/dev/null 2>&1 \
      || die "本机不存在镜像: ${image}（去掉 --skip-build 自动构建，或先 docker build）"
    image_arch="$(docker image inspect "$image" --format '{{.Architecture}}')"
    [[ "$image_arch" == "$ARCH" ]] \
      || die "镜像 ${image} 架构为 ${image_arch}，目标为 ${ARCH}（请用 docker buildx build --platform linux/$ARCH 重新构建）"
  done
fi

mkdir -p "$OUTPUT_DIR"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/jiuzhang-upgrade.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT
package_name="jiuzhang-wdsp-upgrade-${TO_VERSION}-${ARCH}"
package_dir="$work_dir/$package_name"
mkdir -p "$package_dir/images" "$package_dir/installer"

# 镜像 tar（docker save | gzip；--images-dir 模式下直接收录预导出文件）
save_image_gz() { # IMAGE OUT —— 优先按目标平台导出（containerd 存储可共存多架构），失败回退默认导出
  local img="$1" out="$2"
  rm -f "$out"
  if docker save --platform "linux/${ARCH}" "$img" 2>/dev/null | gzip -c > "$out" && [[ -s "$out" ]]; then
    return 0
  fi
  rm -f "$out"
  docker save "$img" | gzip -c > "$out"
}
for comp in "${COMPONENTS[@]}"; do
  tar_rel="images/${comp}-${ARCH}.tar.gz"
  if [[ -n "$IMAGES_DIR" ]]; then
    src="$IMAGES_DIR/${comp}-${ARCH}.tar.gz"
    [[ -f "$src" ]] || die "--images-dir 缺少镜像归档: ${src}（命名约定 <组件>-<arch>.tar.gz）"
    gzip -t "$src" 2>/dev/null || die "镜像归档不是有效 gzip: $src"
    tar -tzf "$src" >/dev/null 2>&1 || die "镜像归档不是有效 tar.gz: $src"
    cp "$src" "$package_dir/$tar_rel"
    log_info "收录预导出镜像归档: $tar_rel"
  else
    log_info "导出镜像 $(component_image "$comp") -> $tar_rel"
    save_image_gz "$(component_image "$comp")" "$package_dir/$tar_rel" \
      || die "docker save 失败: $comp"
  fi
done

# 随附执行器文件不代表执行器会自动升级；部署基线必须预装支持 upgrade 协议的执行器。
install -m 0755 "$SCRIPT_DIR/install-executor.sh" "$package_dir/installer/install-executor.sh"
install -m 0755 "$SCRIPT_DIR/upgrade-executor.sh" "$package_dir/installer/upgrade-executor.sh"

# 新组件 compose 片段：netmgrd 为首部随升级包引入的组件，宿主旧 compose 未定义该服务，
# 执行器将本片段并入 <DataDir>/upgrade-executor/compose-overrides.d/ 后创建服务。
has_netmgrd=false
for comp in "${COMPONENTS[@]}"; do [[ "$comp" == "netmgrd" ]] && has_netmgrd=true; done
if [[ "$has_netmgrd" == "true" ]]; then
  mkdir -p "$package_dir/compose"
  cat > "$package_dir/compose/upgrade-services.yml" <<EOF
# 升级包新增组件编排片段（build-upgrade-pack.sh 生成，目标版本 ${TO_VERSION}）
# 仅允许定义宿主旧 compose 中不存在的新服务；执行器校验「新增服务集合 == 缺失服务集合」
# 且不得改写既有服务镜像后才并入 compose-overrides.d。
# 服务定义口径对齐 deployment/docker-compose.stage5.yml 的 netmgrd。
services:
  netmgrd:
    image: jiuzhang-netmgrd:${TO_VERSION}
    container_name: jiuzhang-netmgrd
    restart: unless-stopped
    network_mode: service:gateway
    cap_add:
      - NET_RAW
      - NET_ADMIN
    environment:
      NODE_NAME: \${NODE_NAME:-gateway-01}
    volumes:
      # 与防护网关共享 Admin Socket 卷（文件契约轮询通道）
      - gateway-admin:/var/run/caddy
    depends_on:
      gateway: {condition: service_started}

volumes:
  gateway-admin: {driver: local}
EOF
fi

# ---------- 清单（双口径 manifest.json + SHA256SUMS 纵深） ----------

(
  cd "$package_dir"
  # compose/ 仅含新组件（netmgrd）时存在；目录清单动态拼，避免 find 因缺目录返回非零
  sum_dirs=(images installer)
  [[ -d compose ]] && sum_dirs+=(compose)
  find "${sum_dirs[@]}" -type f | LC_ALL=C sort \
    | while IFS= read -r f; do
        printf '%s  %s\n' "$(sha256_of "$f" | awk '{print $1}')" "$f"
      done > SHA256SUMS
)

# files 清单：包内除 manifest.json/manifest.sig 外的全部常规文件（服务端口径：一一对应，
# 两个保留根文件均不得收录）；路径强制白名单，python3 紧凑序列化 == Go json.Marshal。
# 注意构建顺序：本步先于 manifest.json 写入与 manifest.sig 签名，两文件天然不在清单内。
files_info="$(python3 - "$package_dir" <<'PY'
import hashlib, json, os, re, sys
root = sys.argv[1]
pat = re.compile(r'^[A-Za-z0-9._/-]+$')
files = []
for dirpath, dirnames, filenames in os.walk(root):
    dirnames.sort()
    for name in sorted(filenames):
        full = os.path.join(dirpath, name)
        if not os.path.isfile(full) or os.path.islink(full):
            continue
        rel = os.path.relpath(full, root).replace(os.sep, '/')
        if rel in ('manifest.json', 'manifest.sig'):
            continue
        if not pat.match(rel) or '..' in rel.split('/') or rel.startswith('/'):
            sys.stderr.write('包内路径不符合白名单: %s\n' % rel)
            sys.exit(1)
        h = hashlib.sha256()
        size = 0
        with open(full, 'rb') as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                h.update(chunk)
                size += len(chunk)
        files.append({'path': rel, 'sha256': h.hexdigest(), 'size': size})
if not files:
    sys.stderr.write('包内无可收录文件\n')
    sys.exit(1)
compact = json.dumps(files, separators=(',', ':'), ensure_ascii=False)
print(compact)
print(hashlib.sha256(compact.encode('utf-8')).hexdigest())
PY
)" || die "生成 files 清单失败"
files_json="$(printf '%s\n' "$files_info" | sed -n '1p')"
files_digest="$(printf '%s\n' "$files_info" | sed -n '2p')"
[[ "$files_digest" =~ ^[0-9a-f]{64}$ ]] || die "files_manifest_sha256 计算异常"

components_json="$(jq -cn '$ARGS.positional' --args "${COMPONENTS[@]}")"
images_json="$(for comp in "${COMPONENTS[@]}"; do
  jq -cn --arg c "$comp" --arg img "$(component_image "$comp")" --arg tar "images/${comp}-${ARCH}.tar.gz" \
    '{component:$c, service:$c, image:$img, tar:$tar}'
done | jq -s '.')"

jq -n \
  --arg fmt "1" \
  --arg ptype "upgrade" \
  --arg ctype "$CHANGE_TYPE" \
  --arg product "wdsp" \
  --arg version "$TO_VERSION" \
  --arg from "$FROM_VERSION" \
  --arg to "$TO_VERSION" \
  --arg arch "$ARCH" \
  --argjson schema "$TARGET_SCHEMA" \
  --argjson components "$components_json" \
  --argjson images "$images_json" \
  --argjson files "$files_json" \
  --arg files_digest "$files_digest" \
  '{
    format_version: $fmt,
    package_type: $ptype,
    change_type: $ctype,
    product: $product,
    version: $version,
    version_from: $from,
    version_to: $to,
    arch: $arch,
    target_schema_version: $schema,
    components: $components,
    images: $images,
    files: $files,
    files_manifest_sha256: $files_digest
  }' > "$package_dir/manifest.json"

# ---------- 包内签名（manifest.sig）与归档前校验 ----------

if [[ "$PKG_SIGNED" == "true" ]]; then
  # 对 manifest.json 原始字节签名（openssl pkeyutl -sign -rawin，与 ed25519_sign_file
  # 同算法，仅输入从整包变为 manifest.json）；manifest.sig 不进 files 清单、不参与
  # files_manifest_sha256（files 清单已于上一步定稿）。
  ed25519_sign_file "$SIGNING_KEY" "$package_dir/manifest.json" "$package_dir/manifest.sig" \
    || die "manifest.json 签名失败"
  # 契约要求 base64 单行文本；GNU base64 默认 76 列换行，统一归一为单行（保留结尾换行）
  { tr -d '\r\n' < "$package_dir/manifest.sig"; printf '\n'; } > "$package_dir/manifest.sig.tmp"
  mv "$package_dir/manifest.sig.tmp" "$package_dir/manifest.sig"
fi

# 归档前校验：根目录恰含预期条目（manifest.json、[manifest.sig、]images/、installer/、
# [compose/、]SHA256SUMS），无 ._* / .DS_Store 垃圾文件（归档后另有兜底校验）。
expected_root=(SHA256SUMS images installer manifest.json)
[[ "$PKG_SIGNED" == "true" ]] && expected_root+=(manifest.sig)
[[ "$has_netmgrd" == "true" ]] && expected_root+=(compose)
junk_entries="$(cd "$package_dir" && find . \( -name '._*' -o -name '.DS_Store' \) -print)"
[[ -z "$junk_entries" ]] || die "包目录含 ._* / .DS_Store 垃圾文件，已中止；请检查构建环境"
actual_root="$(cd "$package_dir" && find . -mindepth 1 -maxdepth 1 | sed 's|^\./||' | LC_ALL=C sort | tr '\n' ' ')"
expected_root_sorted="$(printf '%s\n' "${expected_root[@]}" | LC_ALL=C sort | tr '\n' ' ')"
[[ "$actual_root" == "$expected_root_sorted" ]] \
  || die "包根目录内容不符预期（实际: ${actual_root}；预期: ${expected_root_sorted}）"

archive="$work_dir/$package_name.tar.gz"
# COPYFILE_DISABLE=1：禁止 macOS bsdtar 把扩展属性写成 ._ AppleDouble 条目
# （._ 条目会破坏服务端 commonArchiveRoot 单一根目录判定与 files 一一对应；GNU tar 忽略该变量）。
COPYFILE_DISABLE=1 tar -C "$work_dir" -czf "$archive" "$package_name"
# 兜底校验：归档内不得出现 AppleDouble/系统垃圾文件（无论 tar 实现）
if tar -tzf "$archive" | grep -E '(^|/)\._|\.DS_Store' >/dev/null 2>&1; then
  die "归档含 ._/.DS_Store 垃圾条目（AppleDouble），已中止；请检查 tar 环境"
fi
printf '%s  %s\n' "$(sha256_of "$archive" | awk '{print $1}')" "$(basename "$archive")" > "$archive.sha256"

# ---------- 验签自检（模拟服务端口径：从归档抽回 manifest.json + manifest.sig 用公钥验） ----------

if [[ "$PKG_SIGNED" == "true" ]]; then
  verify_dir="$work_dir/verify"
  mkdir -p "$verify_dir"
  tar -xzf "$archive" -C "$verify_dir" \
    "$package_name/manifest.json" "$package_name/manifest.sig" \
    || die "自检抽包失败（归档内缺 manifest.json/manifest.sig）: $archive"
  ed25519_verify_file "$TRUSTED_PUB" \
    "$verify_dir/$package_name/manifest.json" "$verify_dir/$package_name/manifest.sig" \
    || die "升级包签名自检失败（归档内 manifest.json/manifest.sig 验签不通过）: $archive"
  log_info "包内 manifest.sig（Ed25519 over manifest.json 归档字节）已按服务端口径自检通过"
fi

# 仅在全部自检通过后发布，noclobber 防止并发打包覆盖已有交付物。
( set -o noclobber; cat "$archive" > "$OUTPUT_DIR/$package_name.tar.gz" ) \
  || die "发布失败，目标文件已存在或无法写入"
( set -o noclobber; cat "$archive.sha256" > "$OUTPUT_DIR/$package_name.tar.gz.sha256" ) \
  || die "写入校验文件失败"
archive="$OUTPUT_DIR/$package_name.tar.gz"

log_info "已生成: ${archive}（组件: ${COMPONENTS[*]}，目标迁移号 ${TARGET_SCHEMA}）"
if [[ "$PKG_SIGNED" == "true" ]]; then
  log_info "旁车: $(basename "$archive").sha256（签名 manifest.sig 已内嵌包内，无独立 .sig）"
else
  log_info "旁车: $(basename "$archive").sha256（未签名，包内无 manifest.sig）"
fi

if [[ "$PKG_SIGNED" != "true" ]]; then
  log_warn "未签名包仅可用于本地联调；服务端从包内读取 manifest.sig 验签，未签名/自签包将登记 REJECTED"
  exit 0
fi
cat <<EOF

---------- 前台上传（系统升级页面） ----------
已生成可上传升级包：${archive}
版本区间（${FROM_VERSION} → ${TO_VERSION}）与签名均内嵌于包内 manifest.json / manifest.sig。
仅可通过前台“系统升级”页面上传此 .tar.gz；页面会校验内嵌版本和签名，并按所选的立即或定时策略创建升级任务。
本脚本只生成与校验交付物，不会上传、部署或触发升级。
EOF
