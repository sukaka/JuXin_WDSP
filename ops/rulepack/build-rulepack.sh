#!/usr/bin/env bash
# build-rulepack.sh —— 九章 WDSP 纯离线 WAF 规则包制作与签名脚本（阶段 R1）。
#
# 用法：
#   WDSP_SIGNING_KEY=/path/to/ed25519-private.pem \
#     bash ops/rulepack/build-rulepack.sh \
#       --version 20261201.1 \
#       --min-system-version 1.19.1 \
#       --changelog "新增 CVE-2026-XXXXX 应急防护规则"
#
# 产物（输出至 dist/，同名产物存在时拒绝覆盖）：
#   - jiuzhang-wdsp-rulepack-<VERSION>.tar.gz       （内嵌 manifest.json + manifest.sig + rules/）
#   - jiuzhang-wdsp-rulepack-<VERSION>.tar.gz.sha256
#
# 质量门禁（任一失败拒绝出包）：
#   1. 版本号格式校验（YYYYMMDD.N）与必填参数检查；
#   2. 静态扫描：必备锚点、扩展名白名单、禁用操作符（@inspectFile/SecRuleScript/@rbl）、@pmFromFile 完整性；
#   3. Go 规则解析单测（go test ./internal/wafrules/...）；
#   4. 可选真实 Caddy/Coraza 语法校验（--caddy-bin 或 --caddy-image）；
#   5. 紧凑确定性 manifest.json + Ed25519 签名（正式构建严禁无私钥或公钥不匹配）；
#   6. 使用 server/cmd/rulepackverify（与生产同源验签与静态门禁代码）端到端复验最终归档。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"
# shellcheck source=../lib/signing.sh
source "$SCRIPT_DIR/../lib/signing.sh"

VERSION=""
MIN_SYSTEM_VERSION="1.19.1"
CORAZA_COMPAT=">=3.7.0 <4.0.0"
RULES_SRC="$REPO_ROOT/gateway/rules"
OUT_DIR="$REPO_ROOT/dist"
RELEASE_PUBKEY="$REPO_ROOT/ops/offline-package/release-signing.pub"
CHANGELOG_ITEMS=()
CHANGELOG_FILE=""
HIGHLIGHTED_CVES=()
CADDY_BIN=""
SKIP_GO_TEST=false
ALLOW_DEV_KEY=false
DEV_PUBKEY_OUT=""

usage() {
  cat <<'EOF'
用法: bash ops/rulepack/build-rulepack.sh --version YYYYMMDD.N [选项]

必填:
  --version VER                规则包版本号（单调递增 YYYYMMDD.N，如 20261201.1）

常用选项:
  --min-system-version VER     最低兼容系统版本（默认 1.19.1）
  --coraza-compat RANGE        Coraza 引擎兼容范围说明（默认 ">=3.7.0 <4.0.0"）
  --rules-dir DIR              源规则目录（默认 gateway/rules）
  --out-dir DIR                输出目录（默认 dist）
  --changelog TEXT             更新摘要条目（可多次传入）
  --changelog-file FILE        从文本文件读取更新摘要（每行一条，忽略空行与 # 注释）
  --cve CVE-ID                 重点新增 CVE（可多次传入）
  --caddy-bin PATH             可选：使用定制 caddy 二进制执行真实 Coraza 语法校验
  --skip-go-test               跳过 go test ./internal/wafrules/...（仅加速本地联调，正式发布勿用）
  --dev-ephemeral-key          本地开发自测模式：自动生成临时 Ed25519 密钥对签名（严禁用于生产交付）
  -h, --help                   显示帮助

环境变量:
  WDSP_SIGNING_KEY             正式发布 Ed25519 私钥路径（必须与 ops/offline-package/release-signing.pub 匹配）
  WDSP_OPENSSL_BIN             可选：指定 OpenSSL 3 可执行文件路径（macOS 建议 /opt/homebrew/opt/openssl@3/bin/openssl）
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --min-system-version) MIN_SYSTEM_VERSION="${2:-}"; shift 2 ;;
    --coraza-compat) CORAZA_COMPAT="${2:-}"; shift 2 ;;
    --rules-dir) RULES_SRC="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    --changelog) CHANGELOG_ITEMS+=("${2:-}"); shift 2 ;;
    --changelog-file) CHANGELOG_FILE="${2:-}"; shift 2 ;;
    --cve) HIGHLIGHTED_CVES+=("${2:-}"); shift 2 ;;
    --caddy-bin) CADDY_BIN="${2:-}"; shift 2 ;;
    --skip-go-test) SKIP_GO_TEST=true; shift ;;
    --dev-ephemeral-key) ALLOW_DEV_KEY=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数: $1（使用 --help 查看用法）" ;;
  esac
done

[[ -n "$VERSION" ]] || die "必须通过 --version 指定规则包版本号（格式 YYYYMMDD.N）"
[[ "$VERSION" =~ ^[0-9]{8}\.[0-9]{1,3}$ ]] || die "无效规则包版本号 '$VERSION'（须为 YYYYMMDD.N，如 20261201.1）"
[[ -d "$RULES_SRC" ]] || die "规则源目录不存在: $RULES_SRC"

# 选择支持 Ed25519 pkeyutl -rawin 的 OpenSSL 3
OPENSSL_BIN="${WDSP_OPENSSL_BIN:-}"
if [[ -z "$OPENSSL_BIN" ]]; then
  for cand in /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl "$(command -v openssl || true)"; do
    if [[ -n "$cand" && -x "$cand" ]] && "$cand" version 2>/dev/null | grep -qiE 'OpenSSL [3-9]\.'; then
      OPENSSL_BIN="$cand"
      break
    fi
  done
fi
[[ -n "$OPENSSL_BIN" ]] || die "未找到 OpenSSL 3.x（请安装 OpenSSL 3 或设置 WDSP_OPENSSL_BIN）"

# 选择 Python 3
PYTHON_BIN="${PYTHON3:-$(command -v python3 || true)}"
[[ -n "$PYTHON_BIN" ]] || die "未找到 python3"
require_cmd tar gzip go

# 校验输出目标不覆盖已有产物
mkdir -p "$OUT_DIR"
PKG_NAME="jiuzhang-wdsp-rulepack-${VERSION}.tar.gz"
OUT_TAR="${OUT_DIR}/${PKG_NAME}"
OUT_SHA="${OUT_TAR}.sha256"
[[ ! -e "$OUT_TAR" ]] || die "目标文件已存在，拒绝覆盖: $OUT_TAR"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/jz-rulepack-build.XXXXXX")"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

# 解析或生成签名密钥
SIGN_KEY="${WDSP_SIGNING_KEY:-}"
VERIFY_PUBKEY="$RELEASE_PUBKEY"
if [[ -n "$SIGN_KEY" ]]; then
  [[ -f "$SIGN_KEY" ]] || die "WDSP_SIGNING_KEY 指向的私钥不存在: $SIGN_KEY"
  # 验证私钥与官方发布公钥严格匹配
  derived_pub="$WORK_DIR/derived.pub"
  "$OPENSSL_BIN" pkey -in "$SIGN_KEY" -pubout -out "$derived_pub" 2>/dev/null \
    || die "无法从 WDSP_SIGNING_KEY 导出公钥，请确认其为合法 Ed25519 私钥"
  if [[ -f "$RELEASE_PUBKEY" ]]; then
    if ! cmp -s "$derived_pub" "$RELEASE_PUBKEY"; then
      die "WDSP_SIGNING_KEY 与官方公钥 $RELEASE_PUBKEY 不匹配，拒绝出包"
    fi
  fi
elif [[ "$ALLOW_DEV_KEY" == "true" ]]; then
  log_warn "开发自测模式：正在生成临时 Ed25519 密钥对（产物严禁用于生产环境！）"
  SIGN_KEY="$WORK_DIR/dev-ephemeral.pem"
  VERIFY_PUBKEY="$WORK_DIR/dev-ephemeral.pub"
  "$OPENSSL_BIN" genpkey -algorithm ED25519 -out "$SIGN_KEY" 2>/dev/null
  "$OPENSSL_BIN" pkey -in "$SIGN_KEY" -pubout -out "$VERIFY_PUBKEY" 2>/dev/null
  DEV_PUBKEY_OUT="${OUT_DIR}/jiuzhang-wdsp-rulepack-${VERSION}.dev.pub"
  cp "$VERIFY_PUBKEY" "$DEV_PUBKEY_OUT"
else
  die "正式打包必须设置 WDSP_SIGNING_KEY 指向发布 Ed25519 私钥（本地开发自测请显式传 --dev-ephemeral-key）"
fi

# 1. 读取 CRS 版本号
CRS_VERSION_FILE="$RULES_SRC/crs/VERSION.txt"
[[ -f "$CRS_VERSION_FILE" ]] || die "缺少 $CRS_VERSION_FILE"
CRS_VERSION="$(grep -vE '^\s*(#|$)' "$CRS_VERSION_FILE" | head -n 1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)?' | head -n 1 || true)"
[[ -n "$CRS_VERSION" ]] || die "无法从 $CRS_VERSION_FILE 读取 CRS 版本号"
log_info "规则包版本: ${VERSION} | OWASP CRS: ${CRS_VERSION} | 最低系统版本: ${MIN_SYSTEM_VERSION}"

# 2. 拷贝干净规则树至工作区（剥离 .DS_Store 与符号链接检查）
STAGE_ROOT="$WORK_DIR/pkg"
mkdir -p "$STAGE_ROOT/rules"
if find "$RULES_SRC" -type l | grep -q .; then
  die "规则源目录 $RULES_SRC 包含符号链接，拒绝打包"
fi
cp -R "$RULES_SRC"/. "$STAGE_ROOT/rules/"
find "$STAGE_ROOT/rules" -name '.DS_Store' -delete

# 3. 运行 Go wafrules 单测门禁
if [[ "$SKIP_GO_TEST" != "true" ]]; then
  log_info "运行规则解析与中文化单测 (go test ./internal/wafrules/...)..."
  (cd "$REPO_ROOT/server" && go test ./internal/wafrules/...)
fi

# 4. 可选真实 Caddy / Coraza 语法校验
if [[ -n "$CADDY_BIN" ]]; then
  [[ -x "$CADDY_BIN" ]] || die "--caddy-bin 不可执行: $CADDY_BIN"
  log_info "使用 $CADDY_BIN 执行真实 Coraza 规则编译校验..."
  test_cf="$WORK_DIR/validate.Caddyfile"
  cat > "$test_cf" <<EOF
{
  admin off
  auto_https off
  order coraza_waf first
}
:0 {
  coraza_waf {
    directives \`
      SecRuleEngine DetectionOnly
      Include $STAGE_ROOT/rules/coraza.conf
      Include $STAGE_ROOT/rules/crs/crs-setup.conf
      Include $STAGE_ROOT/rules/crs/plugins/*/plugins/*-config.conf
      Include $STAGE_ROOT/rules/crs/plugins/*/plugins/*-before.conf
      Include $STAGE_ROOT/rules/exclusions/before-crs.conf
      Include $STAGE_ROOT/rules/crs/rules/*.conf
      Include $STAGE_ROOT/rules/contrib/*/*.conf
      Include $STAGE_ROOT/rules/crs/plugins/*/plugins/*-after.conf
      Include $STAGE_ROOT/rules/exclusions/after-crs.conf
      Include $STAGE_ROOT/rules/jiuzhang/jiuzhang-custom.conf
      Include $STAGE_ROOT/rules/jiuzhang/post-contrib-blocking.conf
    \`
  }
  respond 204
}
EOF
  "$CADDY_BIN" validate --config "$test_cf" --adapter caddyfile
fi

# 5. 生成紧凑确定性 manifest.json（与 Go json.Marshal 字节一致）
CHANGELOG_JSON_FILE="$WORK_DIR/changelog.json"
"$PYTHON_BIN" - "$CHANGELOG_FILE" "$CHANGELOG_JSON_FILE" "${CHANGELOG_ITEMS[@]}" <<'PY'
import json, sys
cl_file = sys.argv[1]
out_path = sys.argv[2]
items = [x.strip() for x in sys.argv[3:] if x.strip()]
if cl_file:
    with open(cl_file, 'r', encoding='utf-8') as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith('#'):
                items.append(s)
with open(out_path, 'w', encoding='utf-8') as out:
    json.dump(items, out, ensure_ascii=False)
PY

CVES_JSON_FILE="$WORK_DIR/cves.json"
"$PYTHON_BIN" - "$CVES_JSON_FILE" "${HIGHLIGHTED_CVES[@]}" <<'PY'
import json, sys
out_path = sys.argv[1]
cves = sorted({x.strip().upper() for x in sys.argv[2:] if x.strip()})
with open(out_path, 'w', encoding='utf-8') as out:
    json.dump(cves, out, ensure_ascii=False)
PY

"$PYTHON_BIN" - "$STAGE_ROOT" "$VERSION" "$CRS_VERSION" "$MIN_SYSTEM_VERSION" "$CORAZA_COMPAT" "$CHANGELOG_JSON_FILE" "$CVES_JSON_FILE" <<'PY'
import datetime, hashlib, json, os, re, sys

stage_root, version, crs_ver, min_sys, coraza_compat, cl_path, cves_path = sys.argv[1:8]
rules_dir = os.path.join(stage_root, 'rules')
path_re = re.compile(r'^[A-Za-z0-9._/-]+$')

files = []
for dirpath, dirnames, filenames in os.walk(rules_dir):
    dirnames.sort()
    filenames.sort()
    for fn in filenames:
        full = os.path.join(dirpath, fn)
        rel = os.path.relpath(full, stage_root).replace(os.sep, '/')
        if not path_re.match(rel):
            raise SystemExit(f'非法归档路径字符: {rel}')
        h = hashlib.sha256()
        size = 0
        with open(full, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
                size += len(chunk)
        files.append({'path': rel, 'sha256': h.hexdigest(), 'size': size})

files.sort(key=lambda x: x['path'])
# 紧凑序列化，确保与 Go json.Marshal(manifest.Files) 字节完全一致
files_compact = json.dumps(files, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
files_digest = hashlib.sha256(files_compact).hexdigest()

with open(cl_path, 'r', encoding='utf-8') as f:
    changelog = json.load(f)
with open(cves_path, 'r', encoding='utf-8') as f:
    cves = json.load(f)

manifest = {
    'schema_version': 1,
    'product': 'wdsp',
    'package_type': 'rulepack',
    'rulepack_version': version,
    'crs_version': crs_ver,
    'min_system_version': min_sys,
    'coraza_compat': coraza_compat,
    'released_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    'changelog': changelog,
    'rule_summary': {
        'highlighted_cves': cves,
    },
    'files': files,
    'files_manifest_sha256': files_digest,
}

manifest_path = os.path.join(stage_root, 'manifest.json')
with open(manifest_path, 'wb') as out:
    out.write(json.dumps(manifest, indent=2, ensure_ascii=False).encode('utf-8'))
    out.write(b'\n')
PY

# 6. 使用 Ed25519 私钥签名 manifest.json -> 内嵌 manifest.sig（单行 base64）
SIG_RAW="$WORK_DIR/manifest.sig.raw"
"$OPENSSL_BIN" pkeyutl -sign -inkey "$SIGN_KEY" -rawin -in "$STAGE_ROOT/manifest.json" -out "$SIG_RAW"
base64 < "$SIG_RAW" | tr -d '\r\n' > "$STAGE_ROOT/manifest.sig"
printf '\n' >> "$STAGE_ROOT/manifest.sig"

# 7. 打包 tar.gz（禁用 macOS AppleDouble 扩展属性头）并生成 .sha256 旁车
log_info "打包归档: $OUT_TAR"
COPYFILE_DISABLE=1 tar -C "$STAGE_ROOT" -czf "$OUT_TAR" manifest.json manifest.sig rules
(cd "$OUT_DIR" && sha256_of "$PKG_NAME" | awk -v f="$PKG_NAME" '{print $1 "  " f}' > "$OUT_SHA")

# 8. 端到端自检：调用与管理后端完全一致的 Go rulepackverify 校验归档、签名与静态门禁
log_info "执行 Go 端到端自检 (rulepackverify)..."
verify_args=(--package "$OUT_TAR" --system-version "$MIN_SYSTEM_VERSION")
if [[ "$ALLOW_DEV_KEY" == "true" ]]; then
  verify_args+=(--pubkey "$VERIFY_PUBKEY")
fi
(cd "$REPO_ROOT/server" && go run ./cmd/rulepackverify "${verify_args[@]}")

log_info "离线规则包构建与自检完成:"
log_info "  归档: $OUT_TAR"
log_info "  摘要: $OUT_SHA"
if [[ -n "$DEV_PUBKEY_OUT" ]]; then
  log_warn "  开发测试公钥: ${DEV_PUBKEY_OUT}（仅用于本地测试，严禁交付生产）"
fi
