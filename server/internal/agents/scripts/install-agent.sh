#!/usr/bin/env bash
# 九章 WDSP 分布式流量采集 Agent 一键安装脚本（Linux CentOS/RHEL/Debian/Ubuntu 与 macOS）
#
# 安全约定（跨平台契约 §1/§4.2）：
#   - Enrollment Token 仅通过环境变量 WDSP_ENROLL_TOKEN 或 --token-file 传入；
#   - 严禁将 Token 放进 URL Query；curl 经 0600 临时配置文件发送 Authorization Header，不暴露到进程列表；
#   - 下载安装包后强制核对 SHA-256，校验失败立即中止。
set -euo pipefail

SERVER=""
TOKEN_FILE=""
FORMAT="auto"
ARCH_OVERRIDE=""
BACKEND=""
LOCAL_PACKAGE=""
EXPECTED_SHA256=""
INSECURE=false
FORCE_REENROLL=false
NO_START=false
SKIP_SERVICE=false
CONFIG_PATH=""
STATE_DIR=""

usage() {
  cat <<'EOF'
用法:
  在线安装（从 WDSP 管理面拉取对应平台安装包并注册）:
    WDSP_ENROLL_TOKEN='wdt_...' sudo -E bash install-agent.sh --server https://wdsp.example.com [选项]

  离线安装（使用本地已下载的 .rpm / .deb / .pkg / .tar.gz）:
    WDSP_ENROLL_TOKEN='wdt_...' sudo -E bash install-agent.sh --server https://wdsp.example.com --local-package /path/to/pkg [--sha256 <hex>] [选项]

选项:
  --server <url>            WDSP 管理面地址（必填，除非复用既有配置）
  --token-file <path>       包含一次性 Enrollment Token 的文件路径（优先于 WDSP_ENROLL_TOKEN）
  --format <fmt>            指定安装格式: auto|rpm|deb|pkg|targz（默认 auto）
  --arch <arch>             覆盖 CPU 架构: amd64|arm64（默认自动检测）
  --backend <name>          本地抓包后端: auto|ebpf|afpacket|bpf
  --local-package <path>    离线安装包本地路径（跳过远程下载）
  --sha256 <hex>            离线包期望 SHA-256 校验和（可选；提供时强制校验）
  --config <path>           自定义 agent.json 路径
  --state-dir <dir>         自定义状态目录
  --insecure-skip-verify    跳过服务端 TLS 证书校验（仅自签实验环境，生产禁止）
  --force-reenroll          已存在 agent.json 时强制重新注册
  --no-start                仅安装注册，不启动系统服务
  --skip-service            跳过系统服务注册（适用于无 systemd 容器）
  -h, --help                显示帮助
EOF
}

log_info() { printf '[wdsp-agent-install] %s\n' "$*"; }
log_warn() { printf '[wdsp-agent-install][WARN] %s\n' "$*" >&2; }
die() { printf '[wdsp-agent-install][ERROR] %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER="${2:-}"; shift 2 ;;
    --token-file) TOKEN_FILE="${2:-}"; shift 2 ;;
    --format) FORMAT="${2:-}"; shift 2 ;;
    --arch) ARCH_OVERRIDE="${2:-}"; shift 2 ;;
    --backend) BACKEND="${2:-}"; shift 2 ;;
    --local-package) LOCAL_PACKAGE="${2:-}"; shift 2 ;;
    --sha256) EXPECTED_SHA256="${2:-}"; shift 2 ;;
    --config) CONFIG_PATH="${2:-}"; shift 2 ;;
    --state-dir) STATE_DIR="${2:-}"; shift 2 ;;
    --insecure-skip-verify) INSECURE=true; shift ;;
    --force-reenroll) FORCE_REENROLL=true; shift ;;
    --no-start) NO_START=true; shift ;;
    --skip-service) SKIP_SERVICE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数: $1" ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "请以 root 权限执行本安装脚本（sudo -E bash ...）"

case "$FORMAT" in
  auto|rpm|deb|pkg|targz) ;;
  *) die "不支持的 --format: $FORMAT" ;;
esac

detect_os() {
  case "$(uname -s)" in
    Linux) echo "linux" ;;
    Darwin) echo "darwin" ;;
    *) die "不支持的操作系统: $(uname -s)" ;;
  esac
}

detect_arch() {
  if [[ -n "$ARCH_OVERRIDE" ]]; then
    case "$ARCH_OVERRIDE" in
      amd64|arm64) echo "$ARCH_OVERRIDE"; return ;;
      *) die "不支持的 --arch: $ARCH_OVERRIDE" ;;
    esac
  fi
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "不支持的 CPU 架构: $(uname -m)" ;;
  esac
}

detect_format() {
  local os="$1"
  if [[ "$FORMAT" != "auto" ]]; then
    echo "$FORMAT"
    return
  fi
  if [[ "$os" == "darwin" ]]; then
    if command -v installer >/dev/null 2>&1; then
      echo "pkg"
    else
      echo "targz"
    fi
    return
  fi
  # Linux: 优先按发行版包管理器识别
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-} ${ID_LIKE:-}" in
      *debian*|*ubuntu*|*kylin*|*uos*)
        if command -v dpkg >/dev/null 2>&1; then echo "deb"; return; fi ;;
      *centos*|*rhel*|*rocky*|*almalinux*|*fedora*|*openeuler*|*alinux*|*anolis*|*suse*)
        if command -v rpm >/dev/null 2>&1; then echo "rpm"; return; fi ;;
    esac
  fi
  if command -v dpkg >/dev/null 2>&1; then
    echo "deb"
  elif command -v rpm >/dev/null 2>&1; then
    echo "rpm"
  else
    die "无法识别 Linux 包管理器（未找到 dpkg 或 rpm），请使用 --local-package 手动部署二进制"
  fi
}

calc_sha256() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print tolower($1)}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{print tolower($NF)}'
  else
    die "系统缺少 sha256sum / shasum / openssl，无法完成强制完整性校验"
  fi
}

resolve_token() {
  if [[ -n "$TOKEN_FILE" ]]; then
    [[ -r "$TOKEN_FILE" ]] || die "无法读取 --token-file: $TOKEN_FILE"
    tr -d ' \t\r\n' < "$TOKEN_FILE"
    return
  fi
  printf '%s' "${WDSP_ENROLL_TOKEN:-}" | tr -d ' \t\r\n'
}

OS="$(detect_os)"
ARCH="$(detect_arch)"
PKG_FORMAT="$(detect_format "$OS")"
TOKEN="$(resolve_token)"

if [[ -n "$SERVER" ]]; then
  SERVER="${SERVER%/}"
  case "$SERVER" in
    http://*|https://*) ;;
    *) SERVER="https://${SERVER}" ;;
  esac
fi

umask 077
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wdsp-agent-install.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

PKG_FILE=""

if [[ -n "$LOCAL_PACKAGE" ]]; then
  [[ -f "$LOCAL_PACKAGE" ]] || die "离线安装包不存在: $LOCAL_PACKAGE"
  PKG_FILE="$LOCAL_PACKAGE"
  case "$PKG_FILE" in
    *.rpm) PKG_FORMAT="rpm" ;;
    *.deb) PKG_FORMAT="deb" ;;
    *.pkg) PKG_FORMAT="pkg" ;;
    *.tar.gz|*.tgz) PKG_FORMAT="targz" ;;
  esac
  if [[ -n "$EXPECTED_SHA256" ]]; then
    actual="$(calc_sha256 "$PKG_FILE")"
    expected="$(printf '%s' "$EXPECTED_SHA256" | tr 'A-Z' 'a-z')"
    [[ "$actual" == "$expected" ]] || die "离线包 SHA-256 校验失败: actual=$actual expected=$expected"
    log_info "离线包 SHA-256 校验通过: $actual"
  fi
else
  [[ -n "$SERVER" ]] || die "在线安装必须指定 --server <https://...>"
  [[ -n "$TOKEN" ]] || die "在线安装必须提供 WDSP_ENROLL_TOKEN 或 --token-file"
  command -v curl >/dev/null 2>&1 || die "在线安装需要 curl 命令"
  SERVER="${SERVER%/}"

  # 通过 0600 临时配置文件传 Authorization Header，避免 Token 暴露在 ps 参数中
  CURL_CFG="$WORK_DIR/curl.cfg"
  printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" > "$CURL_CFG"
  chmod 0600 "$CURL_CFG"

  CURL_OPTS=(--fail --silent --show-error --location --connect-timeout 15 --max-time 300 --config "$CURL_CFG")
  if [[ "$INSECURE" == true ]]; then
    CURL_OPTS+=(--insecure)
  fi

  # macOS 若服务端未提供 .pkg，自动回退 .tar.gz
  download_pkg() {
    local fmt="$1"
    local url="${SERVER}/api/v1/agents/bootstrap/packages/${OS}/${ARCH}/${fmt}"
    local hdr_file="$WORK_DIR/resp.headers"
    local out_file="$WORK_DIR/package.${fmt}"
    rm -f "$hdr_file" "$out_file"
    if ! curl "${CURL_OPTS[@]}" -D "$hdr_file" -o "$out_file" "$url"; then
      return 1
    fi
    local srv_sha
    srv_sha="$(tr -d '\r' < "$hdr_file" | awk -F':' 'tolower($1) == "x-wdsp-sha256" {gsub(/^[ \t]+|[ \t]+$/, "", $2); print tolower($2)}' | tail -n 1)"
    [[ -n "$srv_sha" && ${#srv_sha} -eq 64 ]] || die "服务端响应缺少合法 X-WDSP-SHA256 校验头，已中止安装"
    local actual_sha
    actual_sha="$(calc_sha256 "$out_file")"
    [[ "$actual_sha" == "$srv_sha" ]] || die "安装包 SHA-256 校验不匹配: actual=$actual_sha expected=$srv_sha"
    log_info "下载并校验通过 (${OS}/${ARCH}/${fmt}): sha256=${actual_sha}"
    PKG_FILE="$out_file"
    PKG_FORMAT="$fmt"
    return 0
  }

  log_info "正在从 ${SERVER} 拉取 ${OS}/${ARCH}/${PKG_FORMAT} 安装包..."
  if ! download_pkg "$PKG_FORMAT"; then
    if [[ "$OS" == "darwin" && "$PKG_FORMAT" == "pkg" ]]; then
      log_warn "未获取到 macOS .pkg，回退拉取 .tar.gz 安装包..."
      download_pkg "targz" || die "无法从 ${SERVER} 下载 macOS 安装包（请检查令牌有效性与服务端安装包目录）"
    else
      die "无法从 ${SERVER} 下载 ${OS}/${ARCH}/${PKG_FORMAT} 安装包（请检查令牌有效性与服务端安装包目录）"
    fi
  fi
fi

log_info "正在安装 ${PKG_FORMAT} 包: ${PKG_FILE}"
case "$PKG_FORMAT" in
  rpm)
    rpm -Uvh --replacepkgs "$PKG_FILE"
    ;;
  deb)
    dpkg -i "$PKG_FILE"
    ;;
  pkg)
    installer -pkg "$PKG_FILE" -target /
    ;;
  targz)
    EXTRACT_DIR="$WORK_DIR/extract"
    mkdir -p "$EXTRACT_DIR"
    tar -xzf "$PKG_FILE" -C "$EXTRACT_DIR"
    BIN_SRC="$(find "$EXTRACT_DIR" -maxdepth 3 -type f -name 'wdsp-agent' | head -n 1)"
    [[ -n "$BIN_SRC" ]] || die "tar.gz 包内未找到 wdsp-agent 二进制"
    install -d -m 0755 /usr/local/bin
    install -m 0755 "$BIN_SRC" /usr/local/bin/wdsp-agent
    ;;
  *)
    die "未知安装格式: $PKG_FORMAT"
    ;;
esac

AGENT_BIN="/usr/local/bin/wdsp-agent"
[[ -x "$AGENT_BIN" ]] || die "安装后未找到可执行文件: $AGENT_BIN"
log_info "已安装版本: $("$AGENT_BIN" version)"

INSTALL_ARGS=()
[[ -n "$SERVER" ]] && INSTALL_ARGS+=(--server "$SERVER")
[[ -n "$CONFIG_PATH" ]] && INSTALL_ARGS+=(--config "$CONFIG_PATH")
[[ -n "$STATE_DIR" ]] && INSTALL_ARGS+=(--state-dir "$STATE_DIR")
[[ -n "$BACKEND" ]] && INSTALL_ARGS+=(--backend "$BACKEND")
[[ "$INSECURE" == true ]] && INSTALL_ARGS+=(--insecure-skip-verify)
[[ "$FORCE_REENROLL" == true ]] && INSTALL_ARGS+=(--force-reenroll)
[[ "$NO_START" == true ]] && INSTALL_ARGS+=(--no-start)
[[ "$SKIP_SERVICE" == true ]] && INSTALL_ARGS+=(--skip-service)

if [[ -n "$TOKEN_FILE" ]]; then
  INSTALL_ARGS+=(--token-file "$TOKEN_FILE")
elif [[ -n "$TOKEN" ]]; then
  # 经临时 0600 token 文件传给 wdsp-agent install，彻底避免暴露到命令行
  TMP_TOK="$WORK_DIR/enroll.token"
  printf '%s' "$TOKEN" > "$TMP_TOK"
  chmod 0600 "$TMP_TOK"
  INSTALL_ARGS+=(--token-file "$TMP_TOK")
fi

log_info "执行 Agent 注册与服务配置..."
"$AGENT_BIN" install ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}
log_info "安装完成。可使用 '$AGENT_BIN status' 查看运行状态。"
