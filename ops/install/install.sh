#!/usr/bin/env bash
# install.sh —— 九章 WAF 安装向导：离线包真实性验签（Ed25519，内置可信公钥，fail-closed）
# → 完整性校验（旁车 .sha256 + manifest.files，验签通过后的纵深层）
# → 环境检查 → 生成 .env（随机口令/主密钥）→ 启动 → 安装升级执行器 → 三权账号引导。
# 验签在安装任何配置变更前执行；未签名包默认中止（仅 --allow-unsigned 显式放行并醒目告警）。
# 初始口令仅打印一次，不写入任何日志文件。
# 退出码：0=成功 1=失败 2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
# shellcheck source=../lib/signing.sh
source "$SCRIPT_DIR/../lib/signing.sh"

# 内置可信发布公钥（Ed25519，与 ops/offline-package/release-signing.pub 同源；
# 指纹见 docs/DEPLOYMENT.md「离线交付包签名与验签」。生产模式禁止覆盖；
# 仅显式开发模式允许 WDSP_PACKAGE_PUBLIC_KEY 指向测试公钥）。
WDSP_RELEASE_PUBKEY_PEM="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEApGM/1+Y45NHIQ9F6zv5SH0NbiEjFA5hmx22R4nDAGus=
-----END PUBLIC KEY-----"

usage() {
  cat <<'EOF'
用法: install.sh [选项]

安装向导：
  1. 环境检查（docker / compose / 端口 / 内存 / 磁盘 / 时间同步）
  2. 生成 .env（随机 POSTGRES_PASSWORD / VALKEY_PASSWORD / JIUZHANG_MASTER_KEY）
  3. 采集宿主机指纹（离线授权绑定用，写入 runtime/license/host_fingerprint）
  4. 配置宿主机 firewalld（默认仅 80/443；站点其他端口经 --site-ports 显式追加）
  5. 安装 jiuzhang-hostctl systemd 单元（系统控制：重启/关机/恢复出厂；无 systemd 告警跳过）
  6. 启动 compose 项目并等待健康
  7. 安装并启用宿主机升级执行器（完整包必装，供 Web 升级调用）
  8. 初始化三权管理员账号（安全/审计管理员经 API 创建，临时口令仅打印一次）

选项:
  -c, --compose-file FILE  docker compose 文件（默认 docker-compose.yml）
  -e, --env-file FILE      生成的环境文件路径（默认 .env；已存在则拒绝覆盖，除非 --force）
      --api-url URL        管理 API 地址（默认 http://127.0.0.1:18081）
      --gateway-port PORT  网关对外端口检查（默认 80）
      --api-port PORT      API 端口检查（默认 18081）
      --web-port PORT      管理控制台端口检查（默认 8080）
      --site-ports LIST    额外放行的站点端口（逗号分隔，支持区间，如 "8080,8443,9000-9010"）。
                           生产网关 network_mode: host，站点监听端口由管理面发布配置
                           动态决定，安装期无法静态枚举，须按实际发布端口精确追加。
                           切勿图省事放行全部高位端口（1024-65535）：宿主机上任何监听
                           高位端口的无关服务都会被一并暴露到外部
      --force              允许覆盖已存在的 .env
      --no-firewall        跳过 firewalld 放行
      --skip-accounts      跳过三权账号初始化
      --allow-unsigned     放行未签名的离线包（逃生开关，默认关闭）。
                           仅用于本地开发自验；生产环境必须使用官方签名包，
                           使用时输出醒目安全警告
  -h, --help               显示帮助

退出码: 0=成功 1=失败 2=用法错误
EOF
}

GATEWAY_PORT=80
API_PORT=18081
WEB_PORT=8080
SITE_PORTS=""
FORCE=false
NO_FIREWALL=false
SKIP_ACCOUNTS=false
ALLOW_UNSIGNED=false
export WDSP_DEVELOPMENT_MODE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--compose-file) JZ_COMPOSE_FILE="$2"; shift 2 ;;
    -e|--env-file)     JZ_ENV_FILE="$2"; shift 2 ;;
    --api-url)         JZ_API_BASE="$2"; shift 2 ;;
    --gateway-port)    GATEWAY_PORT="$2"; shift 2 ;;
    --api-port)        API_PORT="$2"; shift 2 ;;
    --web-port)        WEB_PORT="$2"; shift 2 ;;
    --site-ports)      SITE_PORTS="$2"; shift 2 ;;
    --force)           FORCE=true; shift ;;
    --no-firewall)     NO_FIREWALL=true; shift ;;
    --skip-accounts)   SKIP_ACCOUNTS=true; shift ;;
    --allow-unsigned)  ALLOW_UNSIGNED=true; shift ;;
    -h|--help)         usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done
# 端口清单格式校验：每项为 1-65535 或起点-终点区间
if [[ -n "$SITE_PORTS" ]]; then
  validate_port_list "$SITE_PORTS" || { log_err "--site-ports 格式非法: ${SITE_PORTS}（逗号分隔端口或区间，如 8080,9000-9010）"; exit 2; }
fi

# ---------- 0. 离线交付包验签与完整性校验（MED-23 后续增强） ----------
# 在任何配置变更、任何包内容执行之前完成：真实性验签（Ed25519，内置可信公钥，
# fail-closed）为信任锚；通过后旁车 .sha256 与 manifest.files 校验保留为纵深。
# 离线包根目录 manifest.json 含 arch 字段（amd64/arm64），与宿主机架构不一致时拒绝安装。
# manifest.json 缺失 delivery_mode/arch 字段的历史包不再作为正式离线交付包接受；
# 非离线包安装（无 manifest.json）跳过本检查。
pkg_manifest=""
for d in "$PWD" "$(cd "$SCRIPT_DIR/../.." && pwd)"; do
  if [[ -f "$d/manifest.json" ]]; then
    pkg_manifest="$d/manifest.json"
    break
  fi
done
PKG_EDITION="waf"
PKG_API_DYNAMIC="false"
PKG_WEB_WAF="true"
if [[ -n "$pkg_manifest" ]]; then
  require_cmd openssl
  pkg_dir="$(cd "$(dirname "$pkg_manifest")" && pwd)"
  pkg_tarball="${pkg_dir}.tar.gz"
  pkg_delivery_mode="$(awk -F'"' '{for(i=1;i<=NF;i++) if($i=="delivery_mode"){print $(i+2); exit}}' "$pkg_manifest")"
  case "$pkg_delivery_mode" in
    production|development) ;;
    *) die "离线包 manifest.json 缺少有效 delivery_mode（production|development），拒绝按正式交付包安装" ;;
  esac
  if [[ "$ALLOW_UNSIGNED" == "true" ]]; then
    [[ "$pkg_delivery_mode" == "development" ]] \
      || die "--allow-unsigned 仅允许 manifest.delivery_mode=development 的开发包；生产包必须使用签名旁车"
    export WDSP_DEVELOPMENT_MODE=1
  fi
  log_info "交付模式：${pkg_delivery_mode}"
  # 第一层：Ed25519 真实性验签（旁车 <包>.tar.gz.sig，发布私钥签名）。
  if [[ -f "$pkg_tarball" ]]; then
    sig_rc=0
    ed25519_verify_sidecar "$pkg_tarball" || sig_rc=$?
    case "$sig_rc" in
      0) log_info "离线包真实性验签通过（Ed25519，旁车 $(basename "$pkg_tarball").sig）" ;;
      2)
        if [[ "$ALLOW_UNSIGNED" == "true" ]]; then
          log_warn "==================== 安全警告：--allow-unsigned 已放行未签名包 ===================="
          log_warn "  ${pkg_tarball} 无旁车签名（.sig），无法证明其为官方发布产物。"
          log_warn "  仅在本地开发自验场景使用；生产环境必须改用官方签名包重新安装。"
          log_warn "=============================================================================="
        else
          die "离线包未签名：${pkg_tarball}.sig 不存在，无法证明包的真实性，中止安装。请使用厂家官方签名包（含旁车 .sig）；本地开发自验可显式加 --allow-unsigned（不推荐）"
        fi
        ;;
      *) die "离线包验签失败：${pkg_tarball} 可能被篡改或非官方签发，中止安装" ;;
    esac
  else
    # 整包 tar.gz 缺失（可能被移动/删除）：真实性无从锚定，与未签名同策略 fail-closed
    if [[ "$ALLOW_UNSIGNED" == "true" ]]; then
      log_warn "==================== 安全警告：--allow-unsigned 已放行无法验签的包 ===================="
      log_warn "  未找到与解压目录同级的交付包 $(basename "$pkg_tarball")，验签与整包哈希锚定均跳过；"
      log_warn "  仅剩 manifest.files 自证校验（防损坏不防篡改）。生产环境请保留 <包>.tar.gz 与"
      log_warn "  .tar.gz.sha256 / .tar.gz.sig 于解压目录同级重新安装。"
      log_warn "================================================================================"
    else
      die "未找到与解压目录同级的交付包 $(basename "$pkg_tarball")，无法执行真实性验签，中止安装。请保留 <包>.tar.gz 及其旁车 .sha256 / .sig 于解压目录同级；本地开发自验可显式加 --allow-unsigned（不推荐）"
    fi
  fi
  # 第二层：整包旁车哈希（验签通过后的纵深，防偶发损坏）
  if [[ -f "$pkg_tarball" ]]; then
    sidecar_rc=0
    sha256_check_sidecar "$pkg_tarball" || sidecar_rc=$?
    case "$sidecar_rc" in
      0) log_info "交付包整包哈希校验通过（旁车 $(basename "$pkg_tarball").sha256）" ;;
      2) die "交付包旁车哈希缺失：${pkg_tarball}.sha256（交付不完整，中止安装；请从原始交付渠道补齐旁车文件）" ;;
      *) die "交付包整包哈希校验失败：${pkg_tarball} 可能已损坏或被篡改，中止安装" ;;
    esac
  fi

  host_arch="$(detect_arch)"
  # 以引号切分逐字段定位键并取其值，兼容紧凑与美化两种 JSON 排版
  pkg_arch="$(awk -F'"' '{for(i=1;i<=NF;i++) if($i=="arch"){print $(i+2); exit}}' "$pkg_manifest")"
  if [[ -z "$pkg_arch" ]]; then
    pkg_arch="amd64"
    log_warn "$pkg_manifest 缺少 arch 字段，按历史 amd64 包处理（建议使用带 arch 字段的新版离线包）"
  fi
  if [[ "$pkg_arch" != "$host_arch" ]]; then
    die "离线包架构（${pkg_arch}）与宿主机架构（${host_arch}）不匹配：请改用 jiuzhang-*-offline-*-${host_arch}.tar.gz（海光 C86、兆芯 KX/KH 等 x86-64 兼容平台使用 amd64 包）"
  fi
  log_info "架构校验通过：离线包 ${pkg_arch} / 宿主机 ${host_arch}"

  # 产品线：manifest.edition（waf|wdsp|api）；缺失按 waf
  PKG_EDITION="$(awk -F'"' '{for(i=1;i<=NF;i++) if($i=="edition"){print $(i+2); exit}}' "$pkg_manifest")"
  PKG_EDITION="$(printf '%s' "${PKG_EDITION:-waf}" | tr '[:upper:]' '[:lower:]')"
  case "$PKG_EDITION" in
    waf|wdsp|api) ;;
    *) log_warn "未知 edition=${PKG_EDITION}，回退 waf"; PKG_EDITION="waf" ;;
  esac
  # 布尔字段（json true/false 无引号）：用 grep 辅助
  if grep -q '"api_dynamic_protection"[[:space:]]*:[[:space:]]*true' "$pkg_manifest" 2>/dev/null; then
    PKG_API_DYNAMIC="true"
  elif [[ "$PKG_EDITION" == "wdsp" || "$PKG_EDITION" == "api" ]]; then
    PKG_API_DYNAMIC="true"
  else
    PKG_API_DYNAMIC="false"
  fi
  if grep -q '"web_waf_enabled"[[:space:]]*:[[:space:]]*false' "$pkg_manifest" 2>/dev/null; then
    PKG_WEB_WAF="false"
  elif [[ "$PKG_EDITION" == "api" ]]; then
    PKG_WEB_WAF="false"
  else
    PKG_WEB_WAF="true"
  fi
  log_info "产品线：edition=${PKG_EDITION} api_dynamic=${PKG_API_DYNAMIC} web_waf=${PKG_WEB_WAF}"

  # 第三层：解压树文件级校验（manifest.files 清单，离线包构建时逐文件记录 SHA-256/大小）
  mfv_rc=0
  manifest_files_verify "$pkg_manifest" "$pkg_dir" || mfv_rc=$?
  case "$mfv_rc" in
    0) ;;
    2) log_warn "manifest.json 无 files 清单（历史包），跳过文件级完整性校验" ;;
    *) die "解压目录文件级完整性校验失败（manifest.files 不符），中止安装" ;;
  esac
fi

[[ -f "$JZ_COMPOSE_FILE" ]] || die "compose 文件不存在: $JZ_COMPOSE_FILE"
require_cmd docker
require_cmd openssl
require_cmd curl
docker compose version >/dev/null 2>&1 || die "缺少 docker compose 插件"

# 完整离线包必须一次安装好宿主机升级执行器。在任何配置变更前预检，
# 避免业务已启动后才发现 Web 升级通道无法安装。
UPGRADE_INSTALLER="$SCRIPT_DIR/../upgrade/install-executor.sh"
UPGRADE_EXECUTOR="$SCRIPT_DIR/../upgrade/upgrade-executor.sh"
if [[ -n "$pkg_manifest" ]]; then
  [[ "$(id -u)" == "0" ]] || die "完整离线包必须使用 root 安装：请执行 sudo bash ops/install/install.sh"
  command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]] \
    || die "完整离线包需要 systemd，用于自动安装宿主机升级执行器"
  [[ -x "$UPGRADE_INSTALLER" && -x "$UPGRADE_EXECUTOR" ]] \
    || die "完整离线包缺少可执行的升级执行器脚本，请重新获取安装包"
  for cmd in jq python3 flock install sha256sum realpath; do
    require_cmd "$cmd"
  done
  log_info "完整包升级执行器预检通过"
fi

# ---------- 1. 环境检查 ----------
log_info "步骤 1/8：环境检查"

port_in_use() { # 检查本机端口占用（lsof 优先，/dev/tcp 兜底）
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
  return 1
}

for p in "$GATEWAY_PORT" "$API_PORT" "$WEB_PORT"; do
  if port_in_use "$p"; then
    die "端口 $p 已被占用，请先释放（或调整端口参数）"
  fi
done
log_info "端口 $GATEWAY_PORT / $API_PORT / $WEB_PORT 可用"

# 内存 ≥4GB
mem_gb=0
if [[ "$(uname)" == "Darwin" ]]; then
  mem_gb=$(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 ))
elif [[ -r /proc/meminfo ]]; then
  mem_gb=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024 / 1024 ))
fi
if (( mem_gb > 0 && mem_gb < 4 )); then
  die "内存 ${mem_gb}GB，低于最低要求 4GB"
fi
log_info "内存 ${mem_gb}GB"

# 磁盘 ≥20GB 可用
free_gb="$(df -P -k . | awk 'NR==2 {print int($4/1024/1024)}')"
if (( free_gb < 20 )); then
  die "当前目录磁盘可用 ${free_gb}GB，低于最低要求 20GB"
fi
log_info "磁盘可用 ${free_gb}GB"

# 时间同步（偏移 >60s 视为异常；无法判定时告警不阻断）
local_epoch="$(date +%s)"
http_date="$(curl -sSI --max-time 5 https://www.baidu.com 2>/dev/null | grep -i '^date:' | head -1 | cut -d' ' -f2- || true)"
if [[ -n "$http_date" ]]; then
  remote_epoch="$(date -u -j -f '%a, %d %b %Y %T GMT' "$http_date" +%s 2>/dev/null || date -u -d "$http_date" +%s 2>/dev/null || echo 0)"
  if [[ "$remote_epoch" =~ ^[0-9]+$ ]] && (( remote_epoch > 0 )); then
    drift=$(( local_epoch - remote_epoch ))
    (( drift < 0 )) && drift=$(( -drift ))
    if (( drift > 60 )); then
      die "系统时间与网络时间偏差 ${drift}s（>60s），请先配置 NTP 时间同步"
    fi
    log_info "时间同步正常（偏差 ${drift}s）"
  else
    log_warn "无法解析远端时间，跳过时间同步检查"
  fi
else
  log_warn "无法访问外网时间源，跳过时间同步检查（离线环境请自行确认 NTP 正常）"
fi

# ---------- 2. 生成 .env ----------
log_info "步骤 2/8：生成环境文件 $JZ_ENV_FILE"
if [[ -f "$JZ_ENV_FILE" && "$FORCE" != "true" ]]; then
  die "$JZ_ENV_FILE 已存在（--force 可覆盖；覆盖前请备份）"
fi
POSTGRES_PASSWORD="$(random_hex 24)"
VALKEY_PASSWORD="$(random_hex 24)"
JIUZHANG_MASTER_KEY="$(random_hex 32)"
INITIAL_ADMIN_PASSWORD="$(random_hex 12)"
umask 077
cat > "$JZ_ENV_FILE" <<EOF
# 九章环境配置（由 ops/install/install.sh 生成于 $(date -u '+%Y-%m-%dT%H:%M:%SZ')）
# 本文件含敏感信息，权限已设为 600，禁止提交到版本库。
# 产品线：${PKG_EDITION}（来自离线包 manifest；waf|wdsp|api）
APP_ENV=prod
POSTGRES_DB=jiuzhang_waf
POSTGRES_USER=jiuzhang
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
VALKEY_PASSWORD=$VALKEY_PASSWORD
JIUZHANG_MASTER_KEY=$JIUZHANG_MASTER_KEY
COOKIE_SECURE=true
INITIAL_ADMIN_USERNAME=jiuzhang_admin
# 初始化完成后请删除下一行（初始口令仅用于首次登录）
INITIAL_ADMIN_PASSWORD=$INITIAL_ADMIN_PASSWORD
API_PORT=$API_PORT
WEB_PORT=$WEB_PORT
PRODUCT_EDITION=$PKG_EDITION
API_DYNAMIC_PROTECTION_ENABLED=$PKG_API_DYNAMIC
WEB_WAF_ENABLED=$PKG_WEB_WAF
API_PROTECTION_MODE=OBSERVE
EOF
chmod 600 "$JZ_ENV_FILE"
log_info "已生成随机口令/主密钥，并写入产品线 PRODUCT_EDITION=${PKG_EDITION}（不回显口令）"

# ---------- 3. 采集宿主机指纹（离线授权绑定用） ----------
# 算法与授权中心 tools/fingerprint 一致；api 容器经只读挂载（compose 的
# ./runtime/license:/app/runtime/license:ro）读取该文件，与授权文件中的
# machine_fingerprint 比对（授权未绑定指纹时本文件不参与校验）。
# 采集失败仅告警不中断：绑定指纹的授权在导入时才校验，可事后重新采集补齐。
log_info "步骤 3/8：采集宿主机指纹（离线授权）"
INSTALL_ROOT="$PWD"
LICENSE_DIR="$INSTALL_ROOT/runtime/license"
HOST_FP_FILE="$LICENSE_DIR/host_fingerprint"
# 目录须 755：api 容器以 uid 1000（server/Dockerfile 的 jiuzhang 用户）只读访问
mkdir -p "$LICENSE_DIR"
chmod 755 "$LICENSE_DIR"
if fp="$(bash "$SCRIPT_DIR/../lib/fingerprint.sh" 2>/dev/null)" && [[ "$fp" == sha256:* ]]; then
  (umask 077; printf '%s\n' "$fp" > "$HOST_FP_FILE")
  chmod 600 "$HOST_FP_FILE"
  # 容器内 uid 1000 须能读取：尽量调整属主（非 root 安装可能失败，届时容器内读取受限）
  if ! chown 1000:1000 "$HOST_FP_FILE" 2>/dev/null; then
    log_warn "未能将 $HOST_FP_FILE 属主调整为 1000:1000（api 容器内 jiuzhang 用户），容器可能无法读取指纹文件"
  fi
  log_info "宿主机指纹已写入 ${HOST_FP_FILE}（授权管理页可查看，用于厂家签发绑定授权）"
else
  log_warn "宿主机指纹采集失败，跳过写入（不影响安装；导入绑定指纹的授权前可执行 bash ops/lib/fingerprint.sh 核对后手动写入 ${HOST_FP_FILE}）"
fi

# ---------- 4. firewalld ----------
# 端口收敛（LOW-O3）：默认只放行网关默认监听 80/443。生产网关 network_mode: host，
# 站点监听端口由管理面发布配置动态决定（1024-65535 任意高位端口），安装期无法静态
# 枚举，须由部署方按实际发布端口经 --site-ports 精确追加；安装后新增站点端口同理
# 手工 firewall-cmd 放行。切勿图省事直接放行 1024-65535：宿主机上任何监听高位端口
# 的无关服务都会被一并暴露到外部（历史默认行为，已按代码审查 LOW-O3 收敛）。
log_info "步骤 4/8：配置 firewalld（80/443${SITE_PORTS:+ 与站点端口 ${SITE_PORTS}}）"
if [[ "$NO_FIREWALL" == "true" ]]; then
  log_info "按 --no-firewall 跳过 firewalld 配置"
elif command -v firewall-cmd >/dev/null 2>&1 && \
     systemctl is-active --quiet firewalld 2>/dev/null; then
  firewall-cmd --permanent --add-port=80/tcp
  firewall-cmd --permanent --add-port=443/tcp
  if [[ -n "$SITE_PORTS" ]]; then
    IFS=',' read -ra _fw_ports <<< "$SITE_PORTS"
    for _fw_p in "${_fw_ports[@]}"; do
      firewall-cmd --permanent --add-port="${_fw_p}/tcp"
    done
    unset _fw_ports _fw_p
  fi
  firewall-cmd --reload
  log_info "firewalld 已放行 80/tcp、443/tcp${SITE_PORTS:+、${SITE_PORTS//,/、}/tcp}"
  if [[ -z "$SITE_PORTS" ]]; then
    log_warn "仅放行了 80/443；站点若使用其他端口（管理面站点配置决定），请用 --site-ports 重跑或手工 firewall-cmd --permanent --add-port=<端口>/tcp 放行"
  fi
else
  log_info "firewalld 未安装或未运行，跳过；如需外部访问请按部署环境自行放行端口（站点端口以管理面发布配置为准）"
fi

# ---------- 5. 安装 jiuzhang-hostctl systemd 单元（系统控制执行通道） ----------
# 系统控制（重启/关机/恢复出厂）：API 容器 read_only + cap_drop ALL，仅往
# runtime/hostctl/ 写标志文件；宿主机 path 单元监视该目录并触发 hostctl-exec.sh 执行。
# 检测 systemd 可用才安装；不可用（容器/无 systemd 环境）或非 root 时告警跳过不阻断，
# 届时可手工执行 ops/system/hostctl-exec.sh 处理标志文件（见 docs/DEPLOYMENT.md）。
log_info "步骤 5/8：安装 jiuzhang-hostctl systemd 单元（系统控制）"
mkdir -p "$INSTALL_ROOT/runtime/hostctl"
chmod 755 "$INSTALL_ROOT/runtime/hostctl"
# api 容器以 uid 1000 写入标志文件：尽量调整属主（非 root 安装可能失败，届时容器写入受限）
if ! chown 1000:1000 "$INSTALL_ROOT/runtime/hostctl" 2>/dev/null; then
  chmod 1777 "$INSTALL_ROOT/runtime/hostctl" 2>/dev/null \
    || log_warn "未能调整 $INSTALL_ROOT/runtime/hostctl 属主/权限，api 容器可能无法写入系统控制标志文件"
fi
# 安全复核（与 ops/system/hostctl-exec.sh 执行前校验同一约定）：属主须为 1000 且目录
# 不得 other-writable。chown 失败退化为 1777 时，任意本地用户可伪造系统控制标志，
# hostctl-exec.sh 将 fail-closed 拒绝执行——此处必须给出醒目警告而非静默带过。
_hc_uid="$(stat -c '%u' "$INSTALL_ROOT/runtime/hostctl" 2>/dev/null || stat -f '%u' "$INSTALL_ROOT/runtime/hostctl" 2>/dev/null || echo unknown)"
_hc_mode="$(stat -c '%a' "$INSTALL_ROOT/runtime/hostctl" 2>/dev/null || stat -f '%Lp' "$INSTALL_ROOT/runtime/hostctl" 2>/dev/null || echo "")"
_hc_insecure=false
[[ "$_hc_uid" == "1000" ]] || _hc_insecure=true
if [[ "$_hc_mode" =~ ^[0-7]{3,4}$ ]] && (( (8#${_hc_mode:${#_hc_mode}-3} & 2) != 0 )); then
  _hc_insecure=true
fi
if [[ "$_hc_insecure" == "true" ]]; then
  log_warn "==================== 安全警告（系统控制通道不可用） ===================="
  log_warn "  $INSTALL_ROOT/runtime/hostctl 当前属主 uid=${_hc_uid}、权限 ${_hc_mode:-unknown}，"
  log_warn "  不满足约定（属主 1000:1000、权限 755 且非全局可写）。"
  log_warn "  该状态下可写该目录的本地用户可伪造重启/关机/恢复出厂标志；"
  log_warn "  hostctl-exec.sh 将因执行前安全校验拒绝处理（fail-closed），"
  log_warn "  即 Web 端系统控制（重启/关机/恢复出厂）不可用，直至修复："
  log_warn "    sudo chown 1000:1000 $INSTALL_ROOT/runtime/hostctl && sudo chmod 755 $INSTALL_ROOT/runtime/hostctl"
  log_warn "======================================================================"
fi
unset _hc_uid _hc_mode _hc_insecure
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]] && [[ "$(id -u)" == "0" ]]; then
  hostctl_install_ok=true
  for unit in jiuzhang-hostctl.path jiuzhang-hostctl.service; do
    if [[ ! -f "$SCRIPT_DIR/../../deployment/systemd/$unit" ]]; then
      log_warn "单元模板缺失: deployment/systemd/${unit}，跳过 systemd 单元安装"
      hostctl_install_ok=false
      break
    fi
    # 渲染 install root 占位符后安装（仅覆盖带 jiuzhang-managed: hostctl-unit 管理标记的既有文件）
    if [[ -f "/etc/systemd/system/$unit" ]] && ! grep -q 'jiuzhang-managed: hostctl-unit' "/etc/systemd/system/$unit" 2>/dev/null; then
      log_warn "/etc/systemd/system/$unit 已存在且非九章安装器管理，跳过覆盖"
      hostctl_install_ok=false
      break
    fi
    sed "s|__INSTALL_ROOT__|$INSTALL_ROOT|g" "$SCRIPT_DIR/../../deployment/systemd/$unit" > "/etc/systemd/system/$unit" \
      || { log_warn "安装 /etc/systemd/system/$unit 失败"; hostctl_install_ok=false; break; }
  done
  if [[ "$hostctl_install_ok" == "true" ]]; then
    if systemctl daemon-reload && systemctl enable --now jiuzhang-hostctl.path; then
      log_info "jiuzhang-hostctl.path 已安装并启用（监视 $INSTALL_ROOT/runtime/hostctl/*.json）"
    else
      log_warn "systemctl daemon-reload/enable 失败，请手工执行后启用 jiuzhang-hostctl.path"
    fi
  fi
else
  log_warn "systemd 不可用或非 root，跳过 jiuzhang-hostctl 单元安装；系统控制可手工执行 ops/system/hostctl-exec.sh"
fi

# ---------- 6. 启动 ----------
log_info "步骤 6/8：启动服务（compose up -d）"
compose up -d
log_info "等待管理 API 健康检查（最长 180s）..."
wait_http_ok "$JZ_API_BASE/api/v1/health" 180 || die "管理 API 启动超时，请用 ops/diagnostics/collect.sh 收集诊断信息"
log_info "管理 API 已就绪"

# ---------- 7. 宿主机升级执行器 ----------
log_info "步骤 7/8：安装宿主机升级执行器"
if [[ -n "$pkg_manifest" ]] || {
  [[ "$(id -u)" == "0" ]] && command -v systemctl >/dev/null 2>&1 \
    && [[ -d /run/systemd/system ]] && [[ -x "$UPGRADE_INSTALLER" ]] && [[ -x "$UPGRADE_EXECUTOR" ]]
}; then
  bash "$UPGRADE_INSTALLER" \
    --compose-file "$JZ_COMPOSE_FILE" \
    --env-file "$JZ_ENV_FILE" \
    --api-url "$JZ_API_BASE"
  systemctl is-enabled --quiet jiuzhang-upgrade-executor.path \
    || die "升级执行器安装后未启用"
  systemctl is-active --quiet jiuzhang-upgrade-executor.path \
    || die "升级执行器监听单元未运行"
  log_info "宿主机升级执行器已安装并启用，Web 升级通道可用"
else
  log_warn "当前为非完整包或非 systemd/root 开发环境，跳过宿主机升级执行器安装"
fi

# ---------- 8. 三权账号初始化 ----------
if [[ "$SKIP_ACCOUNTS" == "true" ]]; then
  log_warn "已跳过三权账号初始化（--skip-accounts）"
  exit 0
fi
log_info "步骤 8/8：初始化三权管理员账号"
require_cmd jq
JZ_ADMIN_PASSWORD="$INITIAL_ADMIN_PASSWORD"
trap api_cleanup EXIT
api_login "jiuzhang_admin"

# 初始管理员首次登录强制改密：改为安装期生成的正式口令（仅本次打印）
FINAL_ADMIN_PASSWORD="$(random_hex 12)Aa!"
chg="$(api_req POST /api/v1/auth/change-password "$(jq -n --arg o "$INITIAL_ADMIN_PASSWORD" --arg n "$FINAL_ADMIN_PASSWORD" \
  '{old_password:$o, new_password:$n}')"
)" || die "修改初始管理员密码失败"
api_cleanup
INITIAL_ADMIN_PASSWORD="$FINAL_ADMIN_PASSWORD"
JZ_ADMIN_PASSWORD="$FINAL_ADMIN_PASSWORD"
api_login "jiuzhang_admin"

declare -a created
create_account() { # create_account USERNAME DISPLAY ROLE
  local username="$1" display="$2" role="$3"
  local body resp code tmp_pwd
  body="$(jq -n --arg u "$username" --arg d "$display" --arg r "$role" \
    '{username:$u, display_name:$d, role_code:$r}')"
  resp="$(api_req POST /api/v1/users "$body")"
  code="$(api_code "$resp")"
  if [[ "$code" != "SUCCESS" ]]; then
    if printf '%s' "$resp" | grep -qi "已存在\|conflict\|duplicate"; then
      log_warn "账号 $username 已存在，跳过创建"
      return 0
    fi
    die "创建账号 $username 失败: $(printf '%s' "$resp" | jq -r '.message // "未知错误"')"
  fi
  tmp_pwd="$(printf '%s' "$resp" | jq -r '.data.temporary_password // empty')"
  [[ -n "$tmp_pwd" ]] || die "创建账号 $username 后未返回临时口令"
  created+=("$username|$role|$tmp_pwd")
}

create_account "jiuzhang_secadmin" "安全管理员" "SECURITY_ADMIN"
create_account "jiuzhang_auditadmin" "审计管理员" "AUDIT_ADMIN"

cat <<EOF

==================== 初始账号（仅打印一次，请立即记录并妥善保管） ====================
  系统管理员: jiuzhang_admin
    初始口令: $INITIAL_ADMIN_PASSWORD
EOF
for entry in "${created[@]:-}"; do
  [[ -z "$entry" ]] && continue
  IFS='|' read -r u r p <<< "$entry"
  printf '  %s (%s)\n    临时口令: %s\n' "$u" "$r" "$p"
done
cat <<'EOF'
====================================================================================
  提示: 所有初始/临时口令首次登录后必须修改；
        确认账号可用后，请从 .env 中删除 INITIAL_ADMIN_PASSWORD 并重启服务。
EOF
