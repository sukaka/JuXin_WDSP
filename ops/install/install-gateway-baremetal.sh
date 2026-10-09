#!/usr/bin/env bash
# install-gateway-baremetal.sh —— 九章 WAF 裸机网关（systemd 形态）安装器。
# 实现 docs/BARE_METAL_GATEWAY_DESIGN.md 期1：宿主机布局（4.2）、共享 GID 权限模型（4.3）、
# systemd 单元渲染安装（4.4）、firewalld 放行与 SELinux 处理（4.9/4.10）。
#
# 输入（二选一）：
#   --package gateway-linux-<arch>.tar.gz   离线裸机包（含 caddy 二进制 + sha256sums + VERSION，
#                                           可选 rules/ blockpage.html Caddyfile.bootstrap unit）；
#                                           先验签后解压：旁车 <包>.sig（Ed25519，脚本内置可信
#                                           公钥）验签通过才解压，验签失败/未签名 fail-closed
#                                           中止（--allow-unsigned 可显式放行未签名包）；
#                                           验签通过后旁车 <包>.sha256 与包内 sha256sums
#                                           保留为纵深层
#   --from-image <docker 镜像>              开发用：docker create + docker cp 抽取 /usr/bin/caddy
#                                           （本地镜像不经签名验真）
#
# 安全纪律：
#   - 任何情况不得 setenforce 0 或建议关闭 SELinux；
#   - 已存在且不带九章管理标记的目标文件不覆盖（报错提示）；
#   - 分配的 UID/GID 与版本写入 /etc/jiuzhang-gateway/install.env 并在结尾报告中打印。
#
# 退出码：0=成功 1=失败 2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"
# shellcheck source=../lib/signing.sh
source "$SCRIPT_DIR/../lib/signing.sh"

# 内置可信发布公钥（Ed25519，与 ops/offline-package/release-signing.pub 同源；
# 指纹见 docs/DEPLOYMENT.md「离线交付包签名与验签」。生产模式禁止覆盖；
# 仅显式开发模式允许 WDSP_PACKAGE_PUBLIC_KEY 指向测试公钥）。
WDSP_RELEASE_PUBKEY_PEM="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJBzjZs04R6NVLDuKoJsViPuBEGlo70z/zpnKi6ZHq2s=
-----END PUBLIC KEY-----"

# ---------- 常量 ----------
GW_USER="jiuzhang-gw"          # 网关运行专用用户（系统段 UID）
WAF_GROUP="jiuzhang-waf"       # 共享 GID 组（管理面容器经 group_add 获得共享权限）
INSTALL_ENV_DIR="/etc/jiuzhang-gateway"
INSTALL_ENV_FILE="$INSTALL_ENV_DIR/install.env"
OPT_ROOT="/opt/jiuzhang-gateway"
CADDY_ETC="/etc/caddy"
SRV_DIR="/srv/jiuzhang"
LOG_DIR="/var/log/caddy"
LIB_DIR="/var/lib/caddy"
RUN_DIR="/var/run/caddy"
ADMIN_SOCK="$RUN_DIR/admin.sock"
UNIT_DEST="/etc/systemd/system/jiuzhang-gateway.service"
BOOTSTRAP_DEST="$CADDY_ETC/Caddyfile.bootstrap"
# 管理标记：目标文件已存在且不含本标记时拒绝覆盖（防止踩掉客户手工文件）
BOOTSTRAP_MARKER="jiuzhang-managed: baremetal-bootstrap"
UNIT_MARKER="jiuzhang-managed: baremetal-gateway-unit"

usage() {
  cat <<'EOF'
用法: install-gateway-baremetal.sh (--package FILE | --from-image IMAGE) [选项]

裸机网关（systemd 形态）安装：前置检查 → 分配 UID/GID → 建目录（4.2 权限表）→
安装 caddy/rules/blockpage/bootstrap/unit → firewalld/SELinux → enable --now → 冒烟检查。

输入（二选一，必填）:
      --package FILE     gateway-linux-<arch>.tar.gz（先验签后解压：旁车 .sig Ed25519
                         验签为信任锚，验签失败/未签名默认中止；验签通过后旁车 .sha256
                         与包内 sha256sums 作为纵深层）
      --from-image IMG   开发用：从本地 docker 镜像抽取 /usr/bin/caddy（如 jiuzhang-gateway:stage5；
                         本地镜像不经签名验真）

选项:
      --gw-uid N         指定网关用户 UID（缺省从系统段 999→100 自高向低取空闲值，自动避让）
      --waf-gid N        指定共享组 GID（同上）
      --rules-dir DIR    CRS 规则目录（缺省：包内 rules/，其次仓库 gateway/rules/）
      --site-ports LIST  额外放行的站点端口（逗号分隔，支持区间，如 "8080,9000-9010"）。
                         站点监听端口由管理面发布配置动态决定，须按实际发布端口精确
                         追加；切勿图省事放行全部高位端口 1024-65535（会把宿主机上
                         无关的高位端口服务一并暴露到外部）
      --release-version V  releases 目录版本名（缺省取包内 VERSION 文件首个字段）
      --no-firewall      跳过 firewalld 放行
      --no-selinux-config 跳过 SELinux fcontext 配置（仅检测并提示）
      --allow-unsigned   放行未签名的裸机包（逃生开关，默认关闭）。仅用于本地开发
                         自验；生产环境必须使用官方签名包，使用时输出醒目安全警告
      --tune N           安装后执行性能调优目标档 6|8|10（Gbps HTTP 吞吐，显式 opt-in，
                         缺省不调优；调用 tune-gateway-baremetal.sh，见
                         docs/BARE_METAL_PERFORMANCE_TUNING.md）
      --dry-run          只打印将执行的操作，不修改系统（可在非 root/非 Linux 环境演练）
  -h, --help             显示帮助

退出码: 0=成功 1=失败 2=用法错误
EOF
}

# ---------- 参数 ----------
PKG=""
FROM_IMAGE=""
OPT_GW_UID=""
OPT_WAF_GID=""
OPT_SITE_PORTS=""
RULES_DIR=""
REL_VER=""
NO_FIREWALL=false
NO_SELINUX=false
ALLOW_UNSIGNED=false
export WDSP_DEVELOPMENT_MODE=0
TUNE_TARGET=""
DRY_RUN=false

# ---------- 小工具 ----------

# run CMD... —— dry-run 下只打印不执行（仅用于有副作用的命令）。
run() {
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[DRY-RUN] %s\n' "$*"
    return 0
  fi
  "$@"
}

# id_taken KIND ID —— KIND=user|group；经 getent（含 NSS）或 /etc/{passwd,group} 判断占用。
id_taken() {
  local kind="$1" id="$2" db
  if command -v getent >/dev/null 2>&1; then
    local ent_db="$kind"
    [[ "$kind" == "user" ]] && ent_db="passwd"   # getent 无 user 库，用户库名为 passwd
    getent "$ent_db" 2>/dev/null | awk -F: -v id="$id" '$3==id{found=1}END{exit !found}'
    return $?
  fi
  db="/etc/passwd"; [[ "$kind" == "group" ]] && db="/etc/group"
  [[ -r "$db" ]] || return 1
  awk -F: -v id="$id" '$3==id{found=1}END{exit !found}' "$db"
}

# name_id KIND NAME —— 输出已存在用户/组的数字 ID，查无返回 1。
name_id() {
  local kind="$1" name="$2" db line
  if command -v getent >/dev/null 2>&1; then
    line="$(getent "$kind" "$name" 2>/dev/null || true)"
  else
    db="/etc/passwd"; [[ "$kind" == "group" ]] && db="/etc/group"
    line="$(awk -F: -v n="$name" '$1==n{print;exit}' "$db" 2>/dev/null || true)"
  fi
  [[ -n "$line" ]] || return 1
  printf '%s\n' "$(printf '%s' "$line" | cut -d: -f3)"
}

# find_free_id KIND —— 系统段 999→100 自高向低找第一个空闲 ID（被占用自动避让）。
find_free_id() {
  local kind="$1" i
  for ((i = 999; i >= 100; i--)); do
    if ! id_taken "$kind" "$i"; then
      printf '%s\n' "$i"
      return 0
    fi
  done
  return 1
}

# sha256_verify DIR —— 在 DIR 内校验 sha256sums（GNU sha256sum 优先，BSD shasum 兜底）。
sha256_verify() {
  local dir="$1"
  [[ -f "$dir/sha256sums" ]] || die "包内缺少 sha256sums：$dir"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$dir" && sha256sum -c sha256sums)
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$dir" && shasum -a 256 -c sha256sums)
  else
    die "缺少 sha256sum/shasum，无法校验包完整性"
  fi
}

# install_managed SRC DEST MODE OWNER MARKER —— 目标已存在且不含管理标记时拒绝覆盖。
install_managed() {
  local src="$1" dest="$2" mode="$3" owner="$4" marker="$5"
  if [[ -e "$dest" ]] && ! grep -qF "$marker" "$dest" 2>/dev/null; then
    die "目标文件已存在且非九章安装器管理（缺少标记 '$marker'）：$dest
       请人工确认后备份移除，或保留手工文件并调整安装。"
  fi
  run install -m "$mode" ${owner:+-o "${owner%%:*}"} ${owner:+-g "${owner##*:}"} "$src" "$dest"
}

# ---------- 1. 前置检查 ----------
preflight() {
  log_info "步骤 1/10：前置检查"
  if [[ "$(id -u)" -ne 0 ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      log_warn "非 root 运行（--dry-run 演练模式，继续）"
    else
      die "需 root 运行"
    fi
  fi
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    log_info "systemd 检测通过"
  elif [[ "$DRY_RUN" == "true" ]]; then
    log_warn "未检测到 systemd（--dry-run 演练模式，继续）"
  else
    die "目标主机非 systemd 系统（未找到 systemctl 或 /run/systemd/system）"
  fi
  local arch
  arch="$(detect_arch)"
  log_info "架构: $arch"

  # OS 识别（非阻断）：openEuler / UOS / 其他 systemd 发行版
  local os_id="unknown" os_name="unknown"
  if [[ -r /etc/os-release ]]; then
    os_id="$(awk -F= '$1=="ID"{gsub(/"/,"",$2);print $2}' /etc/os-release)"
    os_name="$(awk -F= '$1=="PRETTY_NAME"{gsub(/"/,"",$2);print $2}' /etc/os-release)"
  fi
  case "$os_id" in
    openeuler) log_info "OS: openEuler（${os_name}）——目标支持平台" ;;
    uos)       log_info "OS: 统信 UOS（${os_name}）——目标支持平台" ;;
    unknown)   log_warn "无法识别 OS（无 /etc/os-release；--dry-run 演练或非 Linux 环境则属正常）" ;;
    *)         log_warn "OS: ${os_name}（非 openEuler/UOS 的 systemd 发行版，按通用路径安装，请自行复核）" ;;
  esac
}

# ---------- 2. 解析 caddy 二进制来源 ----------
# 输出全局：SRC_DIR（含 caddy/sha256sums/VERSION/delivery_mode，可选 rules/ blockpage.html
#           Caddyfile.bootstrap jiuzhang-gateway.service）、REL_VER
resolve_source() {
  log_info "步骤 2/10：获取网关二进制"
  SRC_DIR=""
  if [[ -n "$PKG" ]]; then
    [[ -f "$PKG" ]] || die "裸机包不存在: $PKG"
    SRC_DIR="$(mktemp -d "${TMPDIR:-/tmp}/jzgwpkg.XXXXXX")"
    # 先验签后解压（MED-23 后续增强）：旁车 <PKG>.sig（Ed25519，脚本内置可信公钥，
    # 生产模式固定使用内置信任根，开发模式才允许 WDSP_PACKAGE_PUBLIC_KEY；
    # 验签通过才解压；
    # 验签失败 fail-closed 中止；未签名默认中止，仅 --allow-unsigned 显式放行。
    sig_rc=0
    ed25519_verify_sidecar "$PKG" || sig_rc=$?
    case "$sig_rc" in
      0) log_info "裸机包真实性验签通过（Ed25519，旁车 ${PKG}.sig）" ;;
      2)
        if [[ "$ALLOW_UNSIGNED" == "true" ]]; then
          log_warn "==================== 安全警告：--allow-unsigned 已放行未签名包 ===================="
          log_warn "  $PKG 无旁车签名（.sig），无法证明其为官方发布产物。"
          log_warn "  仅在本地开发自验场景使用；生产环境必须改用官方签名包重新安装。"
          log_warn "=============================================================================="
        else
          die "裸机包未签名：${PKG}.sig 不存在，无法证明包的真实性，停止安装。请使用厂家官方签名包（含旁车 .sig）；本地开发自验可显式加 --allow-unsigned（不推荐）"
        fi
        ;;
      *) die "裸机包验签失败：$PKG 可能被篡改或非官方签发，停止安装" ;;
    esac
    # 纵深层：旁车 <PKG>.sha256 锚定整包哈希；无旁车时降级包内 sha256sums 自证
    # （见解压后 sha256_verify）。
    sidecar_rc=0
    sha256_check_sidecar "$PKG" || sidecar_rc=$?
    case "$sidecar_rc" in
      0) log_info "裸机包整包哈希校验通过（旁车 ${PKG}.sha256）" ;;
      2) log_warn "裸机包无旁车哈希（${PKG}.sha256 不存在）：整包完整性无从锚定，将仅依赖包内 sha256sums 自证" ;;
      *) die "裸机包旁车哈希校验失败：$PKG 可能已损坏或被篡改，停止安装" ;;
    esac
    tar -xzf "$PKG" -C "$SRC_DIR"
    # 包内允许一层顶层目录（gateway-linux-<arch>/）
    if [[ ! -f "$SRC_DIR/caddy" ]]; then
      local sub
      sub="$(find "$SRC_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)"
      [[ -n "$sub" && -f "$sub/caddy" ]] && SRC_DIR="$sub"
    fi
    [[ -f "$SRC_DIR/delivery_mode" ]] || die "包内缺少 delivery_mode：拒绝安装未声明交付边界的网关包"
    DELIVERY_MODE="$(awk 'NF{print $1;exit}' "$SRC_DIR/delivery_mode")"
    case "$DELIVERY_MODE" in
      production|development) ;;
      *) die "包内 delivery_mode 非法：${DELIVERY_MODE:-<empty>}（仅支持 production|development）" ;;
    esac
    if [[ "$ALLOW_UNSIGNED" == "true" && "$DELIVERY_MODE" != "development" ]]; then
      die "--allow-unsigned 仅允许 delivery_mode=development；正式网关包必须使用签名"
    fi
    log_info "交付模式: $DELIVERY_MODE"
    [[ -f "$SRC_DIR/caddy" ]] || die "包内未找到 caddy 二进制: $PKG"
    sha256_verify "$SRC_DIR" || die "SHA256 校验失败：包已损坏或被篡改，停止安装"
    log_info "SHA256 校验通过: $PKG"
  else
    require_cmd docker
    docker image inspect "$FROM_IMAGE" >/dev/null 2>&1 || die "本地镜像不存在: $FROM_IMAGE"
    SRC_DIR="$(mktemp -d "${TMPDIR:-/tmp}/jzgwimg.XXXXXX")"
    if [[ "$DRY_RUN" == "true" ]]; then
      printf '[DRY-RUN] docker create %s + docker cp <cid>:/usr/bin/caddy\n' "$FROM_IMAGE"
      printf '# dry-run placeholder\n' > "$SRC_DIR/caddy"
    else
      local cid
      cid="$(docker create "$FROM_IMAGE")" || die "docker create 失败: $FROM_IMAGE"
      if ! docker cp "$cid:/usr/bin/caddy" "$SRC_DIR/caddy"; then
        docker rm -f "$cid" >/dev/null 2>&1 || true
        die "docker cp 抽取 /usr/bin/caddy 失败: $FROM_IMAGE"
      fi
      docker rm -f "$cid" >/dev/null
      docker run --rm --entrypoint /usr/bin/caddy "$FROM_IMAGE" version > "$SRC_DIR/VERSION" 2>/dev/null || true
    fi
    log_info "已从镜像抽取 caddy: $FROM_IMAGE（开发路径，本地镜像不经签名验真）"
  fi
  chmod 0755 "$SRC_DIR/caddy" 2>/dev/null || true

  if [[ -z "$REL_VER" ]]; then
    # VERSION 文件为 `caddy version` 输出（"2.11.4 h1:..."），取首个字段
    REL_VER="$(awk 'NF{print $1;exit}' "$SRC_DIR/VERSION" 2>/dev/null || true)"
  fi
  [[ -n "$REL_VER" ]] || REL_VER="unknown-$(date '+%Y%m%d%H%M%S')"
  log_info "版本: $REL_VER"
}

# ---------- 3. 分配 UID/GID（4.3 共享 GID 模型） ----------
# 输出全局：GW_UID / WAF_GID（幂等：账号已存在则复用其实际值）
resolve_ids() {
  log_info "步骤 3/10：分配 UID/GID（共享 GID 模型，占用自动避让）"
  local existing
  existing="$(name_id group "$WAF_GROUP" || true)"
  if [[ -n "$existing" ]]; then
    WAF_GID="$existing"
    log_info "组 $WAF_GROUP 已存在，复用 GID=$WAF_GID"
  elif [[ -n "$OPT_WAF_GID" ]]; then
    id_taken group "$OPT_WAF_GID" && die "指定 GID $OPT_WAF_GID 已被占用（--waf-gid）"
    WAF_GID="$OPT_WAF_GID"
  else
    WAF_GID="$(find_free_id group)" || die "系统段（100-999）无空闲 GID，请用 --waf-gid 显式指定"
  fi

  existing="$(name_id passwd "$GW_USER" || true)"
  if [[ -n "$existing" ]]; then
    GW_UID="$existing"
    log_info "用户 $GW_USER 已存在，复用 UID=$GW_UID"
  elif [[ -n "$OPT_GW_UID" ]]; then
    id_taken user "$OPT_GW_UID" && die "指定 UID $OPT_GW_UID 已被占用（--gw-uid）"
    GW_UID="$OPT_GW_UID"
  else
    GW_UID="$(find_free_id user)" || die "系统段（100-999）无空闲 UID，请用 --gw-uid 显式指定"
  fi
  log_info "分配结果：$GW_USER(uid=$GW_UID) / $WAF_GROUP(gid=$WAF_GID)"
}

create_accounts() {
  run groupadd -r -g "$WAF_GID" "$WAF_GROUP" 2>/dev/null || true
  if [[ -z "$(name_id passwd "$GW_USER" || true)" ]]; then
    local nologin=/sbin/nologin
    [[ -x "$nologin" ]] || nologin=/usr/sbin/nologin
    run useradd -r -u "$GW_UID" -g "$WAF_GROUP" -M -d "$OPT_ROOT" -s "$nologin" \
      -c "JiuZhang WAF Gateway" "$GW_USER"
  fi
  # 分配结果落档：compose 模板 group_add 与后续升级脚本引用
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[DRY-RUN] 写入 %s（GW_UID=%s WAF_GID=%s）\n' "$INSTALL_ENV_FILE" "$GW_UID" "$WAF_GID"
  else
    install -d -m 0750 "$INSTALL_ENV_DIR"
    cat > "$INSTALL_ENV_FILE" <<EOF
# 九章裸机网关安装档案（install-gateway-baremetal.sh 生成于 $(date -u '+%Y-%m-%dT%H:%M:%SZ')）
# 管理面 compose 引用：group_add: ["\${JIUZHANG_WAF_GID}"]（见安装报告后续步骤）
JIUZHANG_GW_USER=$GW_USER
JIUZHANG_GW_UID=$GW_UID
JIUZHANG_WAF_GROUP=$WAF_GROUP
JIUZHANG_WAF_GID=$WAF_GID
JIUZHANG_GATEWAY_VERSION=$REL_VER
EOF
    chmod 0640 "$INSTALL_ENV_FILE"
  fi
}

# ---------- 4. 目录布局（4.2 权限表） ----------
create_layout() {
  log_info "步骤 4/10：创建宿主机目录布局（4.2 权限表）"
  run install -d -m 0755 -o root -g root "$OPT_ROOT" "$OPT_ROOT/releases/$REL_VER"
  # /etc/caddy 与子目录：root:jiuzhang-waf 0750（网关进程凭组只读）
  run install -d -m 0750 -o root -g "$WAF_GROUP" \
    "$CADDY_ETC" "$CADDY_ETC/rules" "$CADDY_ETC/certificates"
  # blockpage：root:jiuzhang-waf，文件 0640
  run install -d -m 0750 -o root -g "$WAF_GROUP" "$SRV_DIR"
  # 网关进程可写：日志目录与 StateDirectory（autosave/data）
  run install -d -m 0750 -o "$GW_USER" -g "$WAF_GROUP" "$LOG_DIR" "$LIB_DIR"
  # 发布存档（current/previous.json）：root:jiuzhang-waf 0750，网关进程恢复时只读。
  # 注意与 unit 的 StateDirectory=caddy 并存：systemd 只保证 /var/lib/caddy 属主，
  # 不递归改动本目录。
  run install -d -m 0750 -o root -g "$WAF_GROUP" "$LIB_DIR/config"
  # RuntimeDirectory=/var/run/caddy 由 systemd 创建（0750，属主为 unit User=）；
  # 此处预建仅为 SELinux fcontext 与冒烟检查提供稳定落点。
  run install -d -m 0750 -o "$GW_USER" -g "$WAF_GROUP" "$RUN_DIR"
}

# ---------- 5. 安装二进制与配套文件 ----------
install_files() {
  log_info "步骤 5/10：安装 caddy 二进制、规则、blockpage、bootstrap 与 systemd unit"
  run install -m 0755 -o root -g root "$SRC_DIR/caddy" "$OPT_ROOT/releases/$REL_VER/caddy"
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[DRY-RUN] ln -sfn releases/%s %s/current\n' "$REL_VER" "$OPT_ROOT"
  else
    ln -sfn "releases/$REL_VER" "$OPT_ROOT/current"
  fi

  # 规则：包内 rules/ 优先，其次 --rules-dir，缺省仓库 gateway/rules/
  local rules_src=""
  if [[ -d "$SRC_DIR/rules" ]]; then rules_src="$SRC_DIR/rules"
  elif [[ -n "$RULES_DIR" ]]; then rules_src="$RULES_DIR"
  elif [[ -d "$REPO_ROOT/gateway/rules" ]]; then rules_src="$REPO_ROOT/gateway/rules"
  fi
  [[ -n "$rules_src" ]] || die "未找到 CRS 规则目录（包内无 rules/，--rules-dir 未指定，仓库 gateway/rules/ 不存在）"
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[DRY-RUN] 复制规则 %s -> %s/rules/\n' "$rules_src" "$CADDY_ETC"
  else
    cp -R "$rules_src/." "$CADDY_ETC/rules/"
    chown -R root:"$WAF_GROUP" "$CADDY_ETC/rules"
    chmod -R u=rwX,g=rX,o= "$CADDY_ETC/rules"
  fi

  local blockpage_src="$SRC_DIR/blockpage.html"
  [[ -f "$blockpage_src" ]] || blockpage_src="$REPO_ROOT/gateway/configs/blockpage.html"
  [[ -f "$blockpage_src" ]] || die "未找到 blockpage.html"
  run install -m 0640 -o root -g "$WAF_GROUP" "$blockpage_src" "$SRV_DIR/blockpage.html"

  local bootstrap_src="$SRC_DIR/Caddyfile.bootstrap"
  [[ -f "$bootstrap_src" ]] || bootstrap_src="$REPO_ROOT/deployment/baremetal/Caddyfile.bootstrap"
  [[ -f "$bootstrap_src" ]] || die "未找到 Caddyfile.bootstrap"
  install_managed "$bootstrap_src" "$BOOTSTRAP_DEST" 0640 "root:$WAF_GROUP" "$BOOTSTRAP_MARKER"

  # unit 模板渲染：sed 替换占位符后安装（带管理标记检查）
  local unit_src="$SRC_DIR/jiuzhang-gateway.service"
  [[ -f "$unit_src" ]] || unit_src="$REPO_ROOT/deployment/systemd/jiuzhang-gateway.service"
  [[ -f "$unit_src" ]] || die "未找到 unit 模板 jiuzhang-gateway.service"
  local rendered
  rendered="$(mktemp "${TMPDIR:-/tmp}/jzgwunit.XXXXXX")"
  sed -e "s/__GW_USER__/$GW_USER/g" -e "s/__WAF_GROUP__/$WAF_GROUP/g" "$unit_src" > "$rendered"
  if grep -q '__GW_USER__\|__WAF_GROUP__' "$rendered"; then
    rm -f "$rendered"
    die "unit 模板占位符渲染不完整"
  fi
  install_managed "$rendered" "$UNIT_DEST" 0644 "root:root" "$UNIT_MARKER"
  rm -f "$rendered"
}

# ---------- 6. firewalld ----------
configure_firewalld() {
  # 端口收敛（LOW-O3）：默认只放行 80/443。站点监听端口由管理面发布配置动态决定
  # （1024-65535 任意高位端口），安装期无法静态枚举，须由部署方按实际发布端口经
  # --site-ports 精确追加。切勿图省事直接放行 1024-65535：宿主机上任何监听高位端口
  # 的无关服务都会被一并暴露到外部（历史默认行为，已按代码审查 LOW-O3 收敛）。
  log_info "步骤 6/10：firewalld 配置"
  if [[ "$NO_FIREWALL" == "true" ]]; then
    log_info "按 --no-firewall 跳过 firewalld 配置"
  elif command -v firewall-cmd >/dev/null 2>&1 && \
       systemctl is-active --quiet firewalld 2>/dev/null; then
    run firewall-cmd --permanent --add-port=80/tcp
    run firewall-cmd --permanent --add-port=443/tcp
    if [[ -n "$OPT_SITE_PORTS" ]]; then
      local _fw_ports
      IFS=',' read -ra _fw_ports <<< "$OPT_SITE_PORTS"
      local _fw_p
      for _fw_p in "${_fw_ports[@]}"; do
        run firewall-cmd --permanent --add-port="${_fw_p}/tcp"
      done
    fi
    run firewall-cmd --reload
    log_info "firewalld 已放行 80/tcp、443/tcp${OPT_SITE_PORTS:+、${OPT_SITE_PORTS//,/、}/tcp}"
  else
    log_info "firewalld 未安装或未运行，跳过"
  fi
  # 运维约定（4.7 修订）：默认仅放行 80/443；站点使用其他端口（含 1024 以上高位端口）
  # 时须按发布结果经 --site-ports 或手工 firewall-cmd 精确放行并审计；
  # 低于 1024 的端口仍需单独评估。
  if [[ -z "$OPT_SITE_PORTS" ]]; then
    log_warn "运维约定：仅 80/443 已放行；站点使用其他端口时须按发布结果手工 firewall-cmd --add-port=<端口>/tcp 放行并审计（或重装时 --site-ports 指定）"
  else
    log_info "运维约定：站点端口以 --site-ports（${OPT_SITE_PORTS}）为准；后续新增站点端口须手工 firewall-cmd 放行并审计"
  fi
}

# ---------- 7. SELinux（4.10；任何情况不得 setenforce 0） ----------
configure_selinux() {
  log_info "步骤 7/10：SELinux 处理"
  SELINUX_STATE="absent"
  if [[ "$NO_SELINUX" == "true" ]]; then
    log_info "按 --no-selinux-config 跳过（仅检测）"
  fi
  if ! command -v getenforce >/dev/null 2>&1; then
    log_info "未检测到 SELinux，跳过"
    return 0
  fi
  SELINUX_STATE="$(getenforce 2>/dev/null || printf 'unknown')"
  log_info "SELinux 状态: $SELINUX_STATE"
  if [[ "$SELINUX_STATE" != "Enforcing" || "$NO_SELINUX" == "true" ]]; then
    return 0
  fi
  # 宿主机 systemd 进程 + Docker 容器共享目录场景：候选方案为共享目录设置
  # container_file_t fcontext（期1 经验证候选；安装报告注明需在目标环境复核）。
  local dirs=("$LOG_DIR" "$RUN_DIR" "$CADDY_ETC/certificates" "$LIB_DIR/config")
  if command -v semanage >/dev/null 2>&1; then
    local d
    for d in "${dirs[@]}"; do
      if [[ "$DRY_RUN" == "true" ]]; then
        printf '[DRY-RUN] semanage fcontext -a -t container_file_t "%s(/.*)?" && restorecon -RF %s\n' "$d" "$d"
      else
        if ! semanage fcontext -a -t container_file_t "$d(/.*)?" 2>/dev/null; then
          semanage fcontext -m -t container_file_t "$d(/.*)?" || die "semanage fcontext 设置失败: $d"
        fi
        restorecon -RF "$d" || log_warn "restorecon 失败: ${d}（请人工执行 restorecon -RF ${d}）"
      fi
    done
    log_info "已为共享目录设置 container_file_t fcontext（候选方案，需在目标环境复核容器侧读写）"
  else
    log_warn "SELinux Enforcing 但缺少 semanage（policycoreutils-python-utils）。请手工执行："
    local d
    for d in "${dirs[@]}"; do
      printf '       semanage fcontext -a -t container_file_t "%s(/.*)?" && restorecon -RF %s\n' "$d" "$d" >&2
    done
    log_warn "不得通过 setenforce 0 或关闭 SELinux 规避（安全纪律，见设计文档 4.10）"
  fi
}

# ---------- 8. 启用服务 ----------
enable_service() {
  log_info "步骤 8/10：注册并启动 systemd 服务"
  run systemctl daemon-reload
  run systemctl enable --now jiuzhang-gateway
}

# ---------- 9. 性能调优（可选，--tune 显式 opt-in） ----------
apply_tuning() {
  [[ -n "$TUNE_TARGET" ]] || return 0
  log_info "步骤 9/10：性能调优（--tune ${TUNE_TARGET} 档）"
  local tune_script="$SCRIPT_DIR/tune-gateway-baremetal.sh"
  [[ -f "$tune_script" ]] || die "未找到调优脚本: ${tune_script}（请确认离线包/仓库完整）"
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[DRY-RUN] bash %s --target %s --apply --dry-run\n' "$tune_script" "$TUNE_TARGET"
  else
    bash "$tune_script" --target "$TUNE_TARGET" --apply \
      || die "性能调优执行失败（可稍后手工执行: bash $tune_script --target $TUNE_TARGET --apply）"
  fi
}

# ---------- 10. 冒烟检查 ----------
smoke_check() {
  log_info "步骤 10/10：冒烟检查"
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[DRY-RUN] 等待 %s 出现（30s）、caddy version、systemctl is-active\n' "$ADMIN_SOCK"
    return 0
  fi
  local i
  for ((i = 0; i < 30; i++)); do
    [[ -S "$ADMIN_SOCK" ]] && break
    sleep 1
  done
  [[ -S "$ADMIN_SOCK" ]] || die "冒烟失败：admin socket 未出现（${ADMIN_SOCK}）；journalctl -u jiuzhang-gateway 排查"
  log_info "admin socket 就绪: $ADMIN_SOCK"
  "$OPT_ROOT/current/caddy" version || die "冒烟失败：caddy version 执行异常"
  systemctl is-active --quiet jiuzhang-gateway \
    || die "冒烟失败：服务未处于 active（systemctl status jiuzhang-gateway）"
  log_info "服务状态: active"
}

# ---------- 安装报告 ----------
print_report() {
  cat <<EOF

==================== 九章裸机网关安装报告 ====================
  版本:        ${REL_VER}（$OPT_ROOT/current -> releases/${REL_VER}）
  账号:        $GW_USER(uid=$GW_UID) / $WAF_GROUP(gid=$WAF_GID)
  安装档案:    $INSTALL_ENV_FILE
  目录:        ${OPT_ROOT}（root 0755，防篡改）
               $CADDY_ETC{,/rules,/certificates}（root:$WAF_GROUP 0750，网关只读）
               $SRV_DIR/blockpage.html（0640）
               $LOG_DIR / ${LIB_DIR}（$GW_USER:$WAF_GROUP 0750，网关可写）
               $LIB_DIR/config（root:$WAF_GROUP 0750，发布存档）
  firewalld:   $([[ "$NO_FIREWALL" == "true" ]] && printf '已跳过(--no-firewall)' || printf '80/443%s 已放行或未运行，见上方日志' "${OPT_SITE_PORTS:+ 与 ${OPT_SITE_PORTS}}")
  SELinux:     $SELINUX_STATE$([[ "$SELINUX_STATE" == "Enforcing" ]] && printf '（container_file_t 为经验证候选方案，请在目标环境复核容器侧读写）')
  性能调优:    $(if [[ -n "$TUNE_TARGET" ]]; then printf '已应用 %s 档（tune-gateway-baremetal.sh；验收见 docs/BARE_METAL_PERFORMANCE_TUNING.md）' "$TUNE_TARGET"; else printf '未执行（如需: bash ops/install/tune-gateway-baremetal.sh --target 6 --apply）'; fi)

  后续步骤（管理面对接，期2 落地）：
    1. 生产 compose 为 api 服务追加 bind mount：
       - $RUN_DIR:/var/run/caddy（admin socket 发布通道）
       - $LOG_DIR:/var/log/caddy-audit:ro（日志采集）
       - $CADDY_ETC/certificates:<dataDir>/certificates（证书下发）
       - $LIB_DIR/config:<dataDir>/gateway-config（发布存档）
    2. api 服务追加 group_add: ["$WAF_GID"]（共享 GID 授权，容器内 UID 无需等于宿主机）
    3. 仅 80/443${OPT_SITE_PORTS:+ 与 ${OPT_SITE_PORTS}} 已放行；站点新增其他端口时按发布结果另行 firewalld 精确放行并审计
    4. 验收：bash ops/install/verify-gateway-baremetal.sh
================================================================
EOF
}

# ---------- main ----------
main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --package)           PKG="$2"; shift 2 ;;
      --from-image)        FROM_IMAGE="$2"; shift 2 ;;
      --gw-uid)            OPT_GW_UID="$2"; shift 2 ;;
      --waf-gid)           OPT_WAF_GID="$2"; shift 2 ;;
      --rules-dir)         RULES_DIR="$2"; shift 2 ;;
      --site-ports)        OPT_SITE_PORTS="$2"; shift 2 ;;
      --release-version)   REL_VER="$2"; shift 2 ;;
      --no-firewall)       NO_FIREWALL=true; shift ;;
      --no-selinux-config) NO_SELINUX=true; shift ;;
      --allow-unsigned)    ALLOW_UNSIGNED=true; shift ;;
      --tune)              TUNE_TARGET="$2"; shift 2 ;;
      --dry-run)           DRY_RUN=true; shift ;;
      -h|--help)           usage; exit 0 ;;
      *) log_err "未知参数: $1"; usage; exit 2 ;;
    esac
  done
  if [[ -n "$PKG" && -n "$FROM_IMAGE" ]]; then
    log_err "--package 与 --from-image 互斥"; usage; exit 2
  fi
  if [[ -z "$PKG" && -z "$FROM_IMAGE" ]]; then
    log_err "必须指定 --package 或 --from-image"; usage; exit 2
  fi
  [[ -z "$OPT_GW_UID" || "$OPT_GW_UID" =~ ^[0-9]+$ ]] || { log_err "--gw-uid 须为数字"; exit 2; }
  [[ -z "$OPT_WAF_GID" || "$OPT_WAF_GID" =~ ^[0-9]+$ ]] || { log_err "--waf-gid 须为数字"; exit 2; }
  [[ -z "$TUNE_TARGET" || "$TUNE_TARGET" =~ ^(6|8|10)$ ]] \
    || { log_err "--tune 非法值: ${TUNE_TARGET}（仅支持 6|8|10）"; exit 2; }
  [[ -z "$RULES_DIR" || -d "$RULES_DIR" ]] || die "--rules-dir 目录不存在: $RULES_DIR"
  if [[ -n "$OPT_SITE_PORTS" ]]; then
    validate_port_list "$OPT_SITE_PORTS" \
      || { log_err "--site-ports 格式非法: ${OPT_SITE_PORTS}（逗号分隔端口或区间，如 8080,9000-9010）"; exit 2; }
  fi

  if [[ "$ALLOW_UNSIGNED" == "true" ]]; then
    export WDSP_DEVELOPMENT_MODE=1
  fi

  SELINUX_STATE="absent"
  preflight
  resolve_source
  resolve_ids
  create_accounts
  create_layout
  install_files
  configure_firewalld
  configure_selinux
  enable_service
  apply_tuning
  smoke_check
  print_report
}

# 允许测试 harness source 本脚本单测内部函数；直接执行时才进入 main。
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
