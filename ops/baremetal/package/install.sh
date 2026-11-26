#!/usr/bin/env bash
# install.sh —— 九章 WDSP 裸机安装包安装脚本（root 执行）。
#
# 用法：
#   sudo bash install.sh                  # 标准安装（systemd 托管全部服务）
#   sudo INSTALL_ROOT=/data/wdsp bash install.sh   # 自定义安装根
#   sudo JZ_SKIP_SYSTEMD=1 bash install.sh         # 只部署文件/数据/单元，不启动服务
#                                                  #（跳过 enable/健康等待/firewalld，
#                                                  #  结束时打印手工启动指引）
#
# 幂等：可重复执行。已存在的 env / pgdata / valkey.conf / 控制台证书保留不覆盖。
# 兼容 bash 3.2+；目标机 openEuler（bash 4+）。
set -euo pipefail

# ---------- 全局参数 ----------
INSTALL_ROOT="${INSTALL_ROOT:-/opt/jiuzhang-wdsp}"
R="${INSTALL_ROOT%/}"          # 去掉可能的尾部斜杠
if [[ -z "${R}" || "${R}" == "/" ]]; then
  printf '[ERROR] 非法 INSTALL_ROOT：%s\n' "${INSTALL_ROOT}" >&2
  exit 1
fi
RUN_USER="jiuzhang"
SKIP_SYSTEMD="${JZ_SKIP_SYSTEMD:-0}"
PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${R}/env"
PG_LD="${R}/bin/pg/syslib:${R}/bin/pg/lib/postgresql/16/lib"
PG_OSSL="${R}/bin/pg/syslib/ossl-modules"
PG_BIN="${R}/bin/pg/lib/postgresql/16/bin"
UNIT_LIST="jiuzhang-postgres jiuzhang-valkey jiuzhang-gateway jiuzhang-api jiuzhang-web jiuzhang-netmgrd jiuzhang-mirrorcap jiuzhang-tproxyd jiuzhang-havipd jiuzhang-logrotator"
OPTIONAL_UNIT_LIST="jiuzhang-hasyncd"
LINK_LIST_FILE="${R}/data/runtime/host-compat-links.list"

log_info() { printf '[INFO]  %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
log_warn() { printf '[WARN]  %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_err()  { printf '[ERROR] %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
die() { log_err "${1:-未知错误}"; exit "${2:-1}"; }

# env_get KEY —— 从 ${ENV_FILE} 读取键值（不 eval，取最后一处定义）
env_get() {
  local line
  line="$(grep -E "^$1=" "${ENV_FILE}" 2>/dev/null | tail -n 1 || true)"
  printf '%s' "${line#*=}"
}

# pg_exec CMD ARGS... —— 以 jiuzhang 身份执行随包 PostgreSQL 工具
pg_exec() {
  runuser -u "${RUN_USER}" -- env \
    LD_LIBRARY_PATH="${PG_LD}" OPENSSL_MODULES="${PG_OSSL}" "$@"
}

# ---------- 0. root 检查 ----------
[[ "$(id -u)" == "0" ]] || die "请以 root 执行（sudo bash install.sh）"
[[ -f "${PKG_DIR}/env.template" ]] || die "未找到 env.template——请在安装包根目录执行本脚本"

# ---------- 1. 预检 ----------
log_info "==> [1/16] 预检（架构/命令/端口/依赖）"
[[ "$(uname -s)" == "Linux" ]] || die "仅支持 Linux 目标机"
[[ "$(uname -m)" == "x86_64" ]] || die "仅支持 x86_64 架构（当前：$(uname -m)）"

if [[ "${SKIP_SYSTEMD}" != "1" ]]; then
  command -v systemctl >/dev/null 2>&1 || die "缺少 systemctl（本包以 systemd 托管服务；如仅需部署文件请用 JZ_SKIP_SYSTEMD=1）"
else
  command -v systemctl >/dev/null 2>&1 || log_warn "JZ_SKIP_SYSTEMD=1 且未找到 systemctl：将跳过单元安装后的 daemon-reload/tmpfiles 动作"
fi

for cmd in curl openssl ip ss; do
  command -v "${cmd}" >/dev/null 2>&1 || die "缺少必需命令：${cmd}（openEuler 安装：dnf install -y curl openssl iproute2）"
done

# 端口占用检查（被占则列出占用进程并失败）
# 注意：不用 grep -q（pipefail 下其提前退出会让上游吃 SIGPIPE，导致误判端口空闲）
PORT_BUSY=""
for p in 8080 8443 18081 5432 6379 80 443; do
  if ss -ltn 2>/dev/null | awk 'NR>1 {print $4}' | grep -E ":${p}$" >/dev/null 2>&1; then
    procs="$(ss -ltnp 2>/dev/null | awk -v pat=":${p}\$" 'NR>1 && $4 ~ pat {print}' \
      | sed 's/.*users:(\(.*\))$/\1/' | sort -u | tr '\n' ' ')"
    PORT_BUSY="${PORT_BUSY} ${p}(${procs:-未知进程})"
  fi
done
if [[ -n "${PORT_BUSY}" ]]; then
  log_err "以下端口已被占用：${PORT_BUSY}"
  if command -v docker >/dev/null 2>&1 \
    && docker ps --format '{{.Names}}' 2>/dev/null | grep -i jiuzhang >/dev/null 2>&1; then
    log_err "检测到正在运行的九章 docker 容器——请先在 docker 部署目录执行 docker compose down，再安装裸机版（迁移指引见 README.md）"
  fi
  die "请释放上述端口后重试"
fi

# netmgrd 运行期依赖：缺失仅警告并给出 dnf 安装名
NM_PKG_ip="iproute2"; NM_PKG_ping="iputils"; NM_PKG_traceroute="traceroute"; NM_PKG_tcpdump="tcpdump"; NM_PKG_iptables="iptables"
for cmd in ip ping traceroute tcpdump iptables; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    eval "pkg=\"\${NM_PKG_${cmd}}\""
    log_warn "netmgrd 依赖命令 ${cmd} 缺失（网络诊断/多网口/透明串接管理将受限）：dnf install -y ${pkg}"
  fi
done
if ! command -v keepalived >/dev/null 2>&1; then
  log_warn "havipd 依赖命令 keepalived 缺失（主备 VIP 漂移功能将受限）：dnf install -y keepalived"
fi

# ---------- 2. 运行账户 ----------
log_info "==> [2/16] 运行账户 ${RUN_USER}"
if id "${RUN_USER}" >/dev/null 2>&1; then
  log_info "账户 ${RUN_USER} 已存在，跳过创建"
else
  useradd --system --shell /sbin/nologin --home-dir "${R}" --comment "JiuZhang WDSP" "${RUN_USER}"
  log_info "已创建系统账户 ${RUN_USER}（nologin）"
fi

# ---------- 3. 复制包内容到安装根 ----------
log_info "==> [3/16] 部署文件到 ${R}"
if [[ "${PKG_DIR}" != "${R}" ]]; then
  mkdir -p "${R}"
  for item in bin web console gateway migrations assets geoip ops systemd tmpfiles.d \
              env.template install.sh uninstall.sh backup.sh restore.sh README.md; do
    [[ -e "${PKG_DIR}/${item}" ]] || die "安装包不完整：缺少 ${item}"
    rm -rf "${R}/${item}"
    cp -a "${PKG_DIR}/${item}" "${R}/${item}"
  done
else
  log_info "已在安装根内执行，跳过自复制"
fi
chmod 755 "${R}/install.sh" "${R}/uninstall.sh" "${R}/backup.sh" "${R}/restore.sh"
chmod 755 "${R}/ops/console-cert.sh" "${R}/ops/fingerprint.sh" "${R}/ops/pg-tune.sh"
# backup.sh / restore.sh 同时装到 ops/ 下（日常运维入口，见 README）
cp -a "${R}/backup.sh" "${R}/ops/backup.sh"
cp -a "${R}/restore.sh" "${R}/ops/restore.sh"
chmod 755 "${R}/ops/backup.sh" "${R}/ops/restore.sh"
# 防误改：包内容属主统一 root（data/certificates/backups 稍后单独属主）
chown -R root:root "${R}/bin" "${R}/web" "${R}/console" "${R}/gateway" \
  "${R}/migrations" "${R}/assets" "${R}/geoip" "${R}/ops" "${R}/systemd" "${R}/tmpfiles.d"
# 权限归一：构建机可能带 0700/0600 私有位，服务账户（jiuzhang）需要读/执行；
# 统一为 root 可写、全员可读执行（data/env/certificates 另设严格权限，不受此影响）
chmod -R u=rwX,go=rX "${R}/bin" "${R}/web" "${R}/console" "${R}/gateway" \
  "${R}/migrations" "${R}/assets" "${R}/geoip" "${R}/ops" "${R}/systemd" "${R}/tmpfiles.d"

# ---------- 4. 渲染 env ----------
log_info "==> [4/16] 运行环境文件 ${ENV_FILE}"
GEN_PG_PW="$(openssl rand -hex 24)"
GEN_VK_PW="$(openssl rand -hex 24)"
GEN_MASTER_KEY="$(openssl rand -hex 32)"
GEN_ADMIN_PW="$(openssl rand -hex 12)Aa!"
GEN_OPER_ADMIN_PW="$(openssl rand -hex 12)Aa!"
GEN_AUDIT_ADMIN_PW="$(openssl rand -hex 12)Aa!"
render_env() {
  sed -e "s|__ROOT__|${R}|g" \
      -e "s|__POSTGRES_PASSWORD__|${GEN_PG_PW}|g" \
      -e "s|__VALKEY_PASSWORD__|${GEN_VK_PW}|g" \
      -e "s|__MASTER_KEY__|${GEN_MASTER_KEY}|g" \
      -e "s|__INITIAL_ADMIN_PASSWORD__|${GEN_ADMIN_PW}|g" \
      -e "s|__INITIAL_OPER_ADMIN_PASSWORD__|${GEN_OPER_ADMIN_PW}|g" \
      -e "s|__INITIAL_AUDIT_ADMIN_PASSWORD__|${GEN_AUDIT_ADMIN_PW}|g" \
      "${R}/env.template"
}
if [[ -f "${ENV_FILE}" ]]; then
  log_info "${ENV_FILE} 已存在：保留现有值，仅补缺失键"
  rendered_tmp="$(mktemp)"
  render_env > "${rendered_tmp}"
  while IFS= read -r line || [[ -n "${line}" ]]; do
    case "${line}" in ''|\#*) continue ;; esac
    key="${line%%=*}"
    if ! grep -qE "^${key}=" "${ENV_FILE}"; then
      printf '%s\n' "${line}" >> "${ENV_FILE}"
      log_info "  补充缺失键：${key}"
    fi
  done < "${rendered_tmp}"
  rm -f "${rendered_tmp}"
else
  (umask 077; render_env > "${ENV_FILE}")
  log_info "已生成 ${ENV_FILE}（含随机口令）"
fi
chown root:"${RUN_USER}" "${ENV_FILE}"
chmod 0640 "${ENV_FILE}"

PG_PW="$(env_get POSTGRES_PASSWORD)"
VK_PW="$(env_get VALKEY_PASSWORD)"
WEB_PORT="$(env_get WEB_PORT)"; WEB_PORT="${WEB_PORT:-8080}"
WEB_HTTPS_PORT="$(env_get WEB_HTTPS_PORT)"; WEB_HTTPS_PORT="${WEB_HTTPS_PORT:-8443}"
NODE_NAME="$(env_get GATEWAY_NODE_NAME)"; NODE_NAME="${NODE_NAME:-gateway-baremetal-01}"
[[ -n "${PG_PW}" ]] || die "${ENV_FILE} 缺少 POSTGRES_PASSWORD"
[[ -n "${VK_PW}" ]] || die "${ENV_FILE} 缺少 VALKEY_PASSWORD"
# 以下值进入 sed 替换，先校验字符集防止注入/破坏模板
[[ "${WEB_PORT}" =~ ^[0-9]+$ ]] || die "env 的 WEB_PORT 非法：${WEB_PORT}"
[[ "${WEB_HTTPS_PORT}" =~ ^[0-9]+$ ]] || die "env 的 WEB_HTTPS_PORT 非法：${WEB_HTTPS_PORT}"
[[ "${NODE_NAME}" =~ ^[A-Za-z0-9._-]+$ ]] || die "env 的 GATEWAY_NODE_NAME 非法：${NODE_NAME}"

# ---------- 5. 数据目录树 ----------
log_info "==> [5/16] 数据目录树"
mkdir -p "${R}/data/pgdata" "${R}/data/valkey" \
  "${R}/data/caddy/config" "${R}/data/caddy/data" "${R}/data/caddy-console" \
  "${R}/data/runtime" "${R}/data/runtime/hostctl" \
  "${R}/data/runtime/upgrade-packages" "${R}/data/runtime/upgrade-executor/jobs" "${R}/data/runtime/upgrade-executor/results" \
  "${R}/data/logs/caddy" "${R}/data/run/caddy/sidecars" "${R}/data/run/caddy/sidecars/keepalived" \
  "${R}/data/run/pg" "${R}/certificates" "${R}/backups"
chown -R "${RUN_USER}:${RUN_USER}" "${R}/data" "${R}/certificates"
chown root:root "${R}/backups"
chmod 0750 "${R}/data"
chmod 0700 "${R}/backups"
chmod 0700 "${R}/data/pgdata" "${R}/data/caddy" "${R}/data/caddy-console" "${R}/certificates"
chmod 0750 "${R}/data/valkey" "${R}/data/runtime" "${R}/data/runtime/hostctl" \
  "${R}/data/runtime/upgrade-packages" "${R}/data/runtime/upgrade-executor" \
  "${R}/data/logs" "${R}/data/logs/caddy" "${R}/data/run" "${R}/data/run/caddy" "${R}/data/run/pg"
# sidecars：api（jiuzhang）写 network.json / ha-vip.json，netmgrd / havipd（root + SupplementaryGroups=jiuzhang、
# 无 CAP_DAC_OVERRIDE）经组 1000 读写 sidecars、sidecars/diag 与 sidecars/keepalived，不开放 other 权限。
chmod 0770 "${R}/data/run/caddy/sidecars" "${R}/data/run/caddy/sidecars/keepalived"
if [[ -d "${R}/data/run/caddy/sidecars/diag" ]]; then
  chmod 0770 "${R}/data/run/caddy/sidecars/diag"
fi

# ---------- 6. PostgreSQL 初始化 ----------
log_info "==> [6/16] PostgreSQL 数据目录"
if [[ -z "$(ls -A "${R}/data/pgdata" 2>/dev/null)" ]]; then
  log_info "pgdata 为空，执行 initdb"
  pwfile="$(mktemp)"
  chmod 600 "${pwfile}"
  printf '%s\n' "${PG_PW}" > "${pwfile}"
  chown "${RUN_USER}:${RUN_USER}" "${pwfile}"
  pg_exec "${PG_BIN}/initdb" -D "${R}/data/pgdata" -U "${RUN_USER}" \
    --locale=C -E UTF-8 --auth-local=peer --auth-host=scram-sha-256 \
    --pwfile="${pwfile}" >/dev/null
  shred -u "${pwfile}" 2>/dev/null || rm -f "${pwfile}"

  # 追加实例配置（文件末尾生效，覆盖 initdb 默认值）
  cat >> "${R}/data/pgdata/postgresql.conf" <<EOF

# ---- 九章裸机版追加（install.sh）----
listen_addresses = '127.0.0.1'
port = 5432
password_encryption = 'scram-sha-256'
unix_socket_directories = '${R}/data/run/pg'
unix_socket_permissions = 0700
EOF
  cat >> "${R}/data/pgdata/pg_hba.conf" <<'EOF'

# ---- 九章裸机版追加（install.sh）----
host jiuzhang_waf jiuzhang 127.0.0.1/32 scram-sha-256
host jiuzhang_waf jiuzhang ::1/128 scram-sha-256
EOF
  chown "${RUN_USER}:${RUN_USER}" "${R}/data/pgdata/postgresql.conf" "${R}/data/pgdata/pg_hba.conf"

  log_info "临时启动实例以创建业务库 jiuzhang_waf"
  if ! pg_exec "${PG_BIN}/pg_ctl" -D "${R}/data/pgdata" -w -t 60 -l "${R}/data/pgdata/initdb-start.log" start >/dev/null; then
    die "临时启动 PostgreSQL 失败，详见 ${R}/data/pgdata/initdb-start.log"
  fi
  db_exists="$(pg_exec env PGPASSWORD="${PG_PW}" "${PG_BIN}/psql" -h 127.0.0.1 -U "${RUN_USER}" -d postgres \
    -tAc "SELECT 1 FROM pg_database WHERE datname='jiuzhang_waf'" 2>/dev/null || true)"
  if [[ "${db_exists}" != "1" ]]; then
    if ! pg_exec env PGPASSWORD="${PG_PW}" "${PG_BIN}/createdb" -h 127.0.0.1 -U "${RUN_USER}" jiuzhang_waf; then
      pg_exec "${PG_BIN}/pg_ctl" -D "${R}/data/pgdata" -w -t 60 stop -m fast >/dev/null 2>&1 || true
      die "createdb jiuzhang_waf 失败（临时实例已停止）"
    fi
    log_info "已创建数据库 jiuzhang_waf"
  else
    log_info "数据库 jiuzhang_waf 已存在，跳过"
  fi
  pg_exec "${PG_BIN}/pg_ctl" -D "${R}/data/pgdata" -w -t 60 stop -m fast >/dev/null
  log_info "PostgreSQL 初始化完成（业务库就绪，服务随后由 systemd 拉起）"
else
  log_info "pgdata 非空，跳过 initdb（保留既有数据）"
fi

# 幂等写入内存自适应 PostgreSQL 调优配置（4G/8G/16G/32G/64G 同机混部安全档）
if [[ -f "${R}/data/pgdata/postgresql.conf" && -f "${R}/ops/pg-tune.sh" ]]; then
  mkdir -p "${R}/data/pgdata/conf.d"
  if ! grep -qE "^[[:space:]]*include_dir[[:space:]]*=[[:space:]]*'conf\.d'" "${R}/data/pgdata/postgresql.conf"; then
    printf "\n# 九章内存自适应调优片段目录（pg-tune.sh 维护）\ninclude_dir = 'conf.d'\n" >> "${R}/data/pgdata/postgresql.conf"
  fi
  bash "${R}/ops/pg-tune.sh" --format conf \
    --profile "${PG_MEMORY_PROFILE:-auto}" \
    --pg-lib "${R}/bin/pg/lib/postgresql/16/lib" \
    > "${R}/data/pgdata/conf.d/90-jiuzhang-tuning.conf"
  chown -R "${RUN_USER}:${RUN_USER}" "${R}/data/pgdata/conf.d" "${R}/data/pgdata/postgresql.conf"
  chmod 0700 "${R}/data/pgdata/conf.d"
  chmod 0600 "${R}/data/pgdata/conf.d/90-jiuzhang-tuning.conf"
  log_info "已刷新 PostgreSQL 内存自适应调优配置 ${R}/data/pgdata/conf.d/90-jiuzhang-tuning.conf（profile=${PG_MEMORY_PROFILE:-auto}）"
fi

# ---------- 7. Valkey 配置 ----------
log_info "==> [7/16] Valkey 配置"
VALKEY_CONF="${R}/data/valkey/valkey.conf"
if [[ -f "${VALKEY_CONF}" ]]; then
  log_info "${VALKEY_CONF} 已存在，保留现状"
else
  cat > "${VALKEY_CONF}" <<EOF
# 九章 WDSP 裸机内置 Valkey（install.sh 渲染）
bind 127.0.0.1
port 6379
requirepass ${VK_PW}
appendonly yes
maxmemory 256mb
maxmemory-policy allkeys-lru
dir ${R}/data/valkey
daemonize no
logfile ""
EOF
  chown "${RUN_USER}:${RUN_USER}" "${VALKEY_CONF}"
  chmod 0640 "${VALKEY_CONF}"
  log_info "已生成 ${VALKEY_CONF}"
fi

# ---------- 8. 控制台证书 ----------
log_info "==> [8/16] 控制台 HTTPS 证书"
bash "${R}/ops/console-cert.sh" --output "${R}/certificates"
chown "${RUN_USER}:${RUN_USER}" "${R}/certificates/console.crt" "${R}/certificates/console.key" 2>/dev/null || true

# ---------- 9. 宿主机指纹与 GeoIP ----------
log_info "==> [9/16] 宿主机指纹与 GeoIP"
mkdir -p "${R}/data/runtime/license" "${R}/data/runtime/geoip"
FP_NOW="$(bash "${R}/ops/fingerprint.sh")"
case "${FP_NOW}" in
  sha256:*) ;;
  *) die "fingerprint.sh 输出非法（期望 sha256: 前缀）：${FP_NOW}" ;;
esac
FP_FILE="${R}/data/runtime/license/host_fingerprint"
if [[ -f "${FP_FILE}" ]] && [[ "$(cat "${FP_FILE}")" == "${FP_NOW}" ]]; then
  log_info "宿主机指纹文件已存在且一致，保持现状"
else
  printf '%s\n' "${FP_NOW}" > "${FP_FILE}"
  log_info "已写入宿主机指纹 ${FP_NOW}"
fi
chown "${RUN_USER}:${RUN_USER}" "${FP_FILE}"
chmod 0600 "${FP_FILE}"
for geo_file in ip2region_v4.xdb city-ipv6.mmdb country.mmdb; do
  if [[ -s "${R}/geoip/${geo_file}" && ! -s "${R}/data/runtime/geoip/${geo_file}" ]]; then
    cp -a "${R}/geoip/${geo_file}" "${R}/data/runtime/geoip/${geo_file}"
    chown "${RUN_USER}:${RUN_USER}" "${R}/data/runtime/geoip/${geo_file}"
    log_info "已部署 GeoIP 库 ${geo_file}"
  elif [[ -s "${R}/data/runtime/geoip/${geo_file}" ]]; then
    log_info "GeoIP 库 ${geo_file} 已存在，保持现状"
  fi
done

# ---------- 10. 渲染 Caddy 配置 ----------
log_info "==> [10/16] 渲染控制台/网关 Caddy 配置"
if [[ -s "${R}/certificates/console.crt" && -s "${R}/certificates/console.key" ]]; then
  CONSOLE_TPL="${R}/console/Caddyfile.template"
  log_info "证书齐备，使用双栈模板（HTTP ${WEB_PORT} + HTTPS ${WEB_HTTPS_PORT}）"
else
  CONSOLE_TPL="${R}/console/Caddyfile.http-only.template"
  log_warn "证书缺失，使用仅 HTTP 模板（端口 ${WEB_PORT}）；补齐证书后重跑 install.sh 可切回双栈"
fi
sed -e "s|__ROOT__|${R}|g" \
    -e "s|__WEB_PORT__|${WEB_PORT}|g" \
    -e "s|__WEB_HTTPS_PORT__|${WEB_HTTPS_PORT}|g" \
    "${CONSOLE_TPL}" > "${R}/console/Caddyfile"
chmod 644 "${R}/console/Caddyfile"
sed -e "s|__ROOT__|${R}|g" \
    "${R}/gateway/Caddyfile.bootstrap.template" > "${R}/gateway/Caddyfile.bootstrap"
chmod 644 "${R}/gateway/Caddyfile.bootstrap"

# ---------- 11. 宿主兼容符号链接 ----------
# 发布配置中硬编码的网关侧路径（rules/certs/blockpage/日志目录）链接到安装根
log_info "==> [11/16] 宿主兼容符号链接"
ensure_link() {
  local link="$1" target="$2" cur
  if [[ -L "${link}" ]]; then
    cur="$(readlink "${link}")"
    if [[ "${cur}" == "${target}" ]]; then
      log_info "  已存在且指向正确：${link}"
      return 0
    fi
    die "符号链接 ${link} 已存在但指向 ${cur}（期望 ${target}），请人工处理后重试"
  fi
  if [[ -e "${link}" ]]; then
    die "路径 ${link} 已存在且不是符号链接（期望指向 ${target}），请人工备份/移除后重试"
  fi
  ln -s "${target}" "${link}"
  log_info "  ${link} -> ${target}"
}
mkdir -p /etc/caddy /srv/jiuzhang
ensure_link /etc/caddy/rules "${R}/gateway/rules"
ensure_link /etc/caddy/certs "${R}/data/runtime/certificates"
ensure_link /srv/jiuzhang/blockpage.html "${R}/gateway/blockpage.html"
ensure_link /var/log/caddy "${R}/data/logs/caddy"
# 登记链接清单（uninstall.sh 仅移除仍指向安装根的链接）
printf '%s\n' /etc/caddy/rules /etc/caddy/certs /srv/jiuzhang/blockpage.html /var/log/caddy \
  > "${LINK_LIST_FILE}"
chown "${RUN_USER}:${RUN_USER}" "${LINK_LIST_FILE}"
chmod 0644 "${LINK_LIST_FILE}"

# ---------- 12. systemd 单元与 tmpfiles ----------
log_info "==> [12/16] systemd 单元"
mkdir -p /etc/systemd/system /etc/tmpfiles.d
for unit in ${UNIT_LIST} ${OPTIONAL_UNIT_LIST}; do
  sed -e "s|__ROOT__|${R}|g" -e "s|__USER__|${RUN_USER}|g" -e "s|__NODE_NAME__|${NODE_NAME}|g" \
      "${R}/systemd/${unit}.service" > "/etc/systemd/system/${unit}.service"
  chmod 644 "/etc/systemd/system/${unit}.service"
done
cp "${R}/tmpfiles.d/jiuzhang.conf" /etc/tmpfiles.d/jiuzhang.conf
chmod 644 /etc/tmpfiles.d/jiuzhang.conf
if [[ -d /etc/modules-load.d ]]; then
  cat > /etc/modules-load.d/jiuzhang-transparent.conf <<'EOF'
# 九章 WDSP 透明串接模式所需内核模块
br_netfilter
nf_conntrack
xt_REDIRECT
EOF
  chmod 644 /etc/modules-load.d/jiuzhang-transparent.conf
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
  systemd-tmpfiles --create /etc/tmpfiles.d/jiuzhang.conf
fi

# ---------- 13. 启动服务 ----------
start_services() {
  local unit
  for unit in ${UNIT_LIST}; do
    log_info "  systemctl enable --now ${unit}"
    systemctl enable --now "${unit}"
  done
  if [[ -f "${R}/data/runtime/hasync.secret" ]]; then
    log_info "  systemctl enable --now jiuzhang-hasyncd（检测到 ${R}/data/runtime/hasync.secret）"
    systemctl enable --now jiuzhang-hasyncd
  else
    log_info "  可选单元 jiuzhang-hasyncd 默认保持禁用（单机部署无需启用；HA 双机部署配置 ${R}/data/runtime/hasync.secret 后执行 systemctl enable --now jiuzhang-hasyncd）"
  fi
}

# ---------- 14. 健康等待 ----------
wait_for() { # DESC CHECK_CMD [ARGS...]
  local desc="$1"; shift
  local i
  for i in $(seq 1 60); do
    if "$@" >/dev/null 2>&1; then
      log_info "  健康检查通过：${desc}"
      return 0
    fi
    sleep 1
  done
  log_err "  健康检查超时（60s）：${desc}"
  return 1
}
check_valkey() { env REDISCLI_AUTH="${VK_PW}" "${R}/bin/valkey/valkey-cli" ping 2>/dev/null | grep PONG >/dev/null 2>&1; }
check_pg()     { env LD_LIBRARY_PATH="${PG_LD}" OPENSSL_MODULES="${PG_OSSL}" "${PG_BIN}/pg_isready" -h 127.0.0.1 -U "${RUN_USER}" -t 2; }
check_api()    { curl -fsS -o /dev/null --max-time 3 "http://127.0.0.1:18081/api/v1/health"; }
check_web()    { curl -fsS -o /dev/null --max-time 3 "http://127.0.0.1:${WEB_PORT}/" \
                   && curl -fsS -o /dev/null --max-time 3 "http://127.0.0.1:${WEB_PORT}/api/v1/health"; }
check_sock()   { [[ -S "${R}/data/run/caddy/admin.sock" ]]; }

health_wait() {
  local failed=0
  wait_for "PostgreSQL（pg_isready）" check_pg || failed=1
  wait_for "Valkey（ping）" check_valkey || failed=1
  wait_for "网关 Admin Socket" check_sock || failed=1
  wait_for "管理 API（18081 /api/v1/health）" check_api || failed=1
  wait_for "控制台（${WEB_PORT} / 与 /api/v1/health）" check_web || failed=1
  if [[ "${failed}" == "1" ]]; then
    log_err "部分服务未就绪。排查指引："
    log_err "  journalctl -u jiuzhang-postgres -u jiuzhang-valkey -u jiuzhang-gateway -u jiuzhang-api -u jiuzhang-web --since '10 min ago'"
    log_err "  systemctl status 'jiuzhang-*'"
    exit 1
  fi
}

if [[ "${SKIP_SYSTEMD}" == "1" ]]; then
  log_info "==> [13-15/16] JZ_SKIP_SYSTEMD=1：跳过服务启动/健康等待/firewalld"
else
  log_info "==> [13/16] 启动服务（enable --now）"
  start_services
  log_info "==> [14/16] 健康等待（各 60s 上限）"
  health_wait
  log_info "==> [15/16] firewalld 放行"
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent \
      --add-port="${WEB_PORT}/tcp" --add-port="${WEB_HTTPS_PORT}/tcp" \
      --add-port=80/tcp --add-port=443/tcp >/dev/null
    firewall-cmd --reload >/dev/null
    log_info "  已放行 ${WEB_PORT}/${WEB_HTTPS_PORT}/80/443 tcp"
  else
    log_info "  firewalld 未运行，跳过"
  fi
fi

# ---------- 16. 收尾 ----------
HOST_IP="$(ip -4 -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}')"
HOST_IP="${HOST_IP:-127.0.0.1}"
echo ""
log_info "==> [16/16] 安装完成"
echo "=============================================================="
echo "  九章 WDSP 裸机版已安装到 ${R}"
echo ""
if [[ "${SKIP_SYSTEMD}" == "1" ]]; then
  echo "  JZ_SKIP_SYSTEMD=1：服务尚未启动。手工启动指引："
  echo "    systemctl daemon-reload"
  for unit in ${UNIT_LIST}; do
    echo "    systemctl enable --now ${unit}"
  done
  echo "  健康自检："
  echo "    curl -fsS http://127.0.0.1:18081/api/v1/health"
  echo "    curl -fsS http://127.0.0.1:${WEB_PORT}/api/v1/health"
else
  echo "  控制台：  http://${HOST_IP}:${WEB_PORT}/"
  if [[ -s "${R}/certificates/console.crt" ]]; then
    echo "            https://${HOST_IP}:${WEB_HTTPS_PORT}/（自签证书，浏览器告警属预期）"
  fi
  echo "  初始账号：系统管理员=$(env_get INITIAL_ADMIN_USERNAME)、运维管理员=$(env_get INITIAL_OPER_ADMIN_USERNAME)、审计管理员=$(env_get INITIAL_AUDIT_ADMIN_USERNAME)"
  echo "  初始口令：见 ${ENV_FILE} 的 INITIAL_*_PASSWORD 行"
  echo "            （首次登录强制改密；改密后请删除相关行并 systemctl restart jiuzhang-api）"
  echo "            若未配置口令行且对应角色下无用户，api 启动日志会打印一次性随机密码："
  echo "            journalctl -u jiuzhang-api | grep -A10 默认管理员"
fi
echo ""
echo "  下一步："
echo "    1. 登录控制台导入授权文件（系统管理 → 授权管理）"
echo "    2. 从 docker 部署迁移数据：见 ${R}/README.md「从 docker 部署迁移」"
echo "    3. 配置定期备份：${R}/ops/backup.sh（建议 crontab 每日执行）"
echo "=============================================================="
