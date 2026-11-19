#!/usr/bin/env bash
# hostctl-exec.sh —— 系统控制执行通道：扫描 hostctl 标志目录，执行重启/关机/恢复出厂/端口放行/PCAP 控制。
#
# 安全要点（C-03 / H-01 / H-02 / H-21）：
#   1. 拒绝标志目录、共享密钥与标志文件的符号链接（! -L + Python os.O_NOFOLLOW + fstat）；
#   2. 独占 flock 串行处理全部待处理 .json 标志（显式排除 pcap-status.*），按 mtime 升序（FIFO）执行；
#   3. .hostctl-secret 的原子自举/读取、标志文件读取、HMAC-SHA256 验签（hmac.compare_digest）
#      全部在 Python 内完成，绝不通过命令行参数传递密钥；
#   4. 消费后的 requestID 持久化至 root 属主防重放状态文件（保留 >= 2 * HOSTCTL_MAX_SKEW），
#      阻断时间窗内的重放攻击；
#   5. 验签后的标志内容复制到 root 0700 临时目录后再传给 pcap_capture_control.py（消除 TOCTOU）。
#
# 规范化签名载荷（两端必须逐字节一致）：以 \n 连接、无结尾换行。
#   v1\n<action>\n<requestedBy>\n<userID>\n<requestID>\n<requestedAt>\n<delaySeconds>
#   v2\nfirewall_ensure\n<requestedBy>\n<userID>\n<requestID>\n<requestedAt>\n0\n<portsCSV>
#   v3\npcap_capture\n<requestedBy>\n<userID>\n<requestID>\n<requestedAt>\n0\n<portsCSV>\n<interface>\n<hotDir>\n<warmDir>\n<nodeID>\n<enabled>
#
# 用法: hostctl-exec.sh [--dry-run] [标志目录]
#   标志目录：位置参数 $1 或环境变量 HOSTCTL_DIR，默认 <仓库根>/runtime/hostctl
#   --dry-run：只打印将执行的动作，不真正执行（供测试验收）
# 退出码: 0=成功（含无待处理标志） 1=失败 2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

ORIG_ARGS=("$@")
DRY_RUN=false
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help)
      sed -n '2,23p' "$0"
      exit 0 ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
[[ ${#POSITIONAL[@]} -le 1 ]] || { log_err "参数过多: ${POSITIONAL[*]:1}"; exit 2; }

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HOSTCTL_DIR="${POSITIONAL[0]:-${HOSTCTL_DIR:-$REPO_ROOT/runtime/hostctl}}"

require_cmd python3
require_cmd logger

# 先检查符号链接（-d 会跟随符号链接，因此必须先判 -L）
if [[ -L "$HOSTCTL_DIR" ]]; then
  log_err "标志目录不得为符号链接: ${HOSTCTL_DIR}（fail-closed）"
  logger -t jiuzhang-hostctl -- "security_rejected reason=hostctl_dir_symlink path=$HOSTCTL_DIR"
  exit 1
fi
[[ -d "$HOSTCTL_DIR" ]] || { log_info "标志目录不存在（${HOSTCTL_DIR}），无待处理项"; exit 0; }

HOSTCTL_EXPECT_UID="${HOSTCTL_EXPECT_UID:-1000}"
HOSTCTL_MAX_SKEW="${HOSTCTL_MAX_SKEW:-300}"
[[ "$HOSTCTL_EXPECT_UID" =~ ^[0-9]+$ ]] || { log_err "HOSTCTL_EXPECT_UID 非法: $HOSTCTL_EXPECT_UID"; exit 2; }
[[ "$HOSTCTL_MAX_SKEW" =~ ^[0-9]+$ ]] || { log_err "HOSTCTL_MAX_SKEW 非法: $HOSTCTL_MAX_SKEW"; exit 2; }

# 解析并准备安全的锁文件与防重放状态文件路径（root 模式下位于 root 专用 0700 目录）
STATE_PATHS="$(python3 - "$HOSTCTL_DIR" "${HOSTCTL_LOCK_FILE:-}" "${HOSTCTL_NONCE_FILE:-}" <<'PY'
import hashlib, os, pathlib, stat, sys, tempfile

hostctl_dir, lock_override, nonce_override = sys.argv[1:]
euid = os.geteuid()
dir_hash = hashlib.sha256(os.path.realpath(hostctl_dir).encode("utf-8")).hexdigest()[:16]

def ensure_private_dir(path_str):
    p = pathlib.Path(path_str)
    cur = pathlib.Path("/")
    for part in p.parts[1:]:
        cur = cur / part
        if cur.is_symlink():
            raise SystemExit(f"状态目录含符号链接组件: {cur}")
        if not cur.exists():
            cur.mkdir(mode=0o700)
    st = os.lstat(p)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != euid:
        raise SystemExit(f"状态目录属主或类型异常: {p}")
    os.chmod(p, 0o700)
    return p

def check_target_file(path_str):
    p = pathlib.Path(path_str)
    if p.is_symlink():
        raise SystemExit(f"状态文件不得为符号链接: {p}")
    if p.parent.is_symlink():
        raise SystemExit(f"状态文件父目录不得为符号链接: {p.parent}")
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return str(p)

if lock_override:
    lock_file = check_target_file(lock_override)
elif euid == 0:
    lock_dir = ensure_private_dir("/run/jiuzhang-hostctl")
    lock_file = str(lock_dir / "hostctl.lock")
else:
    base = pathlib.Path(tempfile.gettempdir()).resolve() / f"jiuzhang-hostctl-state-{euid}"
    lock_dir = ensure_private_dir(str(base))
    lock_file = str(lock_dir / f"hostctl-{dir_hash}.lock")

if nonce_override:
    nonce_file = check_target_file(nonce_override)
elif euid == 0:
    nonce_dir = ensure_private_dir("/var/lib/jiuzhang/hostctl")
    nonce_file = str(nonce_dir / "nonces.json")
else:
    base = pathlib.Path(tempfile.gettempdir()).resolve() / f"jiuzhang-hostctl-state-{euid}"
    nonce_dir = ensure_private_dir(str(base))
    nonce_file = str(nonce_dir / f"nonces-{dir_hash}.json")

print(lock_file)
print(nonce_file)
PY
)" || die "无法初始化 hostctl 锁或防重放状态路径"

LOCK_FILE="$(printf '%s\n' "$STATE_PATHS" | sed -n '1p')"
NONCE_FILE="$(printf '%s\n' "$STATE_PATHS" | sed -n '2p')"

# 独占 flock：优先使用系统 flock，缺失时（如 macOS 测试）由 Python fcntl.flock 持有锁并 exec 本脚本
if [[ "${HOSTCTL_LOCK_HELD:-0}" != "1" ]]; then
  if [[ -L "$LOCK_FILE" ]]; then
    die "锁文件不得为符号链接: $LOCK_FILE"
  fi
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$LOCK_FILE"
    flock -x 9
    export HOSTCTL_LOCK_HELD=1
  else
    exec python3 - "$LOCK_FILE" "$0" "${ORIG_ARGS[@]}" <<'PY'
import fcntl, os, shutil, sys
lock_path = sys.argv[1]
script = sys.argv[2]
args = sys.argv[3:]
fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
os.set_inheritable(fd, True)
os.environ["HOSTCTL_LOCK_HELD"] = "1"
bash = shutil.which("bash") or "/bin/bash"
os.execv(bash, [bash, script, *args])
PY
  fi
fi

# 临时隔离目录（仅当前用户/root 0700 可访问），用于暂存验签后的标志副本
STAGE_DIR="$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/jz-hostctl-stage.XXXXXX")"
chmod 0700 "$STAGE_DIR"
cleanup_stage() {
  case "${STAGE_DIR:-}" in
    */jz-hostctl-stage.*) rm -rf "$STAGE_DIR" ;;
  esac
}
trap cleanup_stage EXIT INT TERM HUP

# 1. 启动阶段：校验标志目录并按需原子自举共享密钥（目录异常时留给逐标志拒绝路径处理）
SECRET_FILE="$HOSTCTL_DIR/.hostctl-secret"
if [[ -L "$SECRET_FILE" ]]; then
  log_err "共享密钥不得为符号链接: ${SECRET_FILE}（fail-closed）"
  logger -t jiuzhang-hostctl -- "secret_bootstrap_failed dir=$HOSTCTL_DIR reason=secret_symlink"
  exit 1
fi

bootstrap_rc=0
bootstrap_msg="$(python3 - "$HOSTCTL_DIR" "$HOSTCTL_EXPECT_UID" <<'PY' 2>&1
import errno, os, re, secrets, stat, sys

hostctl_dir = sys.argv[1]
expect_uid = int(sys.argv[2])

try:
    dir_fd = os.open(hostctl_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except OSError as exc:
    sys.stderr.write(f"无法安全打开标志目录: {exc}\n")
    sys.exit(2)

try:
    dir_st = os.fstat(dir_fd)
    if dir_st.st_uid != expect_uid or (stat.S_IMODE(dir_st.st_mode) & 0o002) != 0:
        # 目录属主或权限异常：跳过自举，由逐标志安全校验路径归档拒绝
        sys.exit(10)
    secret_path = os.path.join(hostctl_dir, ".hostctl-secret")
    try:
        fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            if os.geteuid() == 0:
                os.fchown(fd, dir_st.st_uid, dir_st.st_gid)
            token = (secrets.token_hex(32) + "\n").encode("ascii")
            os.write(fd, token)
            os.fsync(fd)
        finally:
            os.close(fd)
    except FileExistsError:
        pass
    except OSError as exc:
        sys.stderr.write(f"共享密钥缺失且无法自举: {secret_path}（{exc}，fail-closed）\n")
        sys.exit(1)

    try:
        rfd = os.open(secret_path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            sys.stderr.write(f"共享密钥不得为符号链接: {secret_path}（fail-closed）\n")
        else:
            sys.stderr.write(f"无法读取共享密钥: {secret_path}（{exc}，fail-closed）\n")
        sys.exit(1)
    try:
        sec_st = os.fstat(rfd)
        if not stat.S_ISREG(sec_st.st_mode):
            sys.stderr.write(f"共享密钥不是常规文件: {secret_path}（fail-closed）\n")
            sys.exit(1)
        if sec_st.st_uid != dir_st.st_uid:
            sys.stderr.write(
                f"共享密钥属主 uid={sec_st.st_uid} 与目录约定属主 uid={dir_st.st_uid} 不一致（fail-closed）\n"
            )
            sys.exit(1)
        try:
            os.fchmod(rfd, 0o600)
        except OSError:
            if (stat.S_IMODE(sec_st.st_mode) & 0o077) != 0:
                sys.stderr.write(f"共享密钥权限过宽且无法收紧为 0600: {secret_path}（fail-closed）\n")
                sys.exit(1)
        raw = os.read(rfd, 256).decode("ascii", errors="strict").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", raw):
            sys.stderr.write(f"共享密钥格式非法（期望 64 字符 hex）: {secret_path}（fail-closed）\n")
            sys.exit(1)
    finally:
        os.close(rfd)
finally:
    os.close(dir_fd)
PY
)" || bootstrap_rc=$?

if [[ "$bootstrap_rc" -ne 0 && "$bootstrap_rc" -ne 10 ]]; then
  log_err "${bootstrap_msg:-共享密钥校验失败（fail-closed）}"
  logger -t jiuzhang-hostctl -- "secret_bootstrap_failed dir=$HOSTCTL_DIR"
  exit 1
fi

# 2. 按 mtime 升序（FIFO）枚举所有待处理 .json 标志文件（显式排除 pcap-status.*）
FLAG_LIST=()
while IFS= read -r _flag_path; do
  [[ -n "$_flag_path" ]] && FLAG_LIST+=("$_flag_path")
done < <(python3 - "$HOSTCTL_DIR" <<'PY'
import os, sys

hostctl_dir = sys.argv[1]
items = []
for entry in os.scandir(hostctl_dir):
    name = entry.name
    if not name.endswith(".json"):
        continue
    if name.startswith("pcap-status."):
        continue
    full = os.path.join(hostctl_dir, name)
    try:
        st = os.lstat(full)
    except OSError:
        continue
    items.append((st.st_mtime_ns, name, full))

items.sort(key=lambda x: (x[0], x[1]))
for _, _, full in items:
    print(full)
PY
)
unset _flag_path

if [[ ${#FLAG_LIST[@]} -eq 0 ]]; then
  log_info "无待处理标志文件（${HOSTCTL_DIR}）"
  exit 0
fi

log_info "发现 ${#FLAG_LIST[@]} 个待处理标志文件，按 FIFO（oldest-first）顺序依次处理"

HAD_ERROR=0
FLAG_INDEX=0

for flag_path in "${FLAG_LIST[@]}"; do
  FLAG_INDEX=$((FLAG_INDEX + 1))
  FLAG_BASE="$(basename "$flag_path")"
  DONE_FILE="${flag_path}.done"
  STAGED_FLAG="${STAGE_DIR}/flag-${FLAG_INDEX}.json"
  rm -f "$STAGED_FLAG"

  # 原子前置校验并归档（绝不跟随符号链接）
  if [[ -L "$flag_path" ]]; then
    mv -f "$flag_path" "$DONE_FILE" 2>/dev/null || true
    log_err "标志文件安全校验未通过：标志文件不得为符号链接（已归档为 ${FLAG_BASE}.done，不执行）"
    logger -t jiuzhang-hostctl -- "security_rejected file=$FLAG_BASE reason=flag_symlink"
    HAD_ERROR=1
    continue
  fi
  if [[ ! -f "$flag_path" ]]; then
    continue
  fi
  if [[ -L "$DONE_FILE" ]]; then
    log_err "归档目标为符号链接，拒绝覆盖: ${DONE_FILE}"
    logger -t jiuzhang-hostctl -- "security_rejected file=$FLAG_BASE reason=done_symlink"
    HAD_ERROR=1
    continue
  fi

  # 先归档再验签（防 systemd path 单元重复触发同一文件）
  mv "$flag_path" "$DONE_FILE"

  # 在 Python 中完成目录属主/权限复核、O_NOFOLLOW 读密钥与标志、HMAC 恒定时间验签、
  # 时间窗校验、requestID 防重放登记、白名单参数校验，并复制验签后原文至 0700 临时目录
  verify_rc=0
  verify_out="$(python3 - "$HOSTCTL_DIR" "$DONE_FILE" "$STAGED_FLAG" "$HOSTCTL_EXPECT_UID" "$HOSTCTL_MAX_SKEW" "$NONCE_FILE" <<'PY' 2>&1
import datetime, errno, hashlib, hmac, json, os, pathlib, re, stat, sys, time, uuid

hostctl_dir, done_path, staged_path, expect_uid_s, max_skew_s, nonce_file = sys.argv[1:]
expect_uid = int(expect_uid_s)
max_skew = int(max_skew_s)

def fail(reason, tag="security_rejected"):
    sys.stderr.write(f"{tag}|{reason}\n")
    sys.exit(1)

# 1. 目录属主与权限校验（O_NOFOLLOW）
try:
    dir_fd = os.open(hostctl_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except OSError as exc:
    fail(f"无法安全打开标志目录: {exc}")

try:
    dir_st = os.fstat(dir_fd)
    dir_uid = dir_st.st_uid
    dir_mode = stat.S_IMODE(dir_st.st_mode)
    if dir_uid != expect_uid:
        fail(f"标志目录属主 uid={dir_uid} 非约定属主 uid={expect_uid}（属主配置错误，拒绝执行）")
    if (dir_mode & 0o002) != 0:
        fail(f"标志目录权限 {oct(dir_mode)[2:]} 为 other-writable，任意本地用户可伪造标志（请 chmod 755 并核对属主）")

    # 2. 标志文件属主校验 + O_NOFOLLOW 读取原始字节
    try:
        flag_fd = os.open(done_path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            fail("标志文件不得为符号链接")
        fail(f"无法读取标志文件: {exc}")
    try:
        flag_st = os.fstat(flag_fd)
        if not stat.S_ISREG(flag_st.st_mode):
            fail("标志文件不是常规文件")
        if flag_st.st_uid != dir_uid:
            fail(f"标志文件属主 uid={flag_st.st_uid} 与目录约定属主 uid={dir_uid} 不一致（非 api 容器写入，拒绝执行）")
        if flag_st.st_size > 65536:
            fail("标志文件超过 64 KiB 安全上限")
        raw_bytes = os.read(flag_fd, 65537)
        if len(raw_bytes) > 65536:
            fail("标志文件超过 64 KiB 安全上限")
    finally:
        os.close(flag_fd)

    # 3. 共享密钥安全读取（O_NOFOLLOW + fstat，绝不泄露给子进程 argv）
    secret_path = os.path.join(hostctl_dir, ".hostctl-secret")
    try:
        sec_fd = os.open(secret_path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            fail("共享密钥不得为符号链接")
        fail(f"共享密钥不可用（未自举或无法读取）: {exc}")
    try:
        sec_st = os.fstat(sec_fd)
        if not stat.S_ISREG(sec_st.st_mode):
            fail("共享密钥不是常规文件")
        if sec_st.st_uid != dir_uid:
            fail(f"共享密钥属主 uid={sec_st.st_uid} 与目录约定属主 uid={dir_uid} 不一致")
        if (stat.S_IMODE(sec_st.st_mode) & 0o077) != 0:
            try:
                os.fchmod(sec_fd, 0o600)
            except OSError:
                fail("共享密钥权限过宽（必须为 0600）")
        secret = os.read(sec_fd, 256).decode("ascii", errors="strict").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", secret):
            fail("共享密钥格式非法（期望 64 字符 hex）")
    finally:
        os.close(sec_fd)
finally:
    os.close(dir_fd)

# 4. JSON 解析
try:
    data = json.loads(raw_bytes.decode("utf-8"))
except Exception:
    fail("标志文件 JSON 解析失败", tag="parse_failed")
if not isinstance(data, dict):
    fail("标志文件 JSON 顶层必须是对象", tag="parse_failed")

def field_str(key):
    val = data.get(key, "")
    return "" if val is None else str(val)

action = field_str("action")
requested_by = field_str("requestedBy")
user_id = field_str("userID")
request_id = field_str("requestID")
requested_at = field_str("requestedAt")
delay_raw = data.get("delaySeconds")
delay_str = "" if delay_raw is None else (str(delay_raw) if not isinstance(delay_raw, bool) else "")
hmac_field = field_str("hmac")

if not hmac_field or not requested_at or delay_str == "":
    fail("缺少 hmac/requestedAt/delaySeconds 字段（未签名标志一律拒绝）")
if not re.fullmatch(r"[0-9a-f]{64}", hmac_field):
    fail("hmac 字段格式非法")

ports_csv = ""
pcap_interface = ""
pcap_hot_dir = ""
pcap_warm_dir = ""
pcap_node_id = ""
pcap_enabled = ""

if action == "firewall_ensure":
    ports = data.get("ports", [])
    if ports is None:
        ports = []
    if isinstance(ports, list):
        ports_csv = ",".join("" if v is None else str(v) for v in ports)
    else:
        ports_csv = "<invalid-ports>"
    canonical = "\n".join([
        "v2", action, requested_by, user_id, request_id, requested_at, delay_str, ports_csv
    ])
elif action == "pcap_capture":
    try:
        pcap_interface = data["interface"]
        pcap_hot_dir = data["hot_dir"]
        pcap_warm_dir = data["warm_dir"]
        pcap_node_id = data["node_id"]
        enabled_val = data["enabled"]
        ports_val = data["ports"]
        if not isinstance(pcap_interface, str) or not isinstance(pcap_hot_dir, str) \
                or not isinstance(pcap_warm_dir, str) or not isinstance(pcap_node_id, str) \
                or not isinstance(enabled_val, bool) or not isinstance(ports_val, list):
            raise TypeError("invalid pcap_capture field type")
        if not all(isinstance(p, int) and not isinstance(p, bool) for p in ports_val):
            raise TypeError("invalid pcap_capture port type")
        pcap_enabled = "true" if enabled_val else "false"
        ports_csv = ",".join(str(p) for p in sorted(ports_val))
    except Exception:
        fail("pcap_capture 配置字段缺失或类型非法")
    canonical = "\n".join([
        "v3", action, requested_by, user_id, request_id, requested_at, delay_str, ports_csv,
        pcap_interface, pcap_hot_dir, pcap_warm_dir, pcap_node_id, pcap_enabled,
    ])
else:
    canonical = "\n".join([
        "v1", action, requested_by, user_id, request_id, requested_at, delay_str
    ])

expected_hmac = hmac.new(
    secret.encode("ascii"), canonical.encode("utf-8"), hashlib.sha256
).hexdigest()
if not hmac.compare_digest(expected_hmac, hmac_field):
    fail("HMAC 验签失败（内容被篡改或密钥不符）")

# 5. 时间戳窗口校验
ts_text = requested_at.strip()
if ts_text.endswith("Z"):
    ts_text = ts_text[:-1] + "+00:00"
try:
    req_epoch = int(datetime.datetime.fromisoformat(ts_text).timestamp())
except ValueError:
    fail(f"requestedAt 时间戳无法解析: {requested_at}")

now_epoch = int(time.time())
if abs(now_epoch - req_epoch) > max_skew:
    fail(f"requestedAt 超出允许时间窗（±{max_skew}s，疑似重放或时钟异常）")

# 6. Action 白名单与参数校验
allowed_actions = ("reboot", "shutdown", "factory_reset", "firewall_ensure", "pcap_capture")
if action not in allowed_actions:
    fail(f"非法 action: {action or '<空>'}（白名单: {'/'.join(allowed_actions)}）", tag="rejected")

if not request_id or len(request_id) > 128 or any(ch.isspace() for ch in request_id):
    fail("requestID 缺失或格式非法")

if action in ("firewall_ensure", "pcap_capture"):
    if not re.fullmatch(r"[1-9][0-9]{0,4}(,[1-9][0-9]{0,4})*", ports_csv):
        fail(f"{action} ports 必须为十进制整数数组，每项 1..65535")
    port_items = ports_csv.split(",")
    if not (1 <= len(port_items) <= 128):
        fail(f"{action} ports 必须包含 1..128 项")
    prev = 0
    for item in port_items:
        port_num = int(item, 10)
        if not (1 <= port_num <= 65535):
            fail(f"{action} 端口超出 1..65535: {item}")
        if port_num <= prev:
            fail(f"{action} ports 必须严格升序且无重复")
        prev = port_num

if action == "pcap_capture":
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", pcap_interface):
        fail("pcap_capture 网卡名称非法")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", pcap_node_id):
        fail("pcap_capture 节点ID非法")
    if pcap_enabled not in ("true", "false"):
        fail("pcap_capture enabled必须为布尔值")
    if not re.fullmatch(r"/[A-Za-z0-9._/-]+", pcap_hot_dir) or not re.fullmatch(r"/[A-Za-z0-9._/-]+", pcap_warm_dir):
        fail("pcap_capture 存储路径非法")
    if pcap_hot_dir == pcap_warm_dir or pcap_hot_dir == "/" or pcap_warm_dir == "/":
        fail("pcap_capture 冷热目录不能相同或为根目录")

if action in ("firewall_ensure", "pcap_capture"):
    if delay_str != "0":
        fail(f"{action} 的 delaySeconds 必须为 0")
    delay_int = 0
else:
    if re.fullmatch(r"[0-9]+", delay_str):
        delay_int = min(int(delay_str, 10), 60)
    else:
        delay_int = 3

# 7. requestID 防重放检查与持久化登记（保留 >= 2 * HOSTCTL_MAX_SKEW）
nonce_path = pathlib.Path(nonce_file)
if nonce_path.is_symlink() or nonce_path.parent.is_symlink():
    fail("防重放状态文件不得为符号链接")
nonces = {}
if nonce_path.exists():
    try:
        nfd = os.open(str(nonce_path), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            nst = os.fstat(nfd)
            if not stat.S_ISREG(nst.st_mode) or nst.st_uid != os.geteuid():
                fail("防重放状态文件属主或类型异常")
            content = os.read(nfd, 4 * 1024 * 1024).decode("utf-8")
            loaded = json.loads(content) if content.strip() else {}
            if isinstance(loaded, dict):
                nonces = {k: int(v) for k, v in loaded.items() if isinstance(k, str) and isinstance(v, (int, float))}
        finally:
            os.close(nfd)
    except SystemExit:
        raise
    except Exception as exc:
        fail(f"读取防重放状态文件失败: {exc}")

retention = max(2 * max_skew, 600)
nonces = {k: v for k, v in nonces.items() if v >= now_epoch}
dir_scope = hashlib.sha256(os.path.realpath(hostctl_dir).encode("utf-8")).hexdigest()[:16]
nonce_key = f"{dir_scope}:{request_id}"
if nonce_key in nonces:
    fail(f"检测到重放请求（requestID={request_id} 已消费，拒绝重复执行）")
nonces[nonce_key] = now_epoch + retention

tmp_nonce = nonce_path.with_name(f".{nonce_path.name}.{uuid.uuid4().hex}.tmp")
tnfd = os.open(str(tmp_nonce), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    os.fchmod(tnfd, 0o600)
    with os.fdopen(tnfd, "w", encoding="utf-8") as nf:
        tnfd = -1
        json.dump(nonces, nf, separators=(",", ":"), sort_keys=True)
        nf.write("\n")
        nf.flush()
        os.fsync(nf.fileno())
    os.replace(tmp_nonce, nonce_path)
finally:
    if tnfd >= 0:
        os.close(tnfd)
    if tmp_nonce.exists():
        tmp_nonce.unlink()

# 8. 将已验签原始标志字节复制到 root 0700 临时目录，供下游处理器（如 pcap_capture_control.py）安全消费
sfd = os.open(staged_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    os.fchmod(sfd, 0o600)
    with os.fdopen(sfd, "wb") as sf:
        sfd = -1
        sf.write(raw_bytes)
        sf.flush()
        os.fsync(sf.fileno())
finally:
    if sfd >= 0:
        os.close(sfd)

# 输出脱敏后的执行元数据（不含密钥）
print(json.dumps({
    "action": action,
    "requestedBy": requested_by or "unknown",
    "requestID": request_id,
    "delay": delay_int,
    "ports": ports_csv,
}, ensure_ascii=False, separators=(",", ":")))
PY
)" || verify_rc=$?

  if [[ "$verify_rc" -ne 0 ]]; then
    err_tag="${verify_out%%|*}"
    err_reason="${verify_out#*|}"
    [[ "$err_tag" == "$verify_out" ]] && { err_tag="security_rejected"; err_reason="$verify_out"; }
    if [[ "$err_tag" == "parse_failed" ]]; then
      log_err "标志文件 JSON 解析失败: ${FLAG_BASE}（已归档为 ${FLAG_BASE}.done）"
      logger -t jiuzhang-hostctl -- "parse_failed file=$FLAG_BASE"
    elif [[ "$err_tag" == "rejected" ]]; then
      log_err "${err_reason}，已归档不执行"
      logger -t jiuzhang-hostctl -- "rejected file=$FLAG_BASE reason=$err_reason"
    else
      log_err "标志文件安全校验未通过：${err_reason}（已归档为 ${FLAG_BASE}.done，不执行）"
      logger -t jiuzhang-hostctl -- "security_rejected file=$FLAG_BASE reason=$err_reason"
    fi
    rm -f "$STAGED_FLAG"
    HAD_ERROR=1
    continue
  fi

  META_LINES=()
  while IFS= read -r _line; do META_LINES+=("$_line"); done < <(python3 - "$verify_out" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
print(d["action"])
print(d["requestedBy"])
print(d["requestID"])
print(d["delay"])
print(d["ports"])
PY
)
  unset _line
  ACTION="${META_LINES[0]:-}"
  REQUESTED_BY="${META_LINES[1]:-unknown}"
  REQUEST_ID="${META_LINES[2]:-unknown}"
  DELAY="${META_LINES[3]:-0}"
  PORTS="${META_LINES[4]:-}"

  logger -t jiuzhang-hostctl -- "execute action=$ACTION requestedBy=$REQUESTED_BY requestID=$REQUEST_ID delay=$DELAY file=$FLAG_BASE"
  log_info "动作=$ACTION 操作人=$REQUESTED_BY requestID=$REQUEST_ID 延迟=${DELAY}s"

  if [[ "$DRY_RUN" == "true" ]]; then
    if [[ "$ACTION" == "firewall_ensure" ]]; then
      log_info "[dry-run] 将执行: firewall-ensure.sh ${PORTS}（delay=0 不等待，不实际执行）"
    elif [[ "$ACTION" == "pcap_capture" ]]; then
      log_info "[dry-run] 将按验签范围执行PCAP启停（delay=0 不等待，不实际执行）"
    else
      log_info "[dry-run] 将 sleep ${DELAY}s 后执行: ${ACTION}（不实际执行）"
    fi
    rm -f "$STAGED_FLAG"
    continue
  fi

  (( DELAY > 0 )) && sleep "$DELAY"
  action_rc=0
  case "$ACTION" in
    reboot)
      require_cmd systemctl
      log_info "执行 systemctl reboot"
      systemctl reboot || action_rc=$? ;;
    shutdown)
      require_cmd systemctl
      log_info "执行 systemctl poweroff"
      systemctl poweroff || action_rc=$? ;;
    factory_reset)
      [[ -x "$SCRIPT_DIR/factory-reset.sh" ]] || { log_err "恢复出厂脚本不存在或不可执行: $SCRIPT_DIR/factory-reset.sh"; action_rc=1; }
      if [[ "$action_rc" -eq 0 ]]; then
        log_info "执行恢复出厂: $SCRIPT_DIR/factory-reset.sh"
        JZ_ASSUME_YES=true bash "$SCRIPT_DIR/factory-reset.sh" || action_rc=$?
      fi ;;
    firewall_ensure)
      [[ -x "$SCRIPT_DIR/firewall-ensure.sh" ]] || { log_err "防火墙放行脚本不存在或不可执行: $SCRIPT_DIR/firewall-ensure.sh"; action_rc=1; }
      if [[ "$action_rc" -eq 0 ]]; then
        log_info "确保 firewalld runtime+permanent 放行: $PORTS"
        bash "$SCRIPT_DIR/firewall-ensure.sh" "$PORTS" || action_rc=$?
      fi ;;
    pcap_capture)
      [[ -f "$SCRIPT_DIR/pcap_capture_control.py" ]] || { log_err "PCAP控制脚本不存在: $SCRIPT_DIR/pcap_capture_control.py"; action_rc=1; }
      if [[ "$action_rc" -eq 0 ]]; then
        python3 "$SCRIPT_DIR/pcap_capture_control.py" --repo-root "$REPO_ROOT" --flag "$STAGED_FLAG" || action_rc=$?
      fi ;;
  esac
  rm -f "$STAGED_FLAG"
  if [[ "$action_rc" -ne 0 ]]; then
    HAD_ERROR=1
  fi
done

exit "$HAD_ERROR"
