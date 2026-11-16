#!/usr/bin/env bash
# prepare-containerops.sh —— 探测宿主机 docker.sock 属组 gid，生成 CONTAINEROPS_DOCKER_GID。
#
# 背景：containerops sidecar 是全栈唯一挂载 /var/run/docker.sock 的组件（见
# docs/CONTAINER_OPS_DESIGN.md），镜像内以非 root（uid 1000）运行，访问 socket
# 所需的属组 gid 由 compose `group_add: ${CONTAINEROPS_DOCKER_GID}` 注入。
# 该 gid 因宿主机而异（Linux 通常为 docker 组；Docker Desktop / root -owned 场景为 0），
# 安装/升级前用本脚本探测并写入 .env，避免手工猜测。
#
# 用法:
#   prepare-containerops.sh                # 仅打印 CONTAINEROPS_DOCKER_GID=<gid>
#   prepare-containerops.sh -e .env        # 写入/更新 env 文件中的 CONTAINEROPS_DOCKER_GID 行
#
# 安全约束：只读探测（stat），不执行任何容器操作；写 env 文件时仅替换/追加
# CONTAINEROPS_DOCKER_GID 单行，不读取不回显其他键值。
# 退出码：0=成功 1=失败（socket 不存在/无法 stat/写入失败）2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

ENV_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -e|--env-file) ENV_FILE="$2"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
用法: prepare-containerops.sh [-e ENV_FILE]

探测宿主机 /var/run/docker.sock 属组 gid：
  无参数      打印 CONTAINEROPS_DOCKER_GID=<gid> 到 stdout
  -e FILE     将 CONTAINEROPS_DOCKER_GID=<gid> 写入/更新到 env 文件
              （已存在该行则原地替换，否则追加；不改动其他内容）

退出码: 0=成功 1=失败 2=用法错误
EOF
      exit 0 ;;
    *) log_err "未知参数: $1"; exit 2 ;;
  esac
done

SOCK="${DOCKER_HOST_SOCKET:-/var/run/docker.sock}"
[[ -S "$SOCK" ]] || die "Docker socket 不存在或不是 socket 文件: $SOCK（容器运维通道不可用，见 docs/CONTAINER_OPS_DESIGN.md「非容器部署」）"

# GNU stat 优先，BSD stat（macOS）兜底；输出必须是纯数字 gid
DOCKER_GID="$(stat -c '%g' "$SOCK" 2>/dev/null || stat -f '%g' "$SOCK" 2>/dev/null || true)"
[[ "$DOCKER_GID" =~ ^[0-9]+$ ]] || die "无法解析 $SOCK 的属组 gid（stat 输出异常）"

if [[ -z "$ENV_FILE" ]]; then
  printf 'CONTAINEROPS_DOCKER_GID=%s\n' "$DOCKER_GID"
  exit 0
fi

# 写入 env 文件：存在该行则替换，否则追加。不读取/不回显其他键值，避免泄露口令。
touch "$ENV_FILE" || die "无法写入 env 文件: $ENV_FILE"
if grep -q '^CONTAINEROPS_DOCKER_GID=' "$ENV_FILE"; then
  tmp="$(mktemp "${TMPDIR:-/tmp}/jzenv.XXXXXX")"
  trap 'rm -f "$tmp"' EXIT
  # 仅替换目标行，其余行逐字节保留
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      CONTAINEROPS_DOCKER_GID=*) printf 'CONTAINEROPS_DOCKER_GID=%s\n' "$DOCKER_GID" ;;
      *) printf '%s\n' "$line" ;;
    esac
  done < "$ENV_FILE" > "$tmp"
  cat "$tmp" > "$ENV_FILE" || die "回写 env 文件失败: $ENV_FILE"
  rm -f "$tmp"; trap - EXIT
else
  printf 'CONTAINEROPS_DOCKER_GID=%s\n' "$DOCKER_GID" >> "$ENV_FILE" || die "写入 env 文件失败: $ENV_FILE"
fi
log_info "已写入 $ENV_FILE: CONTAINEROPS_DOCKER_GID=$DOCKER_GID"
