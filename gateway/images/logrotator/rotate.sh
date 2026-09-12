#!/bin/sh
# 九章日志轮转 sidecar 主循环（busybox ash 兼容）
# 对 Coraza 审计日志、API 运行时事件、guard 事件、全量访问日志做 copytruncate 轮转：
# 写入方（第三方库/自研模块）以 append 方式常驻打开文件，不能 mv 走原文件，
# 采用“复制当前内容为 .1 → 原地截断 → gzip .1”的方式，写入方 fd 不中断。
set -u

# 轮转检查间隔（秒）
ROTATE_INTERVAL_SECONDS="${ROTATE_INTERVAL_SECONDS:-600}"
# 单文件大小阈值（字节），超过则轮转，默认 100MB
ROTATE_MAX_BYTES="${ROTATE_MAX_BYTES:-104857600}"
# 保留的历史压缩文件个数（.1.gz ~ .N.gz），超出后删除最老一份
ROTATE_KEEP="${ROTATE_KEEP:-7}"
# 日志目录（与网关容器共享的日志卷挂载点）
LOG_DIR="${LOG_DIR:-/var/log/caddy}"

# 固定轮转目标清单（access.log / caddy.log 由 Caddy 自身轮转，不在此列）
ROTATE_TARGETS="coraza-audit.log api-runtime-events.log guard-events.log access-full.jsonl site-discovery.jsonl identity-events.log"

# 输出一行带时间戳的日志到 stdout
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [logrotator] $*"
}

# 轮转单个文件：$1 = 文件绝对路径
# 返回 0 表示已轮转或无需轮转；非 0 表示轮转失败（调用方记录后继续处理其它文件）
rotate_one() {
    file="$1"

    # 文件不存在则跳过（目标文件由网关按需创建，启动初期可能尚未生成）
    [ -f "$file" ] || return 0

    size=$(stat -c %s "$file") || return 1
    # 未超阈值不轮转
    [ "$size" -gt "$ROTATE_MAX_BYTES" ] || return 0

    # 删除最老的一份（保留个数之外）
    if [ -f "$file.$ROTATE_KEEP.gz" ]; then
        rm -f "$file.$ROTATE_KEEP.gz" || return 1
    fi

    # 依次后移：.(keep-1).gz -> .keep.gz、…、.1.gz -> .2.gz
    i=$((ROTATE_KEEP - 1))
    while [ "$i" -ge 1 ]; do
        if [ -f "$file.$i.gz" ]; then
            mv "$file.$i.gz" "$file.$((i + 1)).gz" || return 1
        fi
        i=$((i - 1))
    done

    # copytruncate：先复制当前内容，再原地截断，写入方 fd 不中断
    cp "$file" "$file.1" || return 1
    # 截断刻意不用 `: > file`：`:` 是 POSIX 特殊内建命令，busybox ash 下其重定向
    # 失败（如只读文件 EACCES）会直接终止整个脚本；cat 重定向失败仅返回非零
    cat /dev/null > "$file" || return 1
    gzip "$file.1" || return 1

    log "已轮转 $file（原大小 ${size} 字节，阈值 ${ROTATE_MAX_BYTES} 字节）"
    return 0
}

log "启动：目录=$LOG_DIR 间隔=${ROTATE_INTERVAL_SECONDS}s 阈值=${ROTATE_MAX_BYTES}B 保留=${ROTATE_KEEP} 目标：$ROTATE_TARGETS"

# 主循环：sleep 间隔 → 逐个检查目标文件；单文件失败仅记录，不影响其它文件与后续循环
while :; do
    sleep "$ROTATE_INTERVAL_SECONDS"
    for name in $ROTATE_TARGETS; do
        rotate_one "$LOG_DIR/$name" || log "轮转失败：$LOG_DIR/$name（跳过，下个周期重试）"
    done
done
