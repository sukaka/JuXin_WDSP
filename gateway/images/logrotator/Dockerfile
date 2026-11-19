# 九章日志轮转 sidecar
# 构建: docker build -t jiuzhang-logrotator:stage5 gateway/images/logrotator/
# 纯 busybox 镜像（alpine，不安装任何 apk 包，避免版本漂移）：
# 对网关日志卷中由第三方库/自研模块以 append 方式常驻写入的日志文件
# （coraza-audit.log / api-runtime-events.log / guard-events.log / access-full.jsonl）
# 做 copytruncate 轮转；access.log 与 caddy.log 由 Caddy 自身轮转，不在此处理。
#
# 基础镜像锁定策略与 gateway/Dockerfile 保持一致：
#   版本标签固定（alpine:3.24），digest 通过 ARG 控制；置空则仅按版本标签解析。
#   查询：docker buildx imagetools inspect alpine:3.24
ARG ALPINE_IMAGE_DIGEST=sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

FROM alpine:3.24${ALPINE_IMAGE_DIGEST:+@$ALPINE_IMAGE_DIGEST}

RUN addgroup -g 1000 -S logrotator \
    && adduser -u 1000 -S -G logrotator -H logrotator

COPY --chmod=0755 rotate.sh /usr/local/bin/rotate.sh

USER 1000:1000

ENTRYPOINT ["/usr/local/bin/rotate.sh"]
