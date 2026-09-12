# 九章镜像（旁路）采集器 mirrorcap 运行镜像（阶段C 技术验证 PoC）
# 设计依据：docs/NETWORK_MODES_DESIGN.md §4.2
#
# 构建方式（Docker Hub 在本实验环境不可达，golang 构建镜像无法拉取，故与
# deployment/docker-compose.routed-lab.yml 同一约定：本地镜像按 RepoDigest 锁定；
# 二进制在宿主机用仓库锁定的 Go 工具链静态交叉编译）：
#
#   # 仓库根目录执行（go 1.25.6，见 gateway/go.mod；CGO_ENABLED=0 纯静态产物）
#   cd gateway && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
#     go build -trimpath -ldflags="-s -w" \
#     -o ../deployment/docker/mirrorcap/mirrorcap ./cmd/mirrorcap
#   docker build -t jiuzhang-mirrorcap:stageC-poc deployment/docker/mirrorcap
#
# 多架构交付时 GOARCH 换成 amd64 重新构建即可（产物无 libc 依赖）。

# 本地 alpine:3.20 的 RepoDigest（本机已存在镜像，Docker Hub 不可达时的可复现锁定）
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

# Coraza 运行时目录（SecDataDir）与事件/审计日志目录（卷挂载点）
RUN mkdir -p /tmp/coraza /var/log/caddy

COPY --chmod=0755 mirrorcap /usr/bin/mirrorcap

# 抓包所需权能（CAP_NET_RAW/CAP_NET_ADMIN）由 compose cap_add 授予；
# 容器内唯一进程即采集器， ENTRYPOINT 直接 exec（PID 1 收 SIGTERM 优雅退出）。
ENTRYPOINT ["/usr/bin/mirrorcap"]
