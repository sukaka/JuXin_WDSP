# 九章阶段D 透明串接（透明代理）部署模式 PoC 实验镜像
# 设计依据：docs/NETWORK_MODES_DESIGN.md §4.3
#
# 单容器实验镜像：alpine（RepoDigest 锁定）+ iptables/iproute2 + 三个二进制——
#   caddy       从 jiuzhang-gateway:stage5 镜像提取（规则链与 stage5 静态
#               Caddyfile 一致）；
#   testorigin  从 jiuzhang-testorigin:stage1 镜像提取；
#   tproxyd     自研透明牵引进程，宿主机用仓库锁定 Go 工具链静态交叉编译。
#
# 构建方式（Docker Hub 在本实验环境不可达，与 deployment/docker/mirrorcap/Dockerfile
# 同一约定：本地镜像按 RepoDigest 锁定，二进制在宿主机产出；caddy/testorigin
# 按 extract-binaries.sh 从 digest 锁定的本机镜像 docker cp 提取——BuildKit 无法
# 把自建镜像的 name@digest FROM 解析到本地存储，会回源 registry 失败）：
#
#   # 仓库根目录执行（go 1.25.6，见 gateway/go.mod；CGO_ENABLED=0 纯静态产物）
#   cd gateway && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
#     go build -trimpath -ldflags="-s -w" \
#     -o ../deployment/docker/tproxy-lab/tproxyd ./cmd/tproxyd && cd ..
#   bash deployment/docker/tproxy-lab/extract-binaries.sh
#   docker build -t jiuzhang-tproxy-lab:stageD-poc deployment/docker/tproxy-lab
#
# 多架构交付时 GOARCH 换成 amd64 重新构建即可（产物无 libc 依赖）。

# 本地 alpine:3.20 的 RepoDigest（与 mirrorcap 实验镜像同一基座）
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

# 实验编排工具（PoC 实验镜像，非交付物）：iptables 1.8.10(nf_tables)/iproute2/curl/
# openssl（HTTPS SNI 分流实验：自签名证书签发 + openssl s_server 模拟 TLS 源站），
# 构建期取自 alpine 3.20 官方仓库
RUN apk add --no-cache iptables iproute2 curl openssl

COPY --chmod=0755 caddy /usr/bin/caddy
COPY --chmod=0755 testorigin /usr/bin/testorigin
COPY --chmod=0755 tproxyd /usr/bin/tproxyd
COPY --chmod=0755 entrypoint.sh /usr/local/bin/lab-entrypoint.sh

# Coraza 运行时目录（SecDataDir）、日志目录（/var/log/caddy 为卷挂载点）、
# Caddy 运行目录与实验进程日志目录
RUN mkdir -p /tmp/coraza /var/log/caddy /var/log/lab /var/run/caddy /var/lib/caddy /srv/jiuzhang

# 容器需 privileged（netns/veth/bridge/sysctl/iptables 全在容器内自建）；
# 入口脚本完成拓扑搭建、进程拉起、牵引规则安装与 fail-open 看门狗。
ENTRYPOINT ["/usr/local/bin/lab-entrypoint.sh"]
