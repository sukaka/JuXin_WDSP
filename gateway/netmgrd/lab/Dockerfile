# 九章 netmgrd 网络执行组件 lab 实验镜像（privileged 容器内真实执行验证）
# 组件契约：/var/run/caddy/sidecars/network.json → network-status.json
#
# 单容器实验镜像：alpine（RepoDigest 锁定，与 mirrorcap/tproxy-lab 同一基座）+
# iproute2（真实执行 `ip`/`sysctl` 命令）+ netmgrd 静态二进制（宿主机用仓库
# 锁定的 Go 工具链交叉编译）。
#
# 拓扑（entrypoint 自建，network_mode: none 独立 netns，不触碰任何真实网络）：
#   eth2/eth3/eth4  空闲口（veth pair，模拟物理业务口）
#   mgmt0           192.168.50.1/24（带 IP 的「管理口」，安全红线负例；
#                   其连接路由同时为静态路由用例提供 on-link 下一跳网段）
#
# 构建方式（Docker Hub 在本实验环境不可达，与 deployment/docker/tproxy-lab
# 同一约定：本地镜像按 RepoDigest 锁定，二进制在宿主机产出）：
#
#   # 仓库根目录执行（go 1.25.6，见 gateway/go.mod；CGO_ENABLED=0 纯静态产物）
#   cd gateway && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
#     go build -trimpath -ldflags="-s -w" \
#     -o netmgrd/lab/bin/netmgrd ./cmd/netmgrd && cd ..
#   docker compose -f gateway/netmgrd/lab/docker-compose.netmgr-lab.yml build
#
# 多架构交付时 GOARCH 换成 amd64 重新构建即可（产物无 libc 依赖）。
# bin/ 命中仓库 .gitignore 的 bin/ 模式，二进制不进 Git。

# 本地 alpine:3.20 的 RepoDigest（与 mirrorcap/tproxy-lab 实验镜像同一基座）
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

# 实验编排工具（PoC 实验镜像，非交付物）：iproute2 构建期取自 alpine 3.20 官方仓库
RUN apk add --no-cache iproute2

COPY --chmod=0755 bin/netmgrd /usr/bin/netmgrd
COPY --chmod=0755 entrypoint.sh /usr/local/bin/lab-entrypoint.sh

# 边车契约目录（network.json/network-status.json）
RUN mkdir -p /var/run/caddy/sidecars

# 容器需 privileged（veth/桥/sysctl 全在容器内独立 netns 自建）；
# 入口脚本完成拓扑搭建后驻留，验证动作全部由 netmgr-lab-tests.sh 驱动。
ENTRYPOINT ["/usr/local/bin/lab-entrypoint.sh"]
