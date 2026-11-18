# 九章容器运维 sidecar（containeropsd）镜像
# 构建（仓库根目录）:
#   docker build -f deployment/containerops/Dockerfile -t jiuzhang-containerops:stage5 .
#
# 多架构构建（linux/amd64 + linux/arm64）：
#   docker buildx build --platform linux/amd64,linux/arm64 \
#       -t jiuzhang-containerops:2.0.0 -f deployment/containerops/Dockerfile .
#
# 职责与安全边界（详见 docs/CONTAINER_OPS_DESIGN.md）：
#   - 本组件是全栈唯一挂载 /var/run/docker.sock 的容器，向管理面提供受控容器运维能力
#     （白名单内服务的查看/重启/镜像更新等）；API 容器只挂载共享 Unix Socket 卷，
#     不直接持有 Docker 权限。
#   - 只监听 Unix Socket（CONTAINEROPS_SOCKET），不暴露任何 TCP 端口；
#     compose 中以 network_mode: none 运行，无网络面。
#   - 访问 docker.sock 所需的宿主机 docker 组 gid 由 compose `group_add` 注入
#     （CONTAINEROPS_DOCKER_GID），镜像本体始终以非 root（uid 1000）运行。
#
# 基础镜像锁定策略与 server/Dockerfile 一致（遵循项目“禁止 latest、依赖必须锁定版本”规则）：
#   - 版本标签固定（golang:1.25-alpine、alpine:3.24），digest 通过 ARG 控制；
#   - 下方默认 digest 为 multi-arch index 摘要（含 amd64+arm64），普通 docker build
#     与 buildx 多架构构建均可使用；Docker 按构建机/目标平台选层；
#   - 若 digests 被改成单架构子摘要，多架构构建需 --build-arg GOLANG_IMAGE_DIGEST=
#     --build-arg ALPINE_IMAGE_DIGEST=（按标签解析 manifest list）。
#   查询：docker buildx imagetools inspect golang:1.25-alpine

# 基础镜像 digest（与 server/Dockerfile 同一锁定口径）；置空则仅按版本标签解析
ARG GOLANG_IMAGE_DIGEST=sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587
ARG ALPINE_IMAGE_DIGEST=sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# builder 固定使用构建机原生平台（$BUILDPLATFORM）：Go 交叉编译零成本，
# 避免多架构构建时在 QEMU 模拟下运行 Go 工具链；产物经 GOOS/GOARCH 指向目标平台
FROM --platform=$BUILDPLATFORM golang:1.25-alpine${GOLANG_IMAGE_DIGEST:+@$GOLANG_IMAGE_DIGEST} AS builder

# buildx 自动注入的目标平台参数（单架构 docker build 时默认为构建机平台）
ARG TARGETOS
ARG TARGETARCH

ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}

# server 模块含本地 gateway replace，构建上下文须与 server/Dockerfile 一致（仓库根）。
WORKDIR /build/server
COPY server/go.mod server/go.sum ./
COPY gateway/dynamic_security/ /build/gateway/dynamic_security/
COPY gateway/pcapevidence/ /build/gateway/pcapevidence/
RUN go mod download
COPY server/ ./
# GOOS/GOARCH 显式指向目标平台（Go 交叉编译）
# GOAMD64=v1 锁定 x86-64 v1 基线：兼容兆芯 KH-40000/KX-6000（无 AVX2）等信创 CPU
RUN CGO_ENABLED=0 GOAMD64=v1 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/containeropsd ./cmd/containeropsd

# 运行阶段不加 --platform：buildx 默认即为目标平台
FROM alpine:3.24${ALPINE_IMAGE_DIGEST:+@$ALPINE_IMAGE_DIGEST}

# 非 root 运行（uid/gid 1000）；/run/containerops 为共享 Unix Socket 卷挂载点，
# 命名卷首次挂载会继承镜像内目录属主，保证非 root 进程可创建 socket 文件。
# 访问 /var/run/docker.sock 的组权限由 compose group_add 注入（CONTAINEROPS_DOCKER_GID），
# 不在镜像内固化任何宿主机 gid。
RUN addgroup -g 1000 -S jiuzhang && adduser -u 1000 -S -G jiuzhang jiuzhang \
    && mkdir -p /run/containerops && chown jiuzhang:jiuzhang /run/containerops

COPY --from=builder /out/containeropsd /usr/local/bin/containeropsd

USER jiuzhang
WORKDIR /app

ENV CONTAINEROPS_SOCKET=/run/containerops/containerops.sock
ENV DOCKER_HOST=unix:///var/run/docker.sock

# 进程存活 + socket 文件存在性探活（不发明协议探测，协议契约见 docs/CONTAINER_OPS_DESIGN.md）
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD [ -S "$CONTAINEROPS_SOCKET" ] || exit 1

# 不声明 EXPOSE：本组件不提供任何 TCP 端口
ENTRYPOINT ["/usr/local/bin/containeropsd"]
