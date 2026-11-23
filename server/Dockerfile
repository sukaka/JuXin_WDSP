# 九章管理后端镜像（阶段2）
# 构建: docker build -f server/Dockerfile -t jiuzhang-server:stage2 .
#
# 多架构构建（linux/amd64 + linux/arm64；海光 C86、兆芯 KX/KH 为 x86-64 兼容，直接使用 amd64 产物）：
#   docker buildx build --platform linux/amd64,linux/arm64 \
#       -t jiuzhang-server:2.0.0 -f server/Dockerfile .
# 基础镜像锁定策略（遵循项目“禁止 latest、依赖必须锁定版本”规则）：
#   - 版本标签固定（golang:1.25-alpine、alpine:3.24），digest 通过 ARG 控制；
#   - 下方默认 digest 为 multi-arch index 摘要（含 amd64+arm64），普通 docker build
#     与 buildx 多架构构建均可使用；Docker 按构建机/目标平台选层；
#   - 若 digests 被改成单架构子摘要，多架构构建需 --build-arg GOLANG_IMAGE_DIGEST=
#     --build-arg ALPINE_IMAGE_DIGEST=（按标签解析 manifest list）。
#   查询：docker buildx imagetools inspect golang:1.25-alpine

# 基础镜像 digest（见文件头说明）；置空则仅按版本标签解析
ARG GOLANG_IMAGE_DIGEST=sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587
ARG ALPINE_IMAGE_DIGEST=sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# builder 固定使用构建机原生平台（$BUILDPLATFORM）：Go 交叉编译零成本，
# 避免多架构构建时在 QEMU 模拟下运行 Go 工具链；产物经 GOOS/GOARCH 指向目标平台
FROM --platform=$BUILDPLATFORM golang:1.25-alpine${GOLANG_IMAGE_DIGEST:+@$GOLANG_IMAGE_DIGEST} AS builder

# buildx 自动注入的目标平台参数（单架构 docker build 时默认为构建机平台）
ARG TARGETOS
ARG TARGETARCH
# 正式构建保持默认 0；仅 deployment/docker-compose.test-license.yml 的本地/CI
# 验收构建显式设为 1，以启用 wdsp_testkeys 测试信任根。
ARG WDSP_LICENSE_TEST_KEYS=0

ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}

WORKDIR /build/server
COPY server/go.mod server/go.sum ./
COPY gateway/dynamic_security/ /build/gateway/dynamic_security/
COPY gateway/pcapevidence/ /build/gateway/pcapevidence/
RUN go mod download
COPY server/ ./
# GOOS/GOARCH 显式指向目标平台（Go 交叉编译）
# GOAMD64=v1 锁定 x86-64 v1 基线：兼容兆芯 KH-40000/KX-6000（无 AVX2）等信创 CPU
RUN if [ "$WDSP_LICENSE_TEST_KEYS" = "1" ]; then \
      CGO_ENABLED=0 GOAMD64=v1 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags wdsp_testkeys -trimpath -ldflags="-s -w" -o /out/jiuzhang-api ./cmd/api; \
    else \
      CGO_ENABLED=0 GOAMD64=v1 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/jiuzhang-api ./cmd/api; \
    fi

# 运行阶段不加 --platform：buildx 默认即为目标平台
FROM alpine:3.24${ALPINE_IMAGE_DIGEST:+@$ALPINE_IMAGE_DIGEST}

RUN addgroup -g 1000 -S jiuzhang && adduser -u 1000 -S -G jiuzhang jiuzhang \
    && mkdir -p /app/migrations /app/runtime/certificates && chown -R jiuzhang:jiuzhang /app

COPY --from=builder /out/jiuzhang-api /usr/local/bin/jiuzhang-api
COPY --chown=jiuzhang:jiuzhang server/migrations/ /app/migrations/
# 报告 PDF 字体等资源（阶段6）
COPY --chown=jiuzhang:jiuzhang server/assets/fonts/*.otf server/assets/fonts/*.ttf /app/assets/fonts/
# 统一离线 GeoIP 数据资产（ip2region_v4.xdb + DB-IP IPv6 城市库 + 国家回退库；
# 运行时可在 runtime/geoip/ 放置新版 ip2region 或官方 DB-IP Lite .mmdb 覆盖）
COPY --chown=jiuzhang:jiuzhang server/assets/geoip/ip2region_v4.xdb web/public/assets/geo/city-ipv6.mmdb web/public/assets/geo/country.mmdb /app/assets/geoip/
# 内置 WAF 规则元数据目录（OWASP CRS + 插件 + 第三方/自建规则包 + 九章内置规则；
# 生产编排如挂载 ./gateway/rules:/etc/caddy/rules:ro 并配置 WAF_CRS_DIR 则优先使用挂载目录，
# 旧编排仅升级镜像时可直接回退读取镜像内 /app/gateway/rules）
COPY --chown=jiuzhang:jiuzhang gateway/rules/ /app/gateway/rules/

USER jiuzhang
WORKDIR /app
ENV MIGRATIONS_DIR=/app/migrations

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/api/v1/health || exit 1

# 启动时先执行迁移再启动服务
ENTRYPOINT ["/bin/sh", "-c", "jiuzhang-api migrate up && exec jiuzhang-api"]
