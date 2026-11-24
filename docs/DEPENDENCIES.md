# 依赖锁定清单

本文档记录九章WEB应用智能防护系统V2.0所有第三方组件的精确版本。核查日期：2026-07-20。禁止使用 `latest` 标签。

## 网关核心组件（阶段1锁定）

| 组件名称 | 版本号 | Git提交号 | 许可证 | 项目地址 | 发布日期 | 兼容性说明 | 是否修改 |
|---------|--------|----------|--------|---------|---------|-----------|---------|
| Caddy | v2.11.4 | e2eee6a7fce3 | Apache-2.0 | https://github.com/caddyserver/caddy | 2026-06-03 | 网关基础，coraza-caddy v2.5.0 声明兼容 caddy v2.11.x | 否 |
| Coraza WAF | v3.7.0 | 27069d06c896 | Apache-2.0 | https://github.com/corazawaf/coraza | 2026-04-06 | WAF 检测引擎，支持 SecLang 与 CRS 4.x | 否 |
| coraza-caddy | v2.5.0 | 55c03d45dc55 | Apache-2.0 | https://github.com/corazawaf/coraza-caddy | 2026-04-12 | Caddy 集成模块，go.mod 声明依赖 caddy v2.11.2、coraza v3.7.0 | 否 |
| OWASP CRS | v4.28.0 | 55b09f5acfd1 | Apache-2.0 | https://github.com/coreruleset/coreruleset | 2026-07-02 | 通用攻击规则集，tarball sha256: d8acc96f25ad07c8e3a595a23c797324f6d77e59ddf9e26e90dd95ebd2e676ce | 否 |
| xcaddy | v0.4.5 | 328cac711a1f | Apache-2.0 | https://github.com/caddyserver/xcaddy | 2025-07-29 | Caddy 自定义构建工具（仅构建期使用） | 否 |
| go-ftw | v2.4.0 | 23db497e3a61 | Apache-2.0 | https://github.com/coreruleset/go-ftw | 2026-05-23 | CRS 回归测试框架（仅测试期使用） | 否 |

> **coraza-caddy v2.5.0 哨兵耦合点（升级必读）**：Coraza 阻断归因依赖 coraza-caddy 未导出哨兵错误 `errInterruptionTriggered` 的消息串 `"interruption triggered"`（硬编码于 `gateway/modules/jiuzhang_guard/apicoraza.go` 的 `corazaInterruptionMessage`）。升级 `CORAZA_CADDY_VERSION` 前必须复核上游该哨兵是否变更，并重跑归因测试（`gateway/modules/jiuzhang_guard/apicoraza_test.go`）确认 `waf.downstream_intercept` 归因仍成立；归因局限性（取不到命中规则明细、phase 3 中断不归因等）见 docs/DEVELOPMENT_STATUS.md 阶段8 诚实遗留。

## 阶段5新增组件

| 组件名称 | 版本号 | 许可证 | 项目地址 | 用途 | 是否修改 |
|---------|--------|--------|---------|------|---------|
| valkey-go | v1.0.76 | Apache-2.0 | https://github.com/valkey-io/valkey-go | jiuzhang_guard 模块 Valkey 客户端（CC计数/临时封禁） | 否 |
| jiuzhang_guard | 随仓库 | 自主开发 | 本仓库 gateway/modules/jiuzhang_guard | 访问控制与CC防护 Caddy 模块（独立 go.mod，xcaddy 本地路径替换构建） | 自研 |
| Brotli | v1.3.0 | MIT | https://github.com/andybalholm/brotli | API 压缩响应的 Brotli 解压与安全重编码（gzip 使用 Go 标准库） | 否 |

## 阶段C（镜像/旁路模式 PoC）新增组件

| 组件名称 | 版本号 | 许可证 | 项目地址 | 用途 | 是否修改 |
|---------|--------|--------|---------|------|---------|
| gopacket | v1.1.19 | BSD-3-Clause | https://github.com/google/gopacket | mirrorcap 旁路采集器：pcapgo AF_PACKET 纯 syscall 抓包 + tcpassembly/tcpreader TCP 重组（无 libpcap、无 cgo，CGO_ENABLED=0 静态编译；记录于 gateway/go.mod） | 否 |
| Coraza WAF（复用） | v3.7.0 | Apache-2.0 | https://github.com/corazawaf/coraza | mirrorcap 内嵌 DetectionOnly 检测（与网关同一锁定版本，非新增） | 否 |

## 基础镜像（Docker）

| 镜像 | 标签 | 摘要 | 用途 |
|------|------|------|------|
| golang | 1.25-alpine | sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 | 网关构建阶段 |
| alpine | 3.24 | sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b | 网关运行阶段 |
| postgres | 16.4-alpine | sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c | 主数据库 |
| valkey/valkey | 8.1.8-alpine | sha256:94365b275456ae14621001c03556c732b1d93a0cdeacc317d1bdd52eba680885 | 缓存/锁/任务状态 |
| alpine（mirrorcap PoC） | 3.20 | sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc | 阶段C 旁路采集器运行基镜像（本机 RepoDigest 锁定，Docker Hub 不可达环境可复现） |
| debian | bookworm-slim | sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 | wdsp-agent `.deb` 包与一键安装脚本容器实测镜像 |
| openeuler/openeuler | 24.03-lts-sp4 | sha256:17c15554be2a5bc46023acb6e04d609d77642b8c20e236e88deb18e41ae4558e | wdsp-agent `.rpm` 包与一键安装脚本容器实测镜像 |

## 多架构镜像锁定

系统按 **linux/amd64** 与 **linux/arm64** 双架构交付。

| 目标平台 | 交付产物 | 说明 |
|---------|---------|------|
| x86-64（含 Intel/AMD） | amd64 | 标准路径 |
| 海光 C86 | **amd64** | C86 为 x86-64 兼容，**不单独出包**，直接使用 amd64 离线包与镜像 |
| 兆芯 KX/KH（含 KH-40000） | **amd64** | 兆芯为 x86-64 兼容，**不单独出包**，直接使用 amd64 离线包与镜像 |
| ARM64（鲲鹏/飞腾/Apple Silicon 等） | arm64 | 独立离线包与 `--platform linux/arm64` 构建 |

### 锁定策略说明（重要）

compose / Dockerfile 中 `@sha256:...` **是多架构 index/manifest list 摘要**（含 amd64 + arm64 等平台），
**不是**单架构子摘要。Docker 在拉取时会按宿主机或 `--platform` 自动选对应架构，
因此同一 digest 在 amd64 与 arm64 上均可原生使用，无需按架构改写 compose。

若需更严的「单架构子摘要」锁定（离线包导出前校验用），可用：

```bash
docker buildx imagetools inspect <image:tag>
# 取 Platform: linux/amd64 或 linux/arm64(/v8) 行的 Name 中的 @sha256:...
```

### 各镜像 digest 现状（2026-08-08 核查）

**Index digest**（compose/Dockerfile 锁定值，多架构）：

| 镜像 | 标签 | multi-arch index digest | 用途 |
|------|------|-------------------------|------|
| postgres | 16.4-alpine | `sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c` | 主数据库 |
| valkey/valkey | 8.1.8-alpine | `sha256:94365b275456ae14621001c03556c732b1d93a0cdeacc317d1bdd52eba680885` | 缓存 |
| golang | 1.25-alpine | `sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587` | 构建阶段 |
| alpine | 3.24 | `sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b` | 运行阶段 |
| node | 24-alpine | `sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd` | 前端构建 |
| caddy | 2.11.4-alpine | `sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648` | 前端托管 |

**平台子摘要**（参考；离线包拉取时仍可用 index + `--platform`）：

| 镜像 | linux/amd64 子摘要 | linux/arm64 子摘要 |
|------|-------------------|-------------------|
| postgres:16.4-alpine | `sha256:f5aa7cac1dc299a77761ada5a5cf9c6ef4064bc85c89fed49c587dd2381d6f05` | `sha256:ab472914707ce7b505750a96d769feb4136cbe5b40dc993116a3a3a1bac40631` |
| valkey/valkey:8.1.8-alpine | `sha256:df03836e7c416b32cd284d0705aaadaacaf852fe7bf5de0e4a999cede477ab1c` | `sha256:2f0a6ceb7bec3f4f7d51fc8afca2eb62ff51c18119e0b915eff5d358b81f01a5` |
| golang:1.25-alpine | `sha256:2b6edeb8c6b1071bfa16473f24bb7b7da0b1579009f97bb1542f239b14aabd8f` | `sha256:6779780b49fee40ea72c8f30bb17e6f35c410129940be57ca3cba0efb1c4c777` |
| alpine:3.24 | `sha256:79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f` | `sha256:e7a1a92a5bfeee40966aea60f0796b0e7917cc35591542701834f03a68fa3d18` |
| node:24-alpine | （见 index 内 amd64 manifest） | （见 index 内 arm64/v8 manifest） |
| caddy:2.11.4-alpine | `sha256:98eb57d882ccd5213d1688764db10c1ca2c58a1ca3a6717a3411ad798f7a423a` | `sha256:1172d4213087d3fc30bafc7ff2c2896180eb0c41ff7f75f315568fb36cabdcba` |

### 自研镜像多架构构建

jiuzhang-gateway、jiuzhang-server 等自研镜像均为 `CGO_ENABLED=0` 静态交叉编译
（Dockerfile 使用 `FROM --platform=$BUILDPLATFORM` + `GOOS/GOARCH=$TARGETOS/$TARGETARCH`），
可用 buildx 一次构建双架构：

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -f gateway/Dockerfile -t jiuzhang-gateway:<version> --push gateway/
```

离线包按架构出包（`jiuzhang-offline-{version}-{arch}.tar.gz`，manifest.json 含 `arch` 字段）；
`--load` 仅支持单平台，需分架构构建后分别 `docker save`：

```bash
# 海光 C86 / 兆芯 KX/KH / 通用 x86-64
docker buildx build --platform linux/amd64 -f gateway/Dockerfile -t jiuzhang-gateway:<version> --load gateway/
# ARM64
docker buildx build --platform linux/arm64 -f gateway/Dockerfile -t jiuzhang-gateway:<version> --load gateway/
```

安装时 `ops/install/install.sh` 会比对离线包 `manifest.arch` 与宿主机架构
（`detect_arch`：x86_64→amd64，aarch64→arm64；海光 C86、兆芯 KX/KH 归 amd64），
并从 `manifest.edition` 写入 `PRODUCT_EDITION` / `API_DYNAMIC_PROTECTION_ENABLED` /
`WEB_WAF_ENABLED`。

### 产品线 × 架构离线包

同一套 `jiuzhang-server` / `jiuzhang-gateway` 镜像，按配置打成 3 条产品线：

| 产品 | edition | API 动态防护 | Web 防护专属 | 包名示例 |
|------|---------|--------------|--------------|----------|
| WAF | `waf` | 关 | 开 | `jiuzhang-waf-offline-2.0.0-amd64.tar.gz` |
| WDSP | `wdsp` | 开 | 开 | `jiuzhang-wdsp-offline-2.0.0-amd64.tar.gz` |
| API | `api` | 开 | 关 | `jiuzhang-api-offline-2.0.0-arm64.tar.gz` |

架构：`amd64`（别名 `x86`/`x86_64`，含海光 C86、兆芯 KX/KH）与 `arm64`。

```bash
# 单包
ops/offline-package/build.sh -v 2.0.0 -p waf  -a amd64
ops/offline-package/build.sh -v 2.0.0 -p wdsp -a amd64
ops/offline-package/build.sh -v 2.0.0 -p api  -a arm64

# 全量 3 产品 × 2 架构 = 6 包
ops/offline-package/build-all.sh -v 2.0.0

# 仅 x86-64 三产品（海光 C86 / 兆芯 KX/KH / Intel / AMD）
ops/offline-package/build-all.sh -v 2.0.0 --arches amd64
```

## 基础设施组件

| 组件名称 | 版本号 | 许可证 | 项目地址 | 使用方式 | 是否修改 |
|---------|--------|--------|---------|---------|---------|
| PostgreSQL | 16.4 | PostgreSQL License | https://www.postgresql.org | 主数据库 | 否 |
| Valkey | 8.1.8 | BSD-3-Clause | https://github.com/valkey-io/valkey | 缓存、会话辅助状态、分布式锁、任务状态 | 否 |

## 运行时工具链

| 组件 | 版本 | 说明 |
|------|------|------|
| Go | 1.25.x（本地 1.25.6，容器 golang:1.25-alpine） | 后端与网关构建 |
| Node.js | 24.13.0（`.nvmrc` / `.node-version`） | 前端构建 |
| npm | 11.x（随 Node.js 24 自带） | 前端包管理器 |

## 前端依赖

以 `web/package.json` 与 `web/package-lock.json` 为准，CI 使用 `npm ci` 安装。

## 后端依赖

阶段2引入，以 `server/go.mod` / `server/go.sum` 为准。如使用 Redis 协议兼容客户端连接 Valkey，需在本文件与 THIRD_PARTY_NOTICES.md 单独登记。

报告系统导出增强引入的 Go 依赖（许可证文本归档于 licenses/ 对应目录）：

| 依赖 | 锁定版本 | 许可证 | 用途 |
|------|---------|--------|------|
| github.com/gomutex/godocx | v0.1.5 | MIT | Word（docx）报告生成 |
| github.com/vicanso/go-charts/v2 | v2.6.10 | MIT | 报告图表服务端渲染（PNG/SVG） |
| github.com/wcharczuk/go-chart/v2 | v2.1.0 | MIT | go-charts 底层绘图引擎（间接依赖） |
| github.com/golang/freetype | v0.0.0-20170609003504-e2365dfdc4a0 | FTL（双许可 FTL/GPLv2+，本项目选择 FTL） | 图表字体光栅化（间接依赖） |
| github.com/dustin/go-humanize | v1.0.1 | MIT | godocx 间接依赖 |
| golang.org/x/image | v0.0.0-20200927104501-e162460cd6b5 | BSD-3-Clause | 图表绘制（间接依赖） |

阶段8 gRPC 描述符级解析启用的 Go 依赖：

| 依赖 | 锁定版本 | 许可证 | 用途 |
|------|---------|--------|------|
| google.golang.org/protobuf | v1.36.11 | BSD-3-Clause | gRPC 描述符级消息解析（protodesc/dynamicpb 动态注册表，server 端，迁移 000076；由间接依赖转直接启用，既有锁定版本，零新增外部库） |

阶段8 §33 规范导入扩展启用的 Go 依赖（许可证文本归档于 licenses/yaml/）：

| 依赖 | 锁定版本 | 许可证 | 用途 |
|------|---------|--------|------|
| gopkg.in/yaml.v3 | v3.0.1 | MIT + Apache-2.0（双许可） | OpenAPI/Swagger/JSON Schema/Postman 规范文档的 YAML 解析（server/internal/apisecurity/spec_formats.go，安全解码：自定义标签拒绝 + 节点/深度预算防炸弹） |

## APM 阶段2 数据面新增组件

| 组件名称 | 版本号 | 许可证 | 项目地址 | 用途 | 是否修改 |
|---------|--------|--------|---------|------|---------|
| ClickHouse | 25.8（LTS，镜像 25.8-alpine） | Apache-2.0 | https://github.com/ClickHouse/ClickHouse | APM 数据面：trace/span 原始表与分钟/小时/天聚合（schema 由 deployment/apm/clickhouse 维护，Collector 禁止自动建表） | 否 |
| OpenTelemetry Collector (contrib) | 0.154.0 | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-collector-contrib | APM 数据面：本地 Collector（接收/脱敏/转发）与中央 Collector Gateway（mTLS/二层脱敏/尾采样/写 ClickHouse） | 否 |
| clickhouse-go/v2 | v2.48.0 | Apache-2.0 | https://github.com/ClickHouse/clickhouse-go | 管理后端 ClickHouse 客户端（APM 阶段2 下半 trace 检索/瀑布只读查询，server/go.mod 直接依赖） | 否 |
| ch-go | v0.74.0 | Apache-2.0 | https://github.com/ClickHouse/ch-go | clickhouse-go 底层列式协议驱动（间接依赖） | 否 |
| OpenTelemetry Go（otel） | v1.44.0 | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go | 管理后端自埋点 API（server/internal/apm/selftelemetry.go，server/go.mod 直接依赖） | 否 |
| OpenTelemetry Go SDK（otel/sdk） | v1.44.0 | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go | 自埋点 TracerProvider/有界 BatchSpanProcessor（直接依赖） | 否 |
| otlptracehttp | v1.44.0 | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go | 自埋点 OTLP/HTTP trace exporter（直接依赖） | 否 |
| otelhttp（contrib） | v0.69.0 | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go-contrib | 管理 API HTTP 中间件埋点（直接依赖；contrib v0.69.x 与 otel v1.44.x 为官方配套发布组合，亦与 clickhouse-go v2.48.0 的间接要求一致） | 否 |
| OpenTelemetry Go SDK metrics（otel/sdk/metric） | v1.44.0 | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go | 自埋点 MeterProvider + 30s 周期导出（阶段3 运行时指标，直接依赖） | 否 |
| otlpmetrichttp | v1.44.0 | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go | 自埋点 OTLP/HTTP metric exporter（直接依赖） | 否 |
| instrumentation/runtime（contrib） | v0.69.0 | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go-contrib | Go runtime 指标采集（go.goroutine.count/go.memory.*/go.schedule.duration 等；与 otelhttp 同 contrib 配套版本，直接依赖） | 否 |

### APM 镜像 digest 现状（2026-08-30 经 `docker buildx imagetools inspect` 实测）

**Index digest**（`deployment/docker-compose.apm.yml` 锁定值，多架构）：

| 镜像 | 标签 | multi-arch index digest | 用途 |
|------|------|-------------------------|------|
| clickhouse/clickhouse-server | 25.8-alpine | `sha256:87e0a5b72f5465b18eacca7c76850e7ff551c9795c50e451f5646299e5e24146` | APM 数据面存储 |
| otel/opentelemetry-collector-contrib | 0.154.0 | `sha256:b3079f45e19bdb7326bf49cdddce6cf60dfd865138db39f2733ea48ab17bc4cb` | APM 本地/中央 Collector |

**平台子摘要**（参考；离线包拉取时仍可用 index + `--platform`）：

| 镜像 | linux/amd64 子摘要 | linux/arm64 子摘要 |
|------|-------------------|-------------------|
| clickhouse/clickhouse-server:25.8-alpine | `sha256:07c3dac14693962503aec9fd466f9a0c195af364ce447667a7c2b49c8e630327` | `sha256:e6155c7856a18eb7339724a1cd32a019400cfbb4245bfb381a751fe5838457a0` |
| otel/opentelemetry-collector-contrib:0.154.0 | `sha256:aa96c26bb49db7ab2cd0dc7432ab096506556af82d2af9b9b7aa7f95478520a6` | `sha256:9d76815c9e16d53df284b6820fd8b18a45d7a25c24555f685f588f0b263f39c0` |

> **Collector 版本哨兵（升级必读）**：clickhouse exporter 的 schema 与 Collector 版本耦合
> （`deployment/apm/clickhouse/001_otel_traces.sql` 与 `003_metrics.sql` 分别对齐
> contrib v0.154.0 官方 traces/metrics DDL，
> exporter 配置键 `create_schema`/`async_insert`/`metrics_tables` 等以 v0.154.0
> `exporter/clickhouseexporter/config.go` 为准）。
> 升级 Collector 前必须对照上游 DDL 与配置键变更做兼容性回归，并同步更新本表。

## WDSP 云 API Observation 事件总线新增组件

| 组件名称 | 版本号 | 许可证 | 项目地址 | 用途 | 是否修改 |
|---------|--------|--------|---------|------|---------|
| Apache Kafka | 4.1.2 | Apache-2.0 | https://github.com/apache/kafka | 云 API Observation 中心事件总线（KRaft，无 ZooKeeper） | 否 |
| franz-go | v1.21.0 | BSD-3-Clause | https://github.com/twmb/franz-go | 管理后端唯一 Kafka Go 客户端（Go 1.25.0+） | 否 |

Kafka 镜像锁定：`apache/kafka:4.1.2@sha256:5cc2a2fd93fa2687b44015eee04fb2c3edd9e526bd64bf8bec5ff1e268772e0e`。
经 `docker buildx imagetools inspect` 实测，linux/amd64 子摘要为
`sha256:d50ab7b5df612b3c303f9d8afe8fee59626a5de798addfd626fe1924e3205965`，
linux/arm64 子摘要为 `sha256:4a07b91bf81b35fcc2aaabf3ab6e72aba68d3bb782bce95baba826270c3648da`。
部署与协议边界见 `deployment/kafka/`、`docs/KAFKA_EVENT_BUS_ADR.md` 和
`docs/agents/WDSP_CLOUD_API_SENSOR_CONTRACT.md`。

Java 进程内探针依赖（`wdsp-agent/instrumentation/java/pom.xml`）：

| 组件名称 | 版本号 | 许可证 | 项目地址 | 用途 | 是否修改 |
|---------|--------|--------|---------|------|---------|
| Byte Buddy | 1.17.8 | Apache-2.0 | https://github.com/raphw/byte-buddy | Java 字节码插桩，打入 Agent Jar | 否 |
| Spring Framework（spring-webmvc / spring-web） | 6.2.11 | Apache-2.0 | https://github.com/spring-projects/spring-framework | Spring MVC/RestTemplate 插桩编译 API，provided 不随 Jar 打包 | 否 |
| OpenTelemetry Java API | 1.44.0 | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-java | 已有 Trace Context 只读关联，provided 不随 Jar 打包 | 否 |
| JUnit Jupiter | 5.12.2 | EPL-2.0 | https://github.com/junit-team/junit-framework | Java 单元测试，不进入交付 Jar | 否 |

Java 构建镜像固定为 `maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237`，编译目标 Java 17。Spring Boot `3.5.7` 仅用于 `test/cloud-agent-e2e/` 真实验收应用，不作为探针支持框架范围的替代声明。许可证归档见 `licenses/byte-buddy/`、`licenses/spring-framework/`、`licenses/opentelemetry-java/`。

## WDSP 分布式流量采集 Agent（Phase 1/2）新增组件

| 组件名称 | 版本号 | 许可证 | 项目地址 | 用途 | 是否修改 |
|---------|--------|--------|---------|------|---------|
| gopacket | v1.1.19 | BSD-3-Clause | https://github.com/google/gopacket | wdsp-agent：pcapgo AF_PACKET 纯 syscall 抓包（与 gateway/mirrorcap 同一锁定版本；wdsp-agent/go.mod 直接依赖） | 否 |
| cilium/ebpf | v0.22.0 | MIT | https://github.com/cilium/ebpf | wdsp-agent Phase 2：eBPF/TC（TCX）抓包后端，TC ingress/egress 双 hook + 端口 map + ringbuf 上送（wdsp-agent/go.mod 直接依赖；licenses/cilium-ebpf/ 已归档） | 否 |

## 更新记录

- 2026-11-16：响应安全引入 Brotli v1.3.0（MIT），用于 br 有界解压与重编码；gzip 继续使用 Go 标准库。同步完成 ENCRYPT/MAP、密钥发布与恢复审计，以及 XML/text/SSE 值级检测；依赖归档已登记至 licenses/brotli/ 与 DEPENDENCY_LICENSES.md。

- 2026-11-06：云 API Observation 引入 Kafka 4.1.2、franz-go v1.21.0 与 Java 17 探针；Byte Buddy 1.17.8 随 Agent Jar 分发，Spring Framework 6.2.11 与 OpenTelemetry Java API 1.44.0 为 provided。版本、镜像 digest、许可证归档及 SBOM 生成范围已同步登记。

- 2026-09-02：WDSP 分布式流量采集 Agent Phase 1/2 落地（wdsp-agent 独立 Go module）：登记 gopacket v1.1.19（与 mirrorcap 同版本）与 cilium/ebpf v0.22.0（MIT，eBPF/TC 后端；licenses/cilium-ebpf/ 已归档，license-audit 通过）；eBPF 程序 bpf2go 产物随库提交，日常构建 CGO_ENABLED=0 无需 clang。

- 2026-08-30：APM 阶段3 运行时指标（metrics 信号）引入 otel/sdk/metric 与 otlpmetrichttp v1.44.0（Apache-2.0）及 contrib instrumentation/runtime v0.69.0（Apache-2.0），均为管理后端自埋点直接依赖（server/internal/apm/selftelemetry.go；contrib 版本与既有 otelhttp v0.69.0 配套）；go.sum 中 otel/metric/x v0.66.0 仅为 otel/sdk/metric 自身测试的传递依赖，不链入交付二进制；数据面新增 `deployment/apm/clickhouse/003_metrics.sql`（otel_metrics_* 五表，对齐 contrib v0.154.0 exporter metrics DDL，原始点 TTL 7 天）与 local/central Collector metrics 管道；THIRD_PARTY_NOTICES.md 同步登记。

- 2026-08-30：APM 阶段2 收尾（组件自埋点）引入 OpenTelemetry Go v1.44.0（otel / otel/sdk / otlptracehttp，Apache-2.0）与 contrib otelhttp v0.69.0（Apache-2.0），均为管理后端自埋点直接依赖（server/internal/apm/selftelemetry.go）；版本组合对齐 clickhouse-go v2.48.0 的间接要求（未降级任何既有锁定依赖）；THIRD_PARTY_NOTICES.md 同步登记。

- 2026-08-30：APM 阶段2 下半引入 clickhouse-go/v2 v2.48.0（Apache-2.0，管理后端 ClickHouse 只读查询客户端）及间接底层驱动 ch-go v0.74.0（Apache-2.0）；THIRD_PARTY_NOTICES.md 同步登记。

- 2026-08-30：APM 阶段2 数据面引入 clickhouse-server 25.8-alpine（Apache-2.0）与 otel-collector-contrib 0.154.0（Apache-2.0），tag + multi-arch index digest 双锁（实测 digest 见上文 APM 小节）；编排落点 deployment/docker-compose.apm.yml，schema 落点 deployment/apm/clickhouse/。
- 2026-08-30：补登 google.golang.org/protobuf v1.36.11（阶段8 gRPC 描述符级解析，BSD-3-Clause）；登记 coraza-caddy v2.5.0 哨兵耦合点（未导出错误串 "interruption triggered"，升级必须复核 gateway/modules/jiuzhang_guard/apicoraza.go 并重跑归因测试）。
- 2026-08-27：报告系统新增 Word 导出与图表渲染，引入 godocx v0.1.5、go-charts/v2 v2.6.10（及间接依赖 go-chart/v2 v2.1.0、freetype FTL、go-humanize、x/image），均为宽松许可证；licenses/ 归档与 THIRD_PARTY_NOTICES.md 同步登记。
- 2026-07-20：阶段1首次核查锁定。OWASP CRS 采用 v4.28.0（方案基线为 4.26.x，实际取同大版本下最新发布 v4.28.0）。
- 2026-08-08：自研规则包（CUSTOM_PACK，纯自研无第三方依赖）扩充至 12 个文件 437 条，新增 attack-coverage.conf（SSTI/JWT/SSRF 变形/NoSQL/LDAP/补充 CVE，规则 ID 段 1001100-1001199）等；包结构与完整 ID 段分配见 docs/RULE_PACKS.md。
